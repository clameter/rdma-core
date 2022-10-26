/*
 * RDMA Infiniband to ROCE Bridge or Gateway
 *
 * (C) 2021-2022 Christoph Lameter <cl@linux.com>
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Author: Christoph Lameter [cl@linux.com]$
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <fcntl.h>
#include <ctype.h>
#include <pthread.h>
#include <threads.h>
#include <numa.h>
#include <stdatomic.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/mman.h>


#include "errno.h"
#include "interfaces.h"
#include "cli.h"
#include "sched.h"

/* Timestamp in nanoseconds */
uint64_t timestamp(void)
{
	struct timespec t;

	clock_gettime(CLOCK_REALTIME, &t);
	return t.tv_sec * ONE_SECOND + t.tv_nsec;
}

struct core_info core_infos[MAX_CORE];

thread_local uint64_t now;
thread_local struct core_info *current = NULL;

int cores = 0;
bool terminated = false;

/*
 * Logic to support building a pollfd table for the event loop
 */
#define MAX_POLL_ITEMS 50

unsigned poll_items = 0;

static struct pollfd pfd[MAX_POLL_ITEMS];
static void (*poll_callback[MAX_POLL_ITEMS])(void *);
void *poll_private[MAX_POLL_ITEMS];

void register_callback(event_callback *callback, int fd, void *private)
{
	struct pollfd e = { fd, POLLIN, 0};

	if (poll_items == MAX_POLL_ITEMS)
		panic("Too many poll callback items. Max=%d\n", MAX_POLL_ITEMS);

	poll_callback[poll_items] = callback;
	pfd[poll_items] = e;
	poll_private[poll_items] = private;
	poll_items++;
}

void unregister_callback(int fd)
{
	int i;

	for(i = 0; i < poll_items; i++)
		if (pfd[i].fd == fd)
			break;

	if (i == poll_items)
		panic("Cannot find fd %d on unregister_callback", fd);

	poll_items--;
	while (i < poll_items - 1) {
		pfd[i] = pfd[i+1];
		i++;
	}

}

/* Events are timed according to nanoseconds in the current epoch */
struct timed_event {
	uint64_t time;          /* When should it occur */
	event_callback *callback;       /* function to run */
	void *private;
	struct timed_event *next;       /* The following event */
	const char *text;
};

/* Event queues for each of the threads */
thread_local static struct timed_event *next_event;

int64_t time_to_next_event(void)
{
	if (next_event)
		return (long)next_event->time - (long)timestamp();
	else
		return 0;
}

int get_timer_list(char *buf, char separator)
{
	int n = 0;

	now = timestamp();
	for(struct timed_event *z = next_event; z; z = z->next)
		n += sprintf(buf + n, "%ldms%c", z->time > now ? (z->time - now) / ONE_MILLISECOND : 0,  separator);

	return n;
}

void add_event(uint64_t time, event_callback *callback, void *private, const char *text)
{
	struct timed_event *t;
	struct timed_event *prior = NULL;
	struct timed_event *new_event;

	new_event = calloc(1, sizeof(struct timed_event));
	new_event->time = time;
	new_event->callback = callback;
	new_event->private = private;
	new_event->text = text;

	for(t = next_event; t && time > t->time; t = t->next)
		prior = t;

	new_event->next = t;

	if (prior)
		prior->next = new_event;
	else
		next_event = new_event;
}

/*
 * Run the next event if availabe and return the time till the next event
 * or 0 if there is none
 */
uint64_t run_events(void)
{
	while (next_event) {
		struct timed_event *te = next_event;

		now = timestamp();

		if (te->time > now + ONE_MICROSECOND)
			return te->time - now;

		/* Time is up for an event */
		next_event = te->next;
		te->callback(te->private);
		free(te);
	}
	return 0;
}


void terminate(int x)
{
	terminated = true;
}

int event_loop(void)
{
	int64_t timeout;
	int events = 0;

	while (!terminated) {

		timeout = time_to_next_event();
		if (timeout) {
			/*
			 * If we come from processing poll events then
			 * give priority to more poll event processing
			 */
			if ((timeout <= 0 && events == 0) ||
				       timeout < -(long)milliseconds(10))

				timeout = run_events();

		}

		if (timeout <= 0 || timeout > (long)seconds(10))
			timeout = seconds(10);

	 	events = poll(pfd, poll_items, (timeout + ONE_MILLISECOND/2) / ONE_MILLISECOND);

		if (events < 0)
			return - 1;

		if (events > 0) {
			unsigned t;

			for(t = 0; t < poll_items; t++)
				if (pfd[t].revents & POLLIN)
					poll_callback[t](poll_private[t]);
		}
	}
	return 0;
}

static int busy_event_loop(event_callback *callback, void *private)
{
	while (!terminated) {
		cpu_relax();
		callback(private);
		run_events();
	}
	return 0;
}


void *busyloop(void *private)
{
	struct core_info *core = private;
	unsigned cpu;

	current = core;
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	numa_run_on_node(core->numa_node);

	current->state = core_init;

	cpu = sched_getcpu();
	logg(LOG_NOTICE, "Busyloop started (core %ld) on CPU %d NUMA=%d\n", current - core_infos, cpu, current->numa_node);

	/*
	 * Initialize relevant data structures for this thread. These must be allocated
	 * from the thread to ensure that they are thread local
	 */
	arm_channels(core);

	core->state = core_running;
	busy_event_loop(scan_cqs, core);
	return NULL;
}

/* Called after all the channels have been setup */
void start_cores(void)
{
	int j;

	multithreaded = true;

	for(j = 0; j < cores; j++) {
		struct core_info *ci = core_infos + j;

		if (!ci->nr_channels)
			continue;

		ring_init(&ci->ring);
		get_core_logs(ci);

		if (pthread_create(&ci->thread, &ci->attr, &busyloop, core_infos + j))
			panic("Pthread create failed: %s\n", errname());
	}
}

void stop_cores(void)
{
	int i;

	for(i = 0; i < cores; i++) {
		struct core_info *ci = core_infos + i;

		if (!ci->thread)
			continue;

		pthread_cancel(ci->thread);

		if (pthread_join(ci->thread, NULL))
			panic("pthread_join failed: %s\n", errname());
	}

	multithreaded = false;
}

static void event_cmd(FILE *out, char *parameters)
{
	fprintf(out, "Scheduled events on the high latency thread\n");
	fprintf(out, "-------------------------------------------\n");

	if (next_event) {

		for(struct timed_event *z = next_event; z; z = z->next)
			fprintf(out, "%ldms %s\n", (z->time - timestamp()) / ONE_MILLISECOND, z->text);

	} else
		fprintf(out, "No events.\n");
}

static void core_cmd(FILE *out, char *parameters) {
	if (!parameters) {
		if (cores) {
			unsigned i;

			for(i = 0; i < cores; i++) {
				unsigned j;
				struct core_info *ci = core_infos + i;

				fprintf(out, "Core %d: NUMA=%d", i, ci->numa_node);
				if (latency)
					fprintf(out, " Loops over 5usecs=%u Average=%luns, Max=%uns, Min=%uns\n",
						ci->samples, ci->samples ? ci->sum_latency / ci->samples : 0,
						ci->max_latency, ci->min_latency);

				for (j = 0; j < ci->nr_channels; j++)
					channel_stat(out, ci->channel[j]);
			}
		} else
			fprintf(out, "No cores active. ib2roce operates in single threaded mode.\n");
	} else
		fprintf(out, "Dynamic reseetting of the core config not supported.\n");
}


static void core_set(char *optarg)
{
	cores = atoi(optarg);
	if (cores > 8)
		panic("More than 8 cores\n");
}

__attribute__((constructor))
static void sched_init(void)
{
	register_concom("cores", true, 1, "Setup and list core configuration", core_cmd);
	register_concom("events", true,	0, "Show scheduler event queue", event_cmd);
	register_option("cores", required_argument, 'k', core_set,
			"<nr>", "Spin on the given # of cores");
}

