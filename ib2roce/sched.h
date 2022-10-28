#ifndef IB2ROCE_SCHED_H
#define IB2ROCE_SCHED_H
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
#define BEACON

#include <stdint.h>
#include <sys/types.h>
#include <threads.h>

#include "ring.h"
#include "channel.h"

/* Time keeping */
#define ONE_SECOND (1000000000UL)
#define ONE_MILLISECOND (ONE_SECOND/1000UL)
#define ONE_MICROSECOND (1000UL)

#define seconds(x) ((x)*ONE_SECOND)
#define milliseconds(x) ((x)*ONE_MILLISECOND)

uint64_t timestamp(void);
extern thread_local uint64_t now;

/*
 * Core layout
 *
 * The basic ib2roce thread is outside of the cores here running
 * in high latency mode which is used for management and for all
 * activities not pushed to the polling cores.
 *
 * Cores always contain pairs of QPs on both interfaces. That reduces
 * lock contention and optimizes the behavior overall.
 *
 */
#define MAX_CORE 8
#define MAX_CQS_PER_CORE 4

enum core_state { core_off, core_init, core_running, core_err, nr_core_states };

struct core_info {
	struct rdma_channel *channel[MAX_CQS_PER_CORE];
	unsigned nr_channels;
	/* Statistics */
	unsigned samples;
	long sum_latency;
	unsigned max_latency;
	unsigned min_latency;
	struct ring ring;
	/* Rarely used */
	enum core_state state;
	int numa_node;
	pthread_t thread;                       /* Thread */
	pthread_attr_t attr;
};

extern int cores;

extern struct core_info core_infos[];

extern thread_local struct core_info *current;

#define cpu_relax()	asm volatile("rep; nop")

typedef void event_callback(void *);

/* Callback at a certain time */
void add_event(uint64_t when, event_callback *callback, void *private, const char *text);

/* Callback when data on a filedescriptor becomes available */
void register_callback(event_callback *callback, int fd, void *private);
void unregister_callback(int fd);

int64_t time_to_next_event(void);	/* Time till next event */

uint64_t run_events(void);	/* Run events that are scheduled */

/* Event loop to be used on the slow threads. Services FD and times events */
int event_loop(void);

/* Polling event loop. Polling occurs in the callback. Also runs timed events */
void *busyloop(void *private);

/* terminates the event loop */
void terminate(int x);

/* Get a textual representation of the timers */
int get_timer_list(char *b, char separator);

void start_cores(void);
void stop_cores(void);

#endif
