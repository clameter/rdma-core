/*
 * Logging support to syslog or console
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
#include <execinfo.h>

#include "sched.h"
#include "ring.h"
#include "interfaces.h"
#include "logging.h"
#include "cli.h"
#include "pgm.h"
#include "endpoint.h"

int loglevel = LOG_INFO;
bool background;


__attribute__ ((format (printf, 2, 3)))
void logg(int prio, const char *fmt, ...)
{
	va_list valist;

	if ((prio & 0x7) > loglevel)
		return;

	va_start(valist, fmt);

	if (current) {
		int n;
		char b[150];
		b[0] = '0' + prio;

		n = vsnprintf(b + 1, 149, fmt, valist);
		ring_put(&current->ring, b, n);

	} else if (background)
		vsyslog(prio, fmt, valist);
	else
		vprintf(fmt, valist);
}

#define NR_FRAMES 100
__attribute__ ((format (printf, 1, 2)))
void panic(const char *fmt, ...)
{
	va_list valist;
	void *frames[NR_FRAMES];
	int nrframes;
	int j;
	char **strings;

	printf("IB2ROCE Panic: ");
	va_start(valist, fmt);
	vprintf(fmt, valist);

	nrframes = backtrace(frames, NR_FRAMES);
	strings = backtrace_symbols(frames, nrframes);

	for( j= 0; j < nrframes; j++) {
		printf("%d. %s\n", j, strings[j]);
	}
	free(strings);
	abort();
}

static char hexbyte(unsigned x)
{
	if (x < 10)
		return '0' + x;

	return x - 10 + 'a';
}

char *__hexbytes(char *b, uint8_t *q, unsigned len, char separator)
{
	unsigned i;
	char *p = b;

	for(i = 0; i < len; i++) {
		unsigned n = *q++;
		*p++ = hexbyte( n >> 4 );
		*p++ = hexbyte( n & 0xf);
		if (i < len - 1)
			*p++ = separator;
		else
			*p++ = 0;
	}
	return b;
}

char *hexbytes(uint8_t *q, unsigned len, char separator)
{
	static char b[1000];

	if (3* len >= sizeof(b)) {
		logg(LOG_NOTICE, "hexbytes: string length constrained\n");
		len = sizeof(b) / 3;
	}
	return __hexbytes(b, q, len, separator);
}

static void brief_status(void)
{
	char buf[4000];
	char buf2[4200];
	char counts[200];

	unsigned n = 0;
	const char *events;

	n = get_timer_list(buf, ',');

	if (n > 0)
		buf[n -1] = 0;
	else
		buf[0] = 0;

	if (n == 0) {
		events = "No upcoming events";
	} else {
		snprintf(buf2, sizeof(buf2), "Events in %s", buf);
		events = buf2;
	}

	n = 0;
	for(struct i2r_interface *i = i2r; i < i2r + NR_INTERFACES;i++)
      	   if (i->context)	{
		n+= sprintf(counts + n, "%s(MC %d/%d",
			i->text,
			i->multicast->stats[packets_received],
			i->multicast->stats[packets_sent]);

		if (i->mc_rate_limited)
			n+= sprintf(counts + n, " R%d", i->mc_rate_limited);

		if (pgm_mode != pgm_none && (i->multicast->stats[pgm_spm] || i->multicast->stats[pgm_odata]))
			n+= sprintf(counts + n, " [TSI=%d SPM=%u,ODATA=%u,RDATA=%u,NAK=%u]",
				i->nr_tsi,
				i->multicast->stats[pgm_spm],
				i->multicast->stats[pgm_odata],
				i->multicast->stats[pgm_rdata],
				i->multicast->stats[pgm_nak]);
#ifdef UNICAST
		if (i->ud && i->ud->stats[packets_received])
			n+= sprintf(counts + n, ", UD %d/%d",
				i->ud->stats[packets_received],
				i->ud->stats[packets_sent]);
		if (i->raw && i->raw->stats[packets_received])
			n+= sprintf(counts + n, ", RAW %d", i->raw->stats[packets_received]);
#endif
		n+= sprintf(counts + n, ") ");
	}

	logg(LOG_NOTICE, "%s. Groups=%d/%d. Packets=%s\n", events, active_mc, nr_mc, counts);

	list_endpoints(i2r + INFINIBAND);
	list_endpoints(i2r + ROCE);
}

/*
 * Retrieving logs from other cores
 */
void get_core_logs(void *private)
{
	struct core_info *c = private;
	char msg[251];
	unsigned len;

	while ((len = ring_get(&c->ring, msg, sizeof(msg) - 1))) {
		int prio;

		msg[len] = 0;
		prio = msg[0] - '0';
		logg(prio, "%s\n", msg + 1);
	}
	add_event(now + milliseconds(100), get_core_logs, c, "Get Core Logs");
}

/*
 * Continous printing of the log line on the console
 */
static int log_interval;

static void verbose_set(char *optarg)
{
	loglevel++;
}

static void continous(void *private)
{
	printf("\n");
	brief_status();

	if (log_interval)
		add_event(timestamp() + seconds(log_interval),
				continous, NULL, "Continous Logging");
}

static void continous_cmd(char *parameters)
{
	int old_interval = log_interval;

	if (!parameters) {
		printf("Continuous logging interval is %d seconds.\n", log_interval);
		return;
	}

	log_interval = atoi(parameters);

	if (!old_interval && log_interval)
		continous(NULL);
}

static void statuscmd(char *parameters) {
	brief_status();
}

__attribute__((constructor))
static void logging_init(void)
{
	register_concom("continuous", false, 1,	"Print continous status in specified interval",	continous_cmd);
	register_concom("status", true, 0, "Print a brief status", statuscmd);
	register_enable("loglevel", true, NULL, &loglevel, "5","3", NULL,
		"Log output to console (0=EMERG, 1=ALERT, 2=CRIT, 3=ERR, 4=WARN, 5=NOTICE, 6=INFO, 7=DEBUG)");
	register_option("verbose", no_argument, 'v', verbose_set, NULL, "Increase logging detail");
}


