/*
 * IB2ROCE Sender support
 *
 * (C) 2022 Christoph Lameter <cl@linux.com>
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

#include <unistd.h>

#include "interfaces.h"
#include "sender.h"
#include "cli.h"

static unsigned sendrate = 5;
static unsigned sendbatch = 1;
static unsigned sendlen = 1024;

static uint64_t sender_interval;
static uint64_t sender_time;
static unsigned sender_seq;

static unsigned sessionid;
static char hostname[40];

#define MAX_SENDRATE 10000

struct sender_info {
	unsigned signature;
	unsigned sessionid;
	uint64_t timestamp;
	unsigned sqn;
	char name[40];
	char dummy[];
};

#define SENDER_SIGNATURE 0xD3ADB33F

static void prep_sender_struct(struct i2r_interface *i, struct buf *buf)
{
	struct sender_info *b = (void *)buf->raw;

	/* Max MTU is 4096 bytes */
	if (sendlen > 4096)
		abort();


	memset(buf->raw, 0, sendlen);

	b->signature = SENDER_SIGNATURE;
	memcpy(b->name, hostname, sizeof(hostname));
	b->sessionid = sessionid;

	b->timestamp = now;
	b->sqn = sender_seq;
	buf->end = buf->raw + sendlen;
}

static void sender_send(void *private)
{
	struct buf *buf;
	struct i2r_interface *i = i2r + default_interface;

	if (!sender_interval || !i->context)
		return;

	for(int j = 0; j < sendbatch; j++) {

		now = timestamp();

		/* scan through all multicast groups and send */
		mc_foreach(m) {
			struct rdma_channel *c = m->interface[default_interface].channel;

			if (m->interface[default_interface].status != MC_JOINED)
				continue;

			buf = alloc_buffer(c);
			prep_sender_struct(i, buf);
			send_to(c, buf->raw, buf->end - buf->raw, &m->interface[default_interface].ai, false, 0, buf);
		}
		sender_seq++;
	}

	sender_time += sender_interval;
	add_event(sender_time, sender_send, NULL, "*Sender Send");
}

void sender_shutdown(void)
{
	if (sender_interval) {
		sender_interval = 0;
		sender_send(NULL);		/* Argh... Race condition */
	}
}

void sender_setup(void)
{
	if (sendrate > 1000 || !sendrate) {
		logg(LOG_ERR, "Cannot send more than 1000 batches per second\n");
		return;
	}

	sender_interval = ONE_SECOND / sendrate;

	if (!sender_interval)
		return;

	sender_time = timestamp() + ONE_SECOND + rand() % sender_interval;

	add_event(sender_time, sender_send, NULL, "Sender Send");
}

__attribute__((constructor))
static void sender_init(void)
{
	srand(time(NULL));
	sessionid = rand();
	if (gethostname(hostname, sizeof(hostname)) < 0)
			logg(LOG_CRIT, "Cannot determine hostname: %s\n", errname());

	register_enable("sendrate", true, NULL, (int *)&sendrate, "2", "off", NULL,
		"The rate of sending packets when requested");
	register_enable("sendlen", true, NULL, (int *)&sendlen, "2", "off", NULL,
		"The length of the packets being sent");
	register_enable("sendbatch", true, NULL, (int *)&sendbatch, "2", "off", NULL,
		"Number of packets to send in one batch");
}

