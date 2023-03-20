/*
 * RDMA Endpoint management
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
#include <stdatomic.h>
#include <sys/socket.h>
#include <rdma/rdma_cma.h>
#include <infiniband/ib.h>
#include <infiniband/verbs.h>

#include "packet.h"
#include "errno.h"
#include "fifo.h"
#include "ring.h"
#include "hash.h"
#include "sched.h"
#include "logging.h"
#include "locking.h"
#include "buffers.h"
#include "multicast.h"
#include "interfaces.h"
#include "cli.h"
#include "endpoint.h"

const struct in_addr ip_none = { .s_addr = 0 };

void list_endpoints(struct i2r_interface *i)
{
	char buf[1000] = "";
	int n = 0;
	struct endpoint *e[10];
	unsigned offset = 0;
	unsigned nr;

	if (!i->context || !i->ip_to_ep)
		return;

	while ((nr = hash_get_objects(i->ip_to_ep, offset, 10, (void **)e))) {
		int j;

		for (j = 0; j < nr; j++) {
			struct endpoint *ep = e[j];

			n += snprintf(buf + n, sizeof(buf) - n, " %s", inet_ntoa(ep->addr));
		}

		offset += 10;
	}
	if (n)
		logg(LOG_NOTICE, "Known Endpoints on %s:%s\n", i->text, buf);
}

static unsigned show_endpoints(char *b)
{
	int n = 0;

	interface_foreach(i)
		if (i->ip_to_ep) {
		struct endpoint *e[20];
		unsigned nr;
		unsigned offset = 0;

		n = sprintf(b, "\nEndpoints on %s", i->text);
		while ((nr = hash_get_objects(i->ip_to_ep, offset, 20, (void **)e))) {
			int j;

			for (j = 0; j < nr; j++) {
				n += sprintf(b + n, "\n%3d. %s", offset + j + 1, inet_ntoa(e[j]->addr));
			}
			offset += 20;
		}
	}
	return n;
}

static void resolve_start(struct rdma_unicast *);

void zap_channel(struct rdma_unicast *ru)
{
	struct buf *buf;

	while ((buf = fifo_get(&ru->pending)))		/* Drop pending I/O */
		free_buffer(buf);

	channel_destroy(ru->c);
	if (ru->sin.sin_addr.s_addr) {
		ru->c = NULL;
		ru->state = UC_NONE;
	} else
		/* Temporary struct that can go away now */
		free(ru);
}

/* Drop the first entry from the list of items to resolve */
void resolve_end(struct rdma_unicast *ru)
{
	struct i2r_interface *i = ru->i;

	if (ru != fifo_get(&i->resolve_queue))
		panic("Nothing in fifo\n");

	if (ru->state == UC_CONNECTED) {
		struct buf *buf;

		while ((buf = fifo_get(&ru->pending)))		/* Send pending I/O */
			send_buf(buf, ru);
	} else
		zap_channel(ru);

	/* Resolve the next address */
	ru = fifo_first(&i->resolve_queue);
	if (ru)
		resolve_start(ru);
}

static void resolve_start(struct rdma_unicast *ru)
{
	struct i2r_interface *i = ru->i;

	if (!ru->c) {
		struct sockaddr_in *sin;

		sin = calloc(1, sizeof(struct sockaddr_in));
		sin->sin_family = AF_INET;
		sin->sin_addr = i->if_addr.sin_addr;
		sin->sin_port = 0;
		ru->c = new_rdma_channel(i, channel_incoming, 0);
		ru->c->ru = ru;
	}

	if (rdma_resolve_addr(ru->c->id, NULL, (struct sockaddr *)&ru->sin, 2000) == 0) {
		ru->state = UC_ADDR_REQ;
		return;
	}

	logg(LOG_ERR, "rdma_resolve_addr error %s on %s for %s:%d\n",
		errname(), ru->c->text, inet_ntoa(ru->sin.sin_addr), ntohs(ru->sin.sin_port));

	resolve_end(ru);
}

/* Resolve Address and send buffer when done */
void resolve(struct rdma_unicast *ru)
{
	struct i2r_interface *i = ru->i;

	if (fifo_put(&i->resolve_queue, ru))
		resolve_start(ru);
}

static void endpoints_cmd(FILE *out,char *parameters)
{
	int n;
	char b[5000];

	n = show_endpoints(b);
	b[n] = 0;
	fputs(b, out);
}

struct rdma_unicast *new_rdma_unicast(struct i2r_interface *i, struct sockaddr_in *sin)
{
	struct rdma_unicast *ra = calloc(1, sizeof(struct rdma_unicast));

	ra->i = i;
	memcpy(&ra->sin, sin, sizeof(struct sockaddr_in));
	fifo_init(&ra->pending);
	return ra;
}

__attribute__((constructor))
static void endpoint_init(void)
{
	register_concom("endpoints", true, 0, "List Endpoints", endpoints_cmd);
}
