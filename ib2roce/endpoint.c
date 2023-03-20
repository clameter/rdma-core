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

	if (!i->context || !i->ep)
		return;

	while ((nr = hash_get_objects(i->ep, offset, 10, (void **)e))) {
		int j;

		for (j = 0; j < nr; j++) {
			struct endpoint *ep = e[j];

			if (ep->lid) {

				if (ep->addr.s_addr)
					n += snprintf(buf + n, sizeof(buf) - n, " %s/lid=%d", inet_ntoa(ep->addr), ep->lid);
				else
					n += snprintf(buf + n, sizeof(buf) - n, " lid=%d", ep->lid);

			} else
				n += snprintf(buf + n, sizeof(buf) - n, " %s", inet_ntoa(ep->addr));

			if (ep->forwards) {
				struct forward *f = ep->forwards;

				while (f) {
					n += snprintf(buf + n, sizeof(buf) - n, "[0x%x->%s:%x/%x]",
						f->source_qp, inet_ntoa(f->dest->addr), f->dest_qp, f->dest_qkey);

					f = f->next;
				}
			}
		}

		offset += 10;
	}
	if (n)
		logg(LOG_NOTICE, "Known Endpoints on %s:%s\n", i->text, buf);
}

/*
 * Establish a forwarding for UD unicast packets. Used on UD packet
 * reception to find the destination.
 *
 * This function only adds the forward. Check if there is an existing
 * forward before calling this function.
 */
void add_forward(struct endpoint *source, uint32_t source_qp, struct endpoint *dest, uint32_t dest_qp, uint32_t qkey)
{
	struct forward *f = calloc(1, sizeof(struct forward));

	f->dest = dest;
	f->dest_qp = dest_qp;
	f->dest_qkey = qkey;
	f->source_qp = source_qp;

	f->next = source->forwards;
	source->forwards = f;
}

/*
 * Find the forwarding entry for traffic coming in from a source QP on one side
 *
 * dest == NULL enables wildcard search just based on source_qp
 *
 * source_qp = 0 indicated that the source_qp is not known yet.
 */
struct forward *find_forward(struct endpoint *source, struct endpoint *dest, uint32_t source_qp)
{
	struct forward *f = source->forwards;

	while (f && f->source_qp != source_qp && (!dest || f->dest == dest))
		f = f->next;

	return f;
}

#if 0
/*
 * Remove a forward and indicate if something was there before.
 *
 * This can be used to remove an entry before calling
 * add_forward.
 */
static bool remove_forward(struct endpoint *source, uint32_t source_qp)
{
	struct forward *f = source->forwards;
	struct forward *prior = NULL;

	while (f && f->source_qp != source_qp) {
		prior = f;
		f = f->next;
	}

	if (f) {
		if (prior) {
			prior->next = f->next;
		} else {
			source->forwards = f->next;
		}
		free(f);
		return true;
	} else
		return false;
}
#endif

/*
 * Remove all forwards of an endpoint and indicate how many
 * were removed.
 */
unsigned int remove_forwards(struct endpoint *source)
{
	unsigned int n = 0;

	while (source->forwards) {
		struct forward *f = source->forwards;

		source->forwards = f->next;
		free(f);
		n++;
	}
	return n;
}

static inline void map_ipv4_addr_to_ipv6(__be32 ipv4, struct in6_addr *ipv6)
{
	ipv6->s6_addr32[0] = 0;
	ipv6->s6_addr32[1] = 0;
	ipv6->s6_addr32[2] = htobe32(0x0000FFFF);
	ipv6->s6_addr32[3] = ipv4;
}


/* Create endpoint from the ah_attr values */
static struct endpoint *at_to_ep(struct i2r_interface *i, struct ibv_ah_attr *at)
{
	struct endpoint *ep;
	struct in_addr addr;
	struct ibv_ah *ah;

	memcpy(&addr, (void *)&at->grh.dgid + 12, sizeof(struct in_addr));

	if (!at->dlid && !addr.s_addr)
		panic("Nothing to resolve\n");

redo:
	if (at->dlid) {

		if (i == i2r + ROCE)
			panic("DLID with ROCE\n");

		ep = hash_find(i->ep, &at->dlid);
		if (ep) {
			if (ep->addr.s_addr == 0 && addr.s_addr)
			{
				/* Ok we can add the IP address that was unknown earlier */
				lock();
				ep = hash_find(i->ep, &at->dlid);
				if (ep && ep->addr.s_addr == 0)
					ep->addr = addr;
				hash_add(i->ip_to_ep, &ep);
				unlock();
			}
			return ep;
		}
	}

	if (addr.s_addr) {
		ep = hash_find(i->ip_to_ep, &addr.s_addr);
		if (ep) {
			if (at->dlid && ep->lid == 0 && unicast_lid(at->dlid)) {
				/* Add earlier unknown LID */
				lock();
				ep = hash_find(i->ip_to_ep, &addr.s_addr);
				if (ep->lid == 0)
					ep->lid = at->dlid;
				hash_add(i->ep, &ep);
				unlock();
			}
			return ep;
		}
	}

	if (i == i2r + ROCE) {

		at->is_global = 1;
		map_ipv4_addr_to_ipv6(addr.s_addr, (struct in6_addr *)&at->grh.dgid);

	} else if (addr.s_addr) {	/* INFINIBAND is a bit more involved and some calls here may take a long time*/

		struct rdma_cm_id *id;
		struct sockaddr_in sin = {
			.sin_family = AF_INET,
			.sin_addr = addr,
			.sin_port = 1,
		};

		if (rdma_create_id(NULL, &id, NULL, RDMA_PS_UDP)) {
			logg(LOG_ERR, "Failed to create rdma_cm_id:%s\n", errname());
			return NULL;
		}

		if (rdma_resolve_addr(id, NULL, (struct sockaddr *)&sin, 2000)) {

			logg(LOG_ERR, "Failed to resolve address %s:%d:%s\n", inet_ntoa(sin.sin_addr), sin.sin_port, errname());
			rdma_destroy_id(id);
			return NULL;

		} else if (rdma_resolve_route(id, 2000)) {

			logg(LOG_ERR, "Failed to resolve route:%s\n", errname());
			rdma_destroy_id(id);
			return NULL;

		}

		at->is_global = 0;
		at->dlid = be16toh(id->route.path_rec->dlid);
		at->sl = id->route.path_rec->sl;
		at->src_path_bits = be16toh(id->route.path_rec->slid) & ((1 << i->port_attr.lmc) - 1);
		at->static_rate = id->route.path_rec->rate;
		if (at->port_num != id->port_num)
			panic("Port number mismatch\n");

		rdma_destroy_id(id);

	}

	if (addr.s_addr && !valid_addr(i, addr)) {
		logg(LOG_ERR, "at_to_ep: %s Invalid address %s\n", i->text, inet_ntoa(addr));
		return NULL;
	}

	if (at->dlid && !unicast_lid(at->dlid)) {
		logg(LOG_ERR, "at_to_ep: %s Invalid LID %x\n", i->text, at->dlid);
		return NULL;
	}

	if (rate)
		at->static_rate = rate;

	ah = ibv_create_ah(i->pd, at);
	if (!ah) {
		logg(LOG_ERR, "at_to_ep: Failed to create Endpoint on %s: %s. IP=%s\n",
				i->text, errname(), inet_ntoa(addr));
		return NULL;
	}

	ep = calloc(1, sizeof(struct endpoint));
	if (!ep)
		panic("calloc alloc failured\n");

	ep->i = i;
	ep->addr = addr;
	ep->lid = at->dlid;
	ep->ah = ah;

	lock();

	if (!hash_find(i->ip_to_ep, ep) && (i == i2r + ROCE || !hash_find(i->ep, ep))) {

		/* Dont add the address if it has not been determined yet */
		if (addr.s_addr)
			hash_add(i->ip_to_ep, ep);

		/* But IB must have the LID defined so we can at least add that hash */
		if (i2r + INFINIBAND == i)
			hash_add(i->ep, ep);
	} else	/* Concurrent update. Need to redo this action */
		ep = NULL;

	unlock();

	if (!ep)
		goto redo;

	return ep;
}

/* Create Endpoint just from the IP address */
struct endpoint *ip_to_ep(struct i2r_interface *i, struct in_addr addr)
{
	struct ibv_ah_attr at = {
		.dlid = 0,
		.sl = 0,
		.src_path_bits = 0,
		.static_rate = 0,
		.is_global = 0,
		.port_num = i->port,
		.grh = {
			/* .dgid = , */
			.flow_label = 0,
			.sgid_index = i->gid_index,
			.hop_limit = 20,
			.traffic_class = 0
		}
	};

	memcpy((void *)&at.grh.dgid + 12, &addr, sizeof(struct in_addr));
	return at_to_ep(i, &at);
}

/*
 * Get information from an endpoint or create one with the info available
 */
struct endpoint *buf_to_ep(struct buf *buf, struct in_addr addr)
{
	struct i2r_interface *i = buf->c->i;
	struct rdma_channel *c = buf->c;
	struct ibv_wc *w = buf->w;

	struct ibv_ah_attr at = {
		.dlid = w->slid,
		.sl = w->sl,
		.src_path_bits = w->dlid_path_bits,
		.static_rate = 0,
		.is_global = buf->ip_valid,
		.port_num = i->port,
		.grh = {
			/* .dgid = , */
			.flow_label = buf->grh_valid ? be32toh(buf->grh.version_tclass_flow) & 0xFFFF: 0,
			.sgid_index = i->gid_index,
			.hop_limit = buf->ip_valid ? buf->ip.ttl : 0,
			.traffic_class = buf->ip_valid ? buf->ip.tos : 0
		}
	};

        if (i == i2r + INFINIBAND) {	/* Infiniband */

		if (!unicast_lid(w->slid)) {

			/* No source LID */
			logg(LOG_ERR, "Invalid Source LID %x on %s\n", w->slid, c->text);

			return NULL;
		}
		if (buf->grh_valid) {
			struct pgm_header pgm;
			void *position = buf->cur;

			memcpy(&at.grh.dgid, buf->grh.sgid.raw, sizeof(union ibv_gid));

			if (!addr.s_addr && !hash_find(i->ep, &at.dlid)) {

				PULL(buf, pgm);

				if (w->src_qp != 1) {
					/* Direct PGM packet inspection without verification if this is really PGM */
					memcpy(&addr, pgm.pgm_gsi, sizeof(struct in_addr));
					logg(LOG_NOTICE, "Extracted IP address from PGM header: %s %s\n",
						c->text, inet_ntoa(addr));
				}
			}
			buf->cur = position;
		}
	} else	/* SLID contains crap */
		at.dlid = 0;

	memcpy((void *)&at.grh.dgid + 12, &addr, sizeof(struct in_addr));

	return at_to_ep(i, &at);
}

/*
 * Populate address cache to avoid expensive lookups.
 *
 * This is also used on the senders to multicast groups because the recover channels
 * for multicast connections will connect later and then we already have the
 * addresses cached
 */
void learn_source_address(struct buf *buf)
{
	struct in_addr addr = ip_none;

	if (!unicast)	/* If unicast is not enabled then dont bother to gather addresses */
		return;

	if (buf->ip_valid)
		addr.s_addr = buf->ip.saddr;

	buf->source_ep = buf_to_ep(buf, addr);
}

static unsigned show_endpoints(char *b)
{
	int n = 0;

	interface_foreach(i)
		if (i->ep) {
		struct endpoint *e[20];
		unsigned nr;
		unsigned offset = 0;

		n = sprintf(b, "\nEndpoints on %s", i->text);
		while ((nr = hash_get_objects(i->ep, offset, 20, (void **)e))) {
			int j;

			for (j = 0; j < nr; j++) {
				struct endpoint *ep = e[j];
				struct forward *f;

				n += sprintf(b + n, "\n%3d. %s", offset + j + 1, inet_ntoa(e[j]->addr));

				if (ep->lid)
					n += sprintf(b + n, " LID=%x", ep->lid);

				if (ep->gid.global.interface_id)
					n += sprintf(b + n, " GID=%s",
						inet6_ntoa(&ep->gid));

				for (f = ep->forwards; f; f = f->next) {
					n += sprintf(b + n, " Q%d->%sQ%d",
					      f->source_qp, inet_ntoa(f->dest->addr), f->dest_qp);
				}
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
