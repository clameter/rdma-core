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
#include <stdatomic.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <getopt.h>
#include <rdma/rdma_cma.h>
#include <poll.h>
#include <sys/mman.h>
#include <numa.h>
#include <infiniband/mad.h>
#include <linux/if_arp.h>

#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <infiniband/umad_cm.h>
#include <infiniband/umad_str.h>
#include <execinfo.h>
#include "errno.h"
#include "fifo.h"
#include "ring.h"
#include "hash.h"
#include "sched.h"
#include "logging.h"
#include "locking.h"
#include "multicast.h"
#include "interfaces.h"
#include "cli.h"
#include "pgm.h"
#include "endpoint.h"
#include "unicast.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

/* Unicast packet reception */
void receive_ud(struct buf *buf)
{
	struct rdma_channel *c = buf->c;
	const char *reason;
	struct endpoint *e, *d;
	struct forward *f;
	struct ibv_wc *w = buf->w;
	struct i2r_interface *dest_i = i2r + ((c->i - i2r) ^ 1);

	learn_source_address(buf);

	if (!buf->grh_valid)
		/* Even if there is no GRH there is space reserved at the beginning for UD packets */
		buf->cur += 40;

	e = buf->source_ep;
	if (!e) {
		reason = "Cannot find endpoint";
		goto discard;
	}

	if (buf->ip_valid) {
		struct in_addr addr;

		addr.s_addr = buf->ip.daddr;
		d = ip_to_ep(dest_i, addr);

	} else
		d = NULL;

	f = find_forward(e, d, w->src_qp);

 	if (!f) {
		lock();

		/* Hmm... Not good. Maybe there is a wild chart entry if the source_qp was not determined yet */
		f = find_forward(e, d, 0);
		if (f) {
			f->source_qp = w->src_qp;
			logg(LOG_NOTICE, "Inserted QP#%x into forwarding entry for %s\n", w->src_qp, inet_ntoa(e->addr));

			/* And add the missing reverse forward */
			add_forward(f->dest, f->dest_qp, e, f->source_qp, f->dest_qkey); 
		}

		unlock();
 	}
 
	if (!f) {
		reason = "No QPN is connected";
		goto discard;
 	}	

	/*
	 * This is to satisfy udaddy. Other apps that may use the immediate data differently may not work
	 * if the value in immm matches the src_qp.... Maybe we should not do this by default ?
	 */
	if (ntohl(buf->imm) == w->src_qp)
		buf->imm = htonl(find_channel(f->dest->i, channel_ud)->qp->qp_num);

	logg(LOG_NOTICE, "receive_ud %s Packet len=%u 0x%x lid=%d forwarded to %s %s:0x%x lid=%d qkey=%x\n", c->text,
			w->byte_len, w->src_qp, e->lid, find_channel(dest_i, channel_ud)->text,
				inet_ntoa(f->dest->addr), f->dest_qp, f->dest->lid, f->dest_qkey);

	send_ud(find_channel(dest_i, channel_ud), buf, f->dest->ah, f->dest_qp, f->dest_qkey);
 	return;
 
discard:
	logg(LOG_NOTICE, "receive_ud:Discard %s %s LEN=%ld\n", c->text, reason, buf->end - buf->cur);
	st(c, packets_invalid);
}


