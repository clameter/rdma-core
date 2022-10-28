#ifndef IB2ROCE_BUFFERS
#define IB2ROCE_BUFFERS

/*
 * DMA Buffer Management
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
#include <sys/types.h>
#include <ctype.h>
#include <sys/socket.h>
#include <rdma/rdma_cma.h>
#include <infiniband/ib.h>
#include <infiniband/verbs.h>
#include <linux/ip.h>

#include "sched.h"
#include "channel.h"

/*
 * Manage freelist using simple single linked list with the pointer
 * to the next free element at the beginning of the free buffer
 */
extern int nr_buffers;

#define BUFFER_SIZE 8192
#define META_SIZE 1024
#define DATA_SIZE (BUFFER_SIZE - META_SIZE)

#define MAX_INLINE_DATA 64

/*
 * Buf is page aligned and contains 2 pages. The layout attempts to put critical components
 * at page boundaries
 */
struct buf {
	uint8_t raw[DATA_SIZE];		/* Raw Frame */
	union {
		struct {
			struct buf *next;	/* Next free buffer */
			bool free;
			unsigned refcount;	/* Refcount */
			uint8_t *cur;		/* Current position in the buffer */
			uint8_t *end;		/* Pointer to the last byte in the packet + 1 */

			struct rdma_channel *c;	/* Which Channels does this buffer belong to */
			struct ibv_wc *w;	/* Work Completion struct */
			struct ibv_sge sge;	/* SGE for send */
			struct ibv_send_wr wr;	/* Write request */
			struct endpoint *source_ep;
			struct mc_interface *mi;	/* Destination MC interface / Group */

			bool ip_valid;		/* IP header valid */
			bool grh_valid;		/* Valid GRH header */
			bool imm_valid;		/* unsigned imm is valid */
			bool ip_csum_ok;	/* Hardware check if IP CSUM was ok */

			unsigned imm;		/* Immediate data from the WC */

			/* Structs pulled out of the frame */
			struct ibv_grh grh;
			struct iphdr ip;
		};
		uint8_t meta[META_SIZE];
	};
};

typedef void receive_callback(struct buf *);

static inline void pull(struct buf *buf, void *dest, unsigned length)
{
	memcpy(dest, buf->cur, length);
	buf->cur += length;
}

#define PULL(__BUF, __VAR) pull(__BUF, &(__VAR), sizeof(__VAR))

extern struct buf *buffers;

extern struct buf *nextbuffer;	/* Pointer to next available RDMA buffer */

struct buf *alloc_buffer(struct rdma_channel *c);
void free_buffer(struct buf *buf);

void __get_buf(struct buf *buf);
void __put_buf(struct buf *buf);

void get_buf(struct buf *buf);
void put_buf(struct buf *buf);

void init_buf(void);

void clear_channel_bufs(struct rdma_channel *c);

/*
 * Information provided by RDMA subsystem for how
 * to send a stream to an endpoint that
 * maybe multicast or unicast.
 */
struct ah_info {
	struct ibv_ah *ah;      /* Endpoint Identification */
	uint32_t remote_qpn;    /* Address on the Endpoint */
	uint32_t remote_qkey;
};

/*
 * Do not use a buffer but simply include data directly into WR.
 * Advantage: No buffer used and therefore faster since no memory
 * fetch has to be done by the RDMA subsystem and no completion
 * event has to be handled.
 *
 * No MR is being used so this works for any QP.
 *
 * Space in the WR is limited, so it only works for very small packets.
 */
int send_inline(struct rdma_channel *c, void *addr, unsigned len, struct ah_info *ai, bool imm_used, unsigned imm);

int send_ud(struct rdma_channel *c, struct buf *buf, struct ibv_ah *ah, uint32_t remote_qpn, uint32_t qkey);

/*
 * Send data to a target. No metadata is used in struct buf. However, the buffer must be passed to the wc in order
 * to be able to free up resources when done.
 */
int send_to(struct rdma_channel *c,
	void *addr, unsigned len, struct ah_info *ai,
	bool imm_used, unsigned imm,
	struct buf *buf);

struct i2r_interface;

void send_buf_to(struct i2r_interface *i, struct buf *buf, struct sockaddr_in *sin);

int send_pending_buffers(struct rdma_channel *c);
void send_queue_monitor(void *private);

#endif


