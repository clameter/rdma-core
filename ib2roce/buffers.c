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

#include "errno.h"
#include "locking.h"
#include "logging.h"
#include "buffers.h"
#include "cli.h"
#include "hash.h"
#include "endpoint.h"

#include <sys/mman.h>
#include <stdatomic.h>
#include <stdint.h>

/*
 * Manage freelist using simple single linked list with the pointer
 * to the next free element at the beginning of the free buffer
 */
int nr_buffers = 200000;
static bool huge = false;

struct buf *buffers;
struct buf *nextbuffer;

static bool buf_cmpxchg(struct buf **x, struct buf *y, struct buf *z)
{
	if (multithreaded) {
		return atomic_compare_exchange_weak(x, &y, z);

	} else {
		if (*x == y) {
			*x = z;
			return true;
		}
		return false;
	}
}

struct buf *alloc_buffer(struct rdma_channel *c)
{
	struct buf *buf, *next;

	do {
		buf = nextbuffer;
		if (!buf)
			goto oom;

		next = buf->next;
	} while (!buf_cmpxchg(&nextbuffer, buf, next));

	buf->free = false;
	buf->c = c;
	buf->refcount = 1;

#ifdef DEBUG
	buf->next = NULL;

	for(uint8_t *q = buf->raw; q < buf->raw + DATA_SIZE; q++)
		if (*q)
			panic("buffer content not zeroed\n");
#endif
	return buf;

oom:
	panic("Out of Buffers allocating for channel %s\n", c ? c->text : "Unknown");
	return NULL;
}

void free_buffer(struct buf *buf)
{
#ifdef DEBUG
	memset(buf->raw, 0, DATA_SIZE);
#endif
	buf->free = true;

	do {
		buf->next = nextbuffer;

	} while (!buf_cmpxchg(&nextbuffer, buf->next, buf));
}

void __get_buf(struct buf *buf)
{
	if (!buf->refcount)
		panic("Buf refcount zero on __get_buf()\n");

	buf->refcount++;
}

void __put_buf(struct buf *buf)
{
 	buf->refcount--;
 	if (buf->refcount) {
 		return;
 	}

	free_buffer(buf);
}

void get_buf(struct buf *buf)
{
	unsigned x;

	if (multithreaded) {
		x = atomic_fetch_add(&buf->refcount, 1);
		if (!x)
			panic("Buf refcount zero in get_buf()\n");
	} else
		__get_buf(buf);
}

void put_buf(struct buf *buf)
{
	unsigned x;

	if (multithreaded) {
		x = atomic_fetch_sub(&buf->refcount, 1);
		if (x > 1)
 			return;

		free_buffer(buf);
	} else
		__put_buf(buf);

}

/* Remove all buffers related to a channel */
void clear_channel_bufs(struct rdma_channel *c)
{
	struct buf *buf;

	for (buf = buffers; buf < buffers + nr_buffers; buf++) {

		if (!buf->free && buf->c == c)
			free_buffer(buf);
	}
}

void init_buf(void)
{
	int i;
	unsigned flags;
	unsigned long x = nr_buffers;

	if (sizeof(struct buf) != BUFFER_SIZE)
		panic("struct buf is not 8k as required\n");

	flags = MAP_PRIVATE | MAP_ANONYMOUS;
	if (huge)
		flags |= MAP_HUGETLB;

	x *= BUFFER_SIZE;

	if (x > 1000000000)
		logg(LOG_INFO, "Allocate %lu MByte of memory for %u buffers\n",
				x / 1024 / 1024, nr_buffers);

	buffers = mmap(0, x, PROT_READ|PROT_WRITE, flags, -1, 0);
	if (!buffers)
		panic("Cannot allocate %lu KB of memory required for %d buffers. Error %s\n",
				x / 1024, nr_buffers, errname());

	/*
	 * Free in reverse so that we have a linked list
	 * starting at the first element which points to
	 * the second and so on.
	 */
	for (i = nr_buffers; i > 0; i--)
		free_buffer(&buffers[i-1]);
}

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
int send_inline(struct rdma_channel *c, void *addr, unsigned len, struct ah_info *ai, bool imm_used, unsigned imm)
{
	struct ibv_sge sge = {
		.length = len,
		.addr = (uint64_t)addr
	};
	struct ibv_send_wr wr = {
		.sg_list = &sge,
		.num_sge = 1,
		.opcode = imm_used ? IBV_WR_SEND_WITH_IMM : IBV_WR_SEND,
		.send_flags = IBV_SEND_INLINE,
		.imm_data = imm,
		.wr = {
			/* Get addr info  */
			.ud = {
				.ah = ai->ah,
				.remote_qpn = ai->remote_qpn,
				.remote_qkey = ai->remote_qkey
			}
		}

	};
	struct ibv_send_wr *bad_send_wr;
	int ret;

	if (len > MAX_INLINE_DATA)
		return -E2BIG;

	ret = ibv_post_send(c->qp, &wr, &bad_send_wr);
	if (ret) {
		errno = -ret;
		logg(LOG_ERR, "Failed to post inline send: %s on %s\n", errname(), c->text);
	} else
		logg(LOG_INFO, "Inline Send to QPN=%d QKEY=%x %d bytes\n",
				wr.wr.ud.remote_qpn, wr.wr.ud.remote_qkey, len);

	return ret;
}

/*
 * Send data to target using native RDMA structs relying on state in struct buf.
 */
int send_ud(struct rdma_channel *c, struct buf *buf, struct ibv_ah *ah, uint32_t remote_qpn, uint32_t qkey)
{
	struct ibv_send_wr wr, *bad_send_wr;
	struct ibv_sge sge;
	int ret;
	unsigned len = buf->end - buf->cur;

	buf->c = c;	/* Change ownership to sending channel */
	buf->w = NULL;

	memset(&wr, 0, sizeof(wr));
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.opcode = buf->imm_valid ? IBV_WR_SEND_WITH_IMM : IBV_WR_SEND;
	wr.imm_data = buf->imm;
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.wr_id = (uint64_t)buf;

	/* Get addr info  */
	wr.wr.ud.ah = ah;
	wr.wr.ud.remote_qpn = remote_qpn;
	wr.wr.ud.remote_qkey = qkey;

	sge.length = buf->end - buf->cur;
	sge.lkey = c->mr->lkey;
	sge.addr = (uint64_t)buf->cur;

	if (len <= MAX_INLINE_DATA) {
		wr.send_flags = IBV_SEND_INLINE;
		ret = ibv_post_send(c->qp, &wr, &bad_send_wr);
	} else {
		get_buf(buf);
		c->active_send_buffers++;
		ret = ibv_post_send(c->qp, &wr, &bad_send_wr);
	}

	if (ret) {
		errno = ret;
		logg(LOG_WARNING, "Failed to post send: %s on %s. Active Receive Buffers=%d/%d Active Send Buffers=%d\n", errname(), c->text, c->active_receive_buffers, c->nr_receive, c->active_send_buffers);
	} else
		logg(LOG_DEBUG, "RDMA Send to QPN=%d QKEY=%x %d bytes\n",
			wr.wr.ud.remote_qpn, wr.wr.ud.remote_qkey, len);

	return ret;
}

int send_pending_buffers(struct rdma_channel *c)
{
	while (c->active_send_buffers < c->nr_send) {
		struct buf *buf = fifo_get(&c->send_queue);
		struct ibv_send_wr *bad_send_wr;
		int ret;

		if (!buf)
			return true;

		ret = ibv_post_send(c->qp, &buf->wr, &bad_send_wr);
		if (ret) {
			errno = ret;
			logg(LOG_WARNING, "Failure to post send on %s: %s\n", c->text, errname());
			put_buf(buf);
		} else
			c->active_send_buffers++;
	}
	return false;
}

static void setup_wr(struct rdma_channel *c, void *addr, unsigned len,
	struct ah_info *ai, bool imm_used, unsigned imm, struct buf *buf)
{
	if (!ai->ah)
		panic("Send without a route to a destination\n");

	buf->c = c;	/* Change ownership to sending channel */
	buf->w = NULL;

	memset(&buf->wr, 0, sizeof(struct ibv_send_wr));
	buf->wr.sg_list = &buf->sge;
	buf->wr.num_sge = 1;
	buf->wr.opcode = imm_used ? IBV_WR_SEND_WITH_IMM: IBV_WR_SEND;
	buf->wr.send_flags = IBV_SEND_SIGNALED;
	buf->wr.wr_id = (uint64_t)buf;
	buf->wr.imm_data = imm;

	/* Get addr info  */
	buf->wr.wr.ud.ah = ai->ah;
	buf->wr.wr.ud.remote_qpn = ai->remote_qpn;
	buf->wr.wr.ud.remote_qkey = ai->remote_qkey;

	buf->sge.length = len;
	buf->sge.lkey = c->mr->lkey;
	buf->sge.addr = (uint64_t)addr;
}

/*
 * Send data to a target. No metadata is used in struct buf. However, the buffer must be passed to the wc in order
 * to be able to free up resources when done.
 *
 * This version does not do any queuing or checking if the send buffers are full.
 */
int __send_to(struct rdma_channel *c,
	void *addr, unsigned len, struct ah_info *ai,
	bool imm_used, unsigned imm,
	struct buf *buf)
{
	int ret;
	struct ibv_send_wr *bad_send_wr;


	setup_wr(c, addr, len, ai, imm_used, imm, buf);
	ret = ibv_post_send(c->qp, &buf->wr, &bad_send_wr);
	if (ret) {
		errno = ret;
		logg(LOG_WARNING, "Failed to post send: %s on %s. Active Receive Buffers=%d/%d Active Send Buffers=%d\n", errname(), c->text, c->active_receive_buffers, c->nr_receive, c->active_send_buffers);
		put_buf(buf);
	} else {
		c->active_send_buffers++;
		logg(LOG_DEBUG, "RDMA Send to QPN=%d QKEY=%x %d bytes\n",
			buf->wr.wr.ud.remote_qpn, buf->wr.wr.ud.remote_qkey, len);
	}
	return ret;
}

/*
 * Send data to a target while dealing with the backlog
 */
int send_to(struct rdma_channel *c,
	void *addr, unsigned len, struct ah_info *ai,
	bool imm_used, unsigned imm,
	struct buf *buf)
{
	int ret;
	unsigned backlog = fifo_items(&c->send_queue);

	if (backlog || c->active_send_buffers >= c->nr_send) {
		setup_wr(c, addr, len, ai, imm_used, imm, buf);
		goto queue;
	}

	ret = __send_to(c, addr,len, ai, imm_used, imm, buf);
	if (!ret)
		return 0;

	if (ret != ENOMEM)
		return ret;

queue:
	fifo_put(&c->send_queue, buf);
	st(c, packets_queued);

	if (backlog > c->max_backlog) {
		if (!c->backlog_drop)
			logg(LOG_WARNING, "Backlog for %s has more than %d buffers. Starting to drop from the backlog.\n",
			       c->text, c->max_backlog);
		do {

			buf = fifo_get(&c->send_queue);
			if (!buf)
				break;
			put_buf(buf);
			c->backlog_drop++;

		} while (true);
	}
	return 0;
}

/* Send buffer based on state in struct buf. Unicast only */
int send_buf(struct buf *buf, struct rdma_unicast *ra)
{
	unsigned len = buf->end - buf->cur;
	int ret;

	if (len < MAX_INLINE_DATA) {
		ret = send_inline(ra->c, buf->cur, len, &ra->ai, buf->imm_valid, buf->imm);
	} else
		ret = send_to(ra->c, buf->cur, len, &ra->ai, buf->imm_valid, buf->imm, buf);

	return ret;
}


static unsigned keylength[nr_hashes] = { 4 };

struct rdma_unicast *hash_table[nr_hashes][0x100];

static unsigned generate_hash_key(enum hashes type, uint8_t *key, void *p)
{
	int i;
	unsigned sum = 0;

	memcpy(key, p, keylength[type]);

	for (i = 0; i < keylength[type]; i++)
		sum += key[i];

	return sum & 0xff;
}

static struct rdma_unicast *find_key_in_chain(enum hashes type,
	struct rdma_unicast *next, uint8_t *key)
{
	for ( ; next != NULL; next = next->hash[type].next)
		if (memcmp(key, next->hash[type].key, keylength[type]) == 0)
			break;

	return next;
}

static void add_to_hash(struct rdma_unicast *ra, enum hashes type, void *p)
{
	struct hash_item *h = &ra->hash[type];

	if (h->member)
		abort();        /* Already a member of the hash */

	h->hash = generate_hash_key(type, h->key, p);

	/* Duplicate key ? */
	if (find_key_in_chain(type, hash_table[type][h->hash], h->key))
		abort();

	h->next = hash_table[type][h->hash];
	hash_table[type][h->hash] = ra;

	h->member = true;
}

static struct rdma_unicast *find_in_hash(enum hashes type, void *p)
{
	uint8_t key[hash_max_keylen];
	unsigned hash;

	hash = generate_hash_key(type, key, p);

	return find_key_in_chain(type, hash_table[type][hash], key);
}

/* Ship a unicast datagram to an IP address .... */
void send_buf_to(struct i2r_interface *i, struct buf *buf, struct sockaddr_in *sin)
{
	struct rdma_unicast *ra;
	int ret;

	/* Find address */
	ra = find_in_hash(hash_ip, &sin->sin_addr);
	if (!ra) {
		ra = new_rdma_unicast(i, sin);
		add_to_hash(ra, hash_ip, &sin->sin_addr);
	}

	switch (ra->state) {
		case UC_NONE:   /* We need to resolve the address. Queue up the buffer and initiate */
			fifo_put(&ra->pending, buf);
			resolve(ra);
			return;

		case UC_CONNECTED: /* Channel is open. We can send now */
			ret = send_buf(buf, ra);
			if (!ret)
				logg(LOG_ERR, "Failed to send to %s:%d\n",
				inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
			return;

		default:                /* Resolution is in progress. Just queue it up on the address */
			fifo_put(&ra->pending, buf);
			return;
	}
}

static void buffers_cmd(FILE *out, char *parameters)
{
	struct buf *buf;
	int free = 0;

	for(buf = buffers; buf < buffers + nr_buffers; buf++)
		if (buf->free)
		       free++;

	fprintf(out, "Buffers: Active=%u Total=%u\n", nr_buffers-free , nr_buffers);
	/* Sometime show more details */
}

__attribute__ ((constructor))
static void buffers_init(void)
{
	register_concom("buffers", true, 0, "Print Information about buffer use", buffers_cmd);
	register_enable("buffers", false, NULL, &nr_buffers, "1000000", "10000", NULL,
		"Number of  8K buffers allocated for packet processing");
	register_enable("huge", false, &huge, NULL, "on", "off", NULL,
		"Enable the use of Huge memory for the packet pool");
}
