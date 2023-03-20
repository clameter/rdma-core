#ifndef IB2ROCE_ENDPOINT
#define IB2ROCE_ENDPOINT
/*
 * IB2ROCE management of endpoints and unicast traffic
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

#include "interfaces.h"

extern const struct in_addr ip_none;

/*
 * The forwarding struct describes the forwarding for datagrams
 * coming from a source QP to another QP at an endpoint.
 * This is singly linked list attache to the endpoints
 */
struct forward {
	struct endpoint *dest;
	struct forward *next;
	uint32_t source_qp, dest_qp;
	uint32_t dest_qkey;
};

/*
 * Address information for an endpoint.
 * ah points to the address stucture needed to send data to
 * this endpoint. The rest are basically keys to lookup
 * the ah.
 *
 * Each endpoint has a list of connections. Packets
 * coming in from the host
 */
struct endpoint {
	struct i2r_interface *i;
	struct in_addr addr;
	union ibv_gid gid;
	uint16_t lid;
	struct ibv_ah *ah;
	struct forward *forwards;
};

void list_endpoints(struct i2r_interface *i);

/*
 * A Unicastconnection to a certain port and host with
 * a list of pending I/O items and an rdma channel
 */

enum uc_state { UC_NONE, UC_ADDR_REQ, UC_ROUTE_REQ, UC_CONN_REQ, UC_CONNECTED, UC_ERROR };

/* Enough to fit a GID */
#define hash_max_keylen 16

struct hash_item {
	struct rdma_unicast *next;      /* Linked list to avoid collisions */
	unsigned hash;
	bool member;
	uint8_t key[hash_max_keylen];
};

enum hashes { hash_ip, nr_hashes };

struct rdma_unicast {
	struct i2r_interface *i;
	enum uc_state state;
	struct sockaddr_in sin;		/* Target address */
	struct rdma_channel *c;		/* Channel for resolution and I/O */
	struct fifo pending;		/* Buffers waiting on resolution to complete */
	struct ah_info ai;		/* If ai.ah != NULL then the address info is valid */
	struct hash_item hash[nr_hashes];
};


struct rdma_unicast *new_rdma_unicast(struct i2r_interface *i, struct sockaddr_in *sin);
void resolve_end(struct rdma_unicast *);
void resolve(struct rdma_unicast *ru);
void zap_channel(struct rdma_unicast *ru);


static inline bool multicast_lid(uint16_t lid) {
	return lid & 0xc000;
}

static inline bool unicast_lid(uint16_t lid) {
	return lid > 0 && lid < 0xc000;
}

void learn_source_address(struct buf *buf);

int send_buf(struct buf *buf, struct rdma_unicast *ra);

struct endpoint *ip_to_ep(struct i2r_interface *i, struct in_addr addr);
struct endpoint *buf_to_ep(struct buf *buf, struct in_addr addr);

void add_forward(struct endpoint *source, uint32_t source_qp, struct endpoint *dest, uint32_t dest_qp, uint32_t qkey);
struct forward *find_forward(struct endpoint *source, struct endpoint *dest, uint32_t source_qp);
unsigned int remove_forwards(struct endpoint *source);

#endif

