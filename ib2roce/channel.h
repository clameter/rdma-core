#ifndef IB2ROCE_CHANNEL
#define IB2ROCE_CHANNEL

/*
 * RDMA Gateway Interface definitions
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

#include <stdbool.h>
#include <infiniband/verbs.h>

#include "buffers.h"
#include "fifo.h"

#define ROCE_PORT 4791
#define ETHERTYPE_ROCE 0x8915

extern unsigned default_port;

extern bool latency;

enum interfaces { INFINIBAND, ROCE, NR_INTERFACES };

extern const char *interfaces_text[NR_INTERFACES];

enum stats { packets_received, packets_sent, packets_bridged, packets_invalid, packets_queued,
		join_requests, join_failure, join_success,
		leave_requests, nr_stats
};

extern enum interfaces default_interface;

extern const char *stats_text[nr_stats];

enum channel_type { channel_rdmacm, channel_ud, channel_qp1,
	channel_raw, channel_ibraw,
	channel_packet, channel_incoming,
	channel_err, nr_channel_types };

#define NO_CORE (-1)

struct buf;
typedef void receive_callback(struct buf *);

/*
 * Channel data stucture,
 *
 * Channels may be associated with a core on which a busyloop runs.
 *
 * Therefore changes to variables may only be made from code
 * running on that core if multithreading is active.
 */
struct rdma_channel {
	struct i2r_interface *i;	/* The network interface of this channel */
	struct core_info *core;		/* Core the channel is on or NULL if comp_events is used */
	receive_callback *receive;
	struct ibv_cq *cq;		/* Every channel has a distinct CQ */
	struct ibv_qp *qp;		/* All of the ibv_xxes are pointing to the interface versions if this is not a rdmacm channel */
	struct ibv_mr *mr;
	struct ibv_comp_channel *comp_events;
	struct ibv_pd *pd;
	struct ibv_flow *flow;
	unsigned int active_receive_buffers;
	unsigned int active_send_buffers;	/* if the sender is on a different core than the receiver then we have a race condition for the buffers */
	unsigned int cq_high;		/* Largest number of CQs taken from the queue */
	struct rdma_channel *destination;	/* If set the destination channel for bridging */
	unsigned int nr_cq;		/* Number of items for the CQ */
	unsigned int nr_send;		/* Maximum number of write buffers to use */
	unsigned int nr_receive;	/* Number of read buffer to post */
	unsigned stats[nr_stats];
	unsigned long bytes_sent;
	unsigned long bytes_received;
	unsigned min_packet_size;
	unsigned max_packet_size;
	enum channel_type type;
	struct fifo send_queue;		/* Packets that were deferred for write */
	unsigned max_backlog;
	unsigned backlog_drop;	/* Packets dropped from backlog */
	bool listening;			/* rdmacm Channel is listening for connections */
	bool reduced_rate_warning;	/* Warning about a reduced rate was given */
	unsigned instance;		/* If multuple instances exist */
	const char *text;
	struct rdma_unicast *ru;	/* Only rdmacm */
	struct rdma_cm_id *id;		/* Only rdmacm */
	struct sockaddr *bindaddr;	/* Only rdmacm */
	struct ibv_qp_attr attr;	/* Only !rdmacm */
	int fh;				/* Only channel_packet */
	uint64_t last_snapshot;		/* when was the last snapshot taken */
	unsigned last_received, last_sent;
	unsigned pps_in, pps_out;	/* Rate in the last interval */
	unsigned max_pps_in, max_pps_out; /* Max Rate seen */
	unsigned nr_mcs;		/* Number of multicast groups attached via this channel */
	struct mc *mc[];		/* Dynamically sized structure depending on the number of allowed MC groups for an interface */
};

static inline int sendqueue_avail(struct rdma_channel *c)
{
	return (int)c->nr_send - (int)c->active_send_buffers;
}

static inline bool sendqueue_full(struct rdma_channel *c)
{
	return sendqueue_avail(c) <= 0;
}

static inline void st(struct rdma_channel *c, enum stats s)
{
	c->stats[s]++;
}

typedef bool setup_callback(struct rdma_channel *c);

/*
 * Matrix of channel types and their characteristics
 */
extern struct channel_info {

	const char *suffix;
	short core;
	short alt_core;	/* If that core is not available what is the other choice */
	uint32_t nr_cq;		/* NR of CQ entries to allocate allocate to this channel */
	uint32_t nr_send;	/* NR buffers for receive queue */
	uint32_t qkey;
	uint16_t qp_type;
	setup_callback *setup;
	receive_callback *receive;
	enum channel_type fallback;

} channel_infos[nr_channel_types];

int channel_stats(char *b, struct rdma_channel *c, const char *interface, const char *type);
void channel_stat(int ident, FILE *out, struct rdma_channel *c);

void start_channel(struct rdma_channel *c);
void stop_channel(struct rdma_channel *c);

struct rdma_channel *new_rdma_channel(struct i2r_interface *i, enum channel_type type, unsigned instance);

void arm_channels(struct core_info *core);
void arm_channel(struct rdma_channel *);
void channel_destroy(struct rdma_channel *c);

void all_channels(FILE *out, void (*func)(FILE *out, struct rdma_channel *));

void start_calculate_pps(void);

void show_core_config(void);

int allocate_rdmacm_qp(struct rdma_channel *c, bool multicast);

receive_callback receive_multicast;

#ifdef UNICAST
receive_callback receive_main, receive_raw, receive_ud, receive_qp1;
#endif

#endif

