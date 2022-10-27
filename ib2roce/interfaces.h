#ifndef IB2ROCE_INTERFACES
#define IB2ROCE_INTERFACES
/*
 * RDMA / Socket Interface
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

#include <linux/if.h>

#include "errno.h"
#include "fifo.h"
#include "ring.h"
#include "hash.h"
#include "sched.h"
#include "logging.h"
#include "locking.h"
#include "buffers.h"
#include "multicast.h"

#define MAX_GID 20

extern char *ib_name, *roce_name;

extern bool bridging;
extern bool unicast;

extern int rate;	/* Limit sending rate */
extern int rrate;	/* Software delay per message for ROCE */
extern int irate;	/* Software delay per message for Infiniband */
extern int max_rburst;	/* Dont delay until # of packets for ROCE */
extern int max_iburst;	/* Dont delay until # of packets for Infiniband */

#define MAX_CHANNELS_PER_INTERFACE 10

struct channel_list {
	struct rdma_channel *c[MAX_CHANNELS_PER_INTERFACE];
};

bool is_a_channel_of(struct rdma_channel *, struct channel_list *);

/* Iterators for channel array */

/* Iterator is a pointer to pointer to the object */
#define channelp_foreach(_channel, _channel_list)					\
	for(struct rdma_channel **_channel = ((struct rdma_channel **)&((_channel_list)->c));				\
		_channel < ((struct rdma_channel **)&((_channel_list)->c)) + MAX_CHANNELS_PER_INTERFACE; _channel++)

/* Iterator that is a pointer to the object */
#define channel_foreach(_channel, _channel_list)						\
	channelp_foreach(_ch2, _channel_list) for(struct rdma_channel *_channel = *_ch2; _channel; _channel = NULL)

struct i2r_interface {
	/* Not changed when multithreading */
	struct ibv_context *context;		/* Not for RDMA CM use */
	struct ibv_comp_channel *comp_events;
	struct rdma_event_channel *rdma_events;
	struct channel_list channels;
	struct ibv_cq *cq;
	struct ibv_pd *pd;
	struct ibv_mr *mr;
	unsigned port;
	unsigned mtu;
	unsigned maclen;
	const char *text;
	char if_name[IFNAMSIZ];
	const char *rdma_name;
	uint8_t if_mac[ETH_ALEN];
	struct sockaddr_in if_addr;
	struct sockaddr_in if_netmask;
	unsigned ifindex;
	unsigned mc_per_qp;			/* How many MCs per QP */
	unsigned numa_node;			/* NUMA Affinity of the interface */
	unsigned gid_index;
	union ibv_gid gid;
	struct ibv_device_attr device_attr;
	struct ibv_port_attr port_attr;
	int iges;
	struct ibv_gid_entry ige[MAX_GID];

	/* The following may be updated in a multithreaded environment
	 * from the multicast thread running for each interface.
 	 *
         * Serialization is required but we generally are a bit loose
	 * by allowing read access without locks.
         */
	struct hash *ru_hash;
	struct fifo resolve_queue;		/* List of send buffers with unresolved addresses */
	struct hash *ep;			/* Hash of all endpoints reachable here */
	struct hash *ip_to_ep;			/* Hash based on IP address */
	unsigned mc_rate_limited;		/* Number of MC groups where rate limiting is ongoing */
	unsigned long out_of_buffer;		/* Last state of /sys/class/infiniband .../overrun */

	/* PGM information:  Only updated from the multicast channel core */
	unsigned nr_tsi;
	struct hash *pgm_tsi_hash;
	struct hash *pgm_record_hash;
};

extern struct i2r_interface i2r[];

bool sum_stats(unsigned *stats, struct i2r_interface *i, enum channel_type type);

/* Interator for the Interfaces */
#define interface_foreach(_interface)								\
	for(struct i2r_interface *_interface = i2r; _interface < i2r + NR_INTERFACES;_interface++) \
	if (_interface->context)

/* Event handlers */
void handle_comp_event(void *private);
void handle_rdma_event(void *private);
void handle_async_event(void *private);

void handle_receive_packet(void *private);

const char *inet6_ntoa(void *x);
void set_rate(struct mc *m);
void set_rates(void);

/* Scan a cores rdma channels for completion queue entries */
void scan_cqs(void *private);

void reset_flags(struct buf *);

int check_rdma_device(enum interfaces i, int port, char *name,
	       struct ibv_context *c, struct ibv_port_attr *a, struct ibv_device_attr *d);

/* Scan through available RDMA devices in order to locate the devices for bridging */
int find_rdma_devices(void);
/* Find the interface that allows us to reach a certain IP address */
struct i2r_interface *find_interface(struct sockaddr_in *sin);
struct rdma_channel *find_channel(struct i2r_interface *i, enum channel_type type);

void check_joins(struct channel_list *infiniband, struct channel_list *roce);
void next_join_complete(void);

void check_out_of_buffer(void *);

void post_receive(struct rdma_channel *c);
void post_receive_buffers(void);

void setup_interface(enum interfaces);

void shutdown_ib(void);
void shutdown_roce(void);

static inline bool __valid_addr(struct i2r_interface *i, __be32 saddr)
{
	unsigned netmask = i->if_netmask.sin_addr.s_addr;

	return ((saddr & netmask) ==  (i->if_addr.sin_addr.s_addr & netmask));
}

static inline bool valid_addr(struct i2r_interface *i, struct in_addr addr)
{
	return __valid_addr(i, addr.s_addr);
}

#endif
