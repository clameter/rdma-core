#ifndef IB2ROCE_MULTICAST
#define IB2ROCE_MULTICAST
/*
 * RDMA / Socket Multicast Support
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include "errno.h"
#include "fifo.h"
#include "ring.h"
#include "hash.h"
#include "sched.h"
#include "logging.h"
#include "locking.h"
#include "buffers.h"


#define MAX_MC 1000

extern unsigned nr_mc;		/* Multicast groups entries */
extern unsigned active_mc;	/* MC groups active */

enum mc_status { MC_OFF, MC_JOINING, MC_JOINED, MC_ERROR, NR_MC_STATUS };

extern const char *mc_text[NR_MC_STATUS];

extern unsigned int default_mc_port;

/* A multicast group.
 *
 * ah_info points to multicast address and QP number in use
 * for the stream. There are no "ports" unless they are
 * embedded in the GID (like done by CLLM).
 *
 * Multicast groups are setup before we enter multithreaded mode
 * However, the state of joins etc may change in multithreaded
 * mode. Access to that status information requires some care.
 */
struct mc_interface {
	struct rdma_channel *channel;
	enum mc_status status;
	bool sendonly;
	struct ah_info ai;
	struct sockaddr *sa;

	/* Statistics */
	uint32_t packet_time;		/* How much time must elapse for a packet to be sent 0 = disabled */
	uint32_t max_burst;		/* How long can a burst last */
	uint64_t last_sent;		/* Last time a packet was sent */
	uint64_t last_delayed;		/* Last a delayed packet was scheduled */
	unsigned pending;		/* How many packets are waiting to be sent */
	unsigned burst;			/* # of packets encountered with pacing below packet_time */
	unsigned long delayed;		/* Packets delayed */
};

struct mc {
	struct in_addr addr;
	struct mc_interface interface[NR_INTERFACES];
	void (*callback)(struct mc *, enum interfaces, struct buf *);
	uint8_t tos_mode;
	uint8_t mgid_mode;
	bool enabled;				/* Are we handling traffic? */
	bool admin;				/* Administrative group */
	uint16_t port;
	const char *text;
};

extern struct mc mcs[MAX_MC];

int hash_add_mc(struct mc *m);
struct mc *hash_lookup_mc(struct in_addr addr);

/* Setup the addreses for ROCE and INFINIBAND based on a ipaddr:port spec */
void setup_mc_addrs(struct mc *m, struct sockaddr_in *si);

/* Multicast group specifications on the command line */
int new_mc_addr(char *arg,
	bool sendonly_infiniband,
	bool sendonly_roce);

struct sockaddr_in *parse_addr(const char *arg, int port,
	uint8_t *p_mgid_mode, uint8_t *p_tos_mode, bool mc_only);



int leave_mc(enum interfaces i, struct rdma_channel *);

/* MGID format related functions */
const char *mgid_text(struct mc *m);
void mgids_out(void);
bool mgid_check(struct mc *m, unsigned short signature);

unsigned show_multicast(char *b);

#endif
