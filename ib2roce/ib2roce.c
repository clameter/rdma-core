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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <rdma/rdma_cma.h>
#include <infiniband/ib.h>
#include <infiniband/verbs.h>
#include <poll.h>
#include <sys/mman.h>

#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <infiniband/mad.h>
#include <infiniband/umad_cm.h>
#include <infiniband/umad_str.h>
#include "packet.h"
#include "errno.h"
#include "bth_hdr.h"
#include "ib_hdrs.h"
#include "fifo.h"
#include "hash.h"
#include "ibraw.h"
#include "cma-hdr.h"

#define VERSION "2022.0220"

#define MIN(a,b) (((a)<(b))?(a):(b))

#define ROCE_PORT 4791
#define ETHERTYPE_ROCE 0x8915

#define BEACON_SIGNATURE 0xD3ADB33F

// #define HAVE_MSTFLINT
// #define DEBUG

/* Globals */

static unsigned default_port = 0;	/* Port to use to bind to devices  */
static unsigned default_mc_port = 4711;	/* Port for MC groups that do not have a port (if a port is required) */
static bool debug = false;		/* Stay in foreground, print more details */
static bool background = false;		/* Are we actually running in the background ? */
static bool terminated = false;		/* Daemon received a signal to terminate */
static bool update_requested = false;	/* Received SIGUSR1. Dump all MC data details */
static bool beacon = false;		/* Announce our presence (and possibly coordinate between multiple instances in the future */
static bool bridging = true;		/* Allow briding */
static bool unicast = false;		/* Bridge unicast packets */
static bool flow_steering = false;	/* Use flow steering to filter packets */
static int log_packets = 0;		/* Show details on discarded packets */
static bool testing = false;		/* Run some tests on startup */
static bool packet_socket = false;	/* Do not use RAW QPs, use packet socket instead */
static bool loopback_blocking = true;	/* Ask for loopback blocking on Multicast QPs */

/* Timestamp in milliseconds */
static unsigned long timestamp(void)
{
	struct timespec t;

	clock_gettime(CLOCK_REALTIME, &t);
	return t.tv_sec * 1000 + (t.tv_nsec + 500000) / 1000000;
}

__attribute__ ((format (printf, 2, 3)))
static void logg(int prio, const char *fmt, ...)
{
	va_list valist;

	va_start(valist, fmt);

	if (background)
		vsyslog(prio, fmt, valist);
	else
		vprintf(fmt, valist);
}

/*
 * Handling of special Multicast Group MGID encodings on Infiniband
 */
#define nr_mgid_signatures 5

struct mgid_signature {		/* Manage different MGID formats used */
	unsigned short signature;
	const char *id;
	bool port;		/* Port field is used in MGID */
	bool full_ipv4;		/* Full IP address */
	bool pkey;		/* Pkey in MGID */
} mgid_signatures[nr_mgid_signatures] = {
	{	0x0000, "RDMA", false, false, true },
	{	0x401B,	"IPv4",	false, false, true },
	{	0x601B,	"IPv6",	false, false, true },
	{	0xA01B,	"CLLM", true, true, false },
	{	0x4001, "IB",	false, false, false }
};

struct mgid_signature *mgid_mode = mgid_signatures + 3;		/* CLLM is the default */

/*
 * Basic RDMA interface management
 */

#define MAX_GID 20
#define MAX_INLINE_DATA 64

static char *ib_name, *roce_name;

enum interfaces { INFINIBAND, ROCE, NR_INTERFACES };

static const char *interfaces_text[NR_INTERFACES] = { "Infiniband", "ROCE" };

enum stats { packets_received, packets_sent, packets_bridged, packets_invalid,
		join_requests, join_failure, join_success,
		leave_requests,
		nr_stats
};

static const char *stats_text[nr_stats] = {
	"PacketsReceived", "PacketsSent", "PacketsBridged", "PacketsInvalid",
	"JoinRequests", "JoinFailures", "JoinSuccess",
	"LeaveRequests"
};

static int cq_high = 0;	/* Largest batch of CQs encountered */

enum channel_type { channel_rdmacm, channel_ud, channel_raw, channel_packet, nr_channel_types };

struct buf;

typedef void receive_callback(struct buf *);

struct rdma_channel {
	struct i2r_interface *i;	/* The network interface of this channel */
	receive_callback *receive;
	struct ibv_cq *cq;		/* Every channel has a distinct CQ */
	struct ibv_qp *qp;		/* All of the ibv_xxes are pointing to the interface versions if this is not a rdmacm channel */
	struct ibv_mr *mr;
	struct ibv_comp_channel *comp_events;
	struct ibv_pd *pd;
	struct ibv_flow *flow;
	unsigned int active_receive_buffers;
	unsigned int nr_cq;
	unsigned stats[nr_stats];
	enum channel_type type;
	bool listening;		/* rdmacm Channel is listening for connections */
	const char *text;
	struct rdma_unicast *ru;	/* Onlu rdmacm */
	struct rdma_cm_id *id;		/* Only rdmacm */
	struct sockaddr *bindaddr;	/* Only rdmacm */
	struct ibv_qp_attr attr;	/* Only !rdmacm */
	int fh;				/* Only channel_packet */
};

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
	struct rdma_channel *c;
	struct in_addr addr;
	union ibv_gid gid;
	uint16_t lid;
	struct ibv_ah *ah;
	struct forward *forwards;
};

static struct i2r_interface {
	struct ibv_context *context;		/* Not for RDMA CM use */
	struct rdma_event_channel *rdma_events;
	struct rdma_channel *multicast;
	struct rdma_channel *qp1;		/* Channel for QP1 communications but not QP1 (userspace) */
	struct rdma_channel *ud;		/* Regular data */
	struct rdma_channel *raw;
	struct ibv_comp_channel *comp_events;
	struct ibv_cq *cq;
	struct ibv_pd *pd;
	struct ibv_mr *mr;
	unsigned port;
	unsigned mtu;
	unsigned maclen;
	const char *text;
	char if_name[IFNAMSIZ];
	uint8_t if_mac[ETH_ALEN];
	struct sockaddr_in if_addr;
	struct sockaddr_in if_netmask;
	unsigned ifindex;
	unsigned gid_index;
	union ibv_gid gid;
	struct ibv_device_attr device_attr;
	struct ibv_port_attr port_attr;
	int iges;
	struct ibv_gid_entry ige[MAX_GID];
	struct hash *ru_hash;
	struct fifo resolve_queue;		/* List of send buffers with unresolved addresses */
	struct hash *ep;			/* Hash of all endpoints reachable here */
	struct hash *ip_to_ep;			/* Hash based on IP address */
} i2r[NR_INTERFACES];

/*
 * Information provided by RDMA subsystem for how
 * to send a stream to an endpoint that
 * maybe multicast or unicast.
 */
struct ah_info {
	struct ibv_ah *ah;	/* Endpoint Identification */
	uint32_t remote_qpn;	/* Address on the Endpoint */
	uint32_t remote_qkey;
};

/*
 * A Unicastconnection to a certain port and host with
 * a list of pending I/O items and an rdma channel
 */

enum uc_state { UC_NONE, UC_ADDR_REQ, UC_ROUTE_REQ, UC_CONN_REQ, UC_CONNECTED, UC_ERROR };

struct rdma_unicast {
	struct i2r_interface *i;
	enum uc_state state;
	struct sockaddr_in sin;		/* Target address */
	struct rdma_channel *c;		/* Channel for resolution and I/O */
	struct fifo pending;		/* Buffers waiting on resolution to complete */
	struct ah_info ai;		/* If ai.ah != NULL then the address info is valid */
};

static inline void st(struct rdma_channel *c, enum stats s)
{
	c->stats[s]++;
}

/* Forwards */
static void add_event(unsigned long time_in_ms, void (*callback));
static struct rdma_unicast *new_rdma_unicast(struct i2r_interface *i, struct sockaddr_in *sin);
static void register_callback(void (*callback)(void *), int fd, void *private);
static void handle_receive_packet(void *private);

static receive_callback receive_main, receive_multicast, receive_raw, receive_ud;

static inline struct rdma_cm_id *id(enum interfaces i)
{
	return i2r[i].multicast->id;
}

/* Check the RDMA device if it fits what was specified on the command line and store it if it matches */
static int check_rdma_device(enum interfaces i, int port, char *name,
	       struct ibv_context *c, struct ibv_port_attr *a, struct ibv_device_attr *d)
{
	char *s;
	int p = 1;
	const char *rdmadev = ibv_get_device_name(c->device);

	if (i2r[i].context)
		/* Already found a match */
		return 0;

	if (!name)
		/* No command line option, take the first port/device */
		goto success;

	if (strncmp(name, rdmadev, strlen(rdmadev)))
		return 0;

	/* Port / device specified */
	s = strchr(name, ':');
	if (s) {
		/* Portnumber follows device name */
		p = atoi(s + 1);

		if (port != p)
			return 0;
	}

	s = strchr(name, '/');
	if (s && i == INFINIBAND) {
		/* IP device name follows */
		char *q = s + 1;

		while (isdigit(*q) || isalpha(*q))
			 q++;

		memcpy(i2r[INFINIBAND].if_name, s + 1, q - s - 1);
	}

success:
	if (a->active_mtu == IBV_MTU_4096)
		i2r[i].mtu = 4096;
	else if (a->active_mtu == IBV_MTU_2048)
		i2r[i].mtu = 2048;
	else if (a->active_mtu == IBV_MTU_1024) 	/* Needed for rxe support */
		i2r[i].mtu = 1024;
	else
		/* Other MTUs are not supported */
		return 0;

	i2r[i].context = c;
	i2r[i].port = port;
	i2r[i].port_attr = *a;
	i2r[i].device_attr = *d;
	return 1;
}

/* Scan through available RDMA devices in order to locate the devices for bridging */
static int find_rdma_devices(void)
{
	int nr;
	int i;
	struct ibv_device **list;

	list = ibv_get_device_list(&nr);

	if (nr <= 0) {
		logg(LOG_CRIT, "No RDMA devices present.\n");
		return 1;
	}

	for (i = 0; i < nr; i++) {
		struct ibv_device *d = list[i];
		struct ibv_context *c;
		struct ibv_device_attr dattr;
		int found = 0;
		int port;

		if (d->node_type != IBV_NODE_CA)
			continue;

		if (d->transport_type != IBV_TRANSPORT_IB)
			continue;

		c = ibv_open_device(d);
		if (!c) {
			logg(LOG_CRIT, "Cannot open device %s\n", ibv_get_device_name(d));
			return 1;
		}

		if (ibv_query_device(c, &dattr)) {
			logg(LOG_CRIT, "Cannot query device %s\n", ibv_get_device_name(d));
			return 1;
		}

		for (port = 1; port <= dattr.phys_port_cnt; port++) {
			struct ibv_port_attr attr;

			if (ibv_query_port(c, port, &attr)) {
				logg(LOG_CRIT, "Cannot query port %s:%d\n", ibv_get_device_name(d), port);
				return 1;
			}

			if (attr.link_layer == IBV_LINK_LAYER_INFINIBAND) {
				if (check_rdma_device(INFINIBAND, port, ib_name, c, &attr, &dattr) &&
					(!i2r[ROCE].mtu || i2r[ROCE].mtu == i2r[INFINIBAND].mtu))
					found = 1;

			} else if (attr.link_layer == IBV_LINK_LAYER_ETHERNET) {
				if (check_rdma_device(ROCE, port, roce_name, c, &attr, &dattr) &&
					(!i2r[INFINIBAND].mtu || i2r[ROCE].mtu == i2r[INFINIBAND].mtu))
					found = 1;
			}
		}

		if (!found)
			ibv_close_device(c);
	}


	ibv_free_device_list(list);


	if (!i2r[ROCE].context) {

		if (roce_name && roce_name[0] == '-')
			/* Disabled on the command line */
			bridging = false;
		else {
			if (roce_name) {
				logg(LOG_CRIT, "ROCE device %s not found\n", roce_name);
				return 1;
			}
			/* There is no ROCE device so we cannot bridge */
			bridging = false;
		}
	}

	if (!i2r[INFINIBAND].context) {

		if ((ib_name && ib_name[0] == '-') && bridging)
			/* Disabled on the command line */
			bridging = false;
		else {
			if (ib_name)
				/* User specd IB device */
				logg(LOG_CRIT, "Infiniband device %s not found.\n", ib_name);
			else {
				if (!bridging) {
					logg(LOG_CRIT, "No RDMA Devices available.\n");
					return 1;
				}
				/* We only have a ROCE device but we cannot bridge */
				bridging = false;
			}
		}
	}
	return 0;
}

/*
 * Multicast Handling
 */
#define MAX_MC 500

static unsigned nr_mc;
static unsigned active_mc;	/* MC groups actively briding */

enum mc_status { MC_OFF, MC_JOINING, MC_JOINED, MC_ERROR, NR_MC_STATUS };

const char *mc_text[NR_MC_STATUS] = { "Inactive", "Joining", "Joined", "Error" };

/* A multicast group.
 * ah_info points to multicast address and QP number in use
 * for the stream. There are no "ports" unless they are
 * embedded in the GID (like done by CLLM).
 */
static struct mc {
	struct in_addr addr;
	enum mc_status status[2];
	bool sendonly[2];
	bool beacon;
	struct ah_info ai[2];
	struct sockaddr *sa[2];
	struct mgid_signature *mgid_mode;
	const char *text;
} mcs[MAX_MC];

struct hash *mc_hash;

static struct mc *hash_lookup_mc(struct in_addr addr)
{
	unsigned a = ntohl(addr.s_addr) | 0xe0000000; /* Infiniband may strip top 4 bits so provide them */
	struct in_addr x = {
		.s_addr = htonl(a)
	};

	return hash_find(mc_hash, &x);
}

static int hash_add_mc(struct mc *m)
{
	if (hash_find(mc_hash, &m->addr))
		return -EEXIST;

	hash_add(mc_hash, m);
	return 0;
}

static struct mgid_signature *find_mgid_mode(char *p)
{
	struct mgid_signature *g;

	for(g = mgid_signatures; g < mgid_signatures + nr_mgid_signatures; g++)
		if (strcasecmp(p, g->id) == 0)
			break;

	if (g >= mgid_signatures + nr_mgid_signatures) {
		fprintf(stderr, "Not a valid mgid mode %s\n", p);
		return NULL;
	}
	return g;
}

/*
 * Parse an address with port number [:xxx] and/or mgid format [/YYYY]
 */
static struct sockaddr_in *parse_addr(const char *arg, int port,
	struct mgid_signature **p_mgid_mode, bool mc_only)
{
	struct addrinfo *res;
	char *service;
	const struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP
	};
	struct sockaddr_in *si;
	char *p;
	int ret;
	struct mgid_signature *mgid;
	struct in_addr addr;
	char *a = strdupa(arg);

	service = strchr(a, ':');

	if (service) {

		*service++ = 0;
		p = service;

	} else {
		char *s = alloca(10);

		snprintf(s, 10, "%d", port);
		service = s;
		p = a;
	}

	p = strchr(p, '/');
	if (p) {
		*p++ = 0;
		mgid = find_mgid_mode(p);

		if (!mgid)
			return NULL;
	} else
		mgid = mgid_mode;

	ret = getaddrinfo(a, service, &hints, &res);
	if (ret) {
		fprintf(stderr, "getaddrinfo() failed (%s) - invalid IP address.\n", gai_strerror(ret));
		return NULL;
	}

	si = malloc(sizeof(struct sockaddr_in));
	memcpy(si, res->ai_addr, sizeof(struct sockaddr_in));
	freeaddrinfo(res);

	addr = si->sin_addr;
	if (mc_only && !IN_MULTICAST(ntohl(addr.s_addr))) {
		fprintf(stderr, "Not a multicast address (%s)\n", arg);
		return NULL;
	}

	*p_mgid_mode = mgid;
	return si;
}

/* Setup the addreses for ROCE and INFINIBAND based on a ipaddr:port spec */
static void setup_mc_addrs(struct mc *m, struct sockaddr_in *si)
{
	m->sa[ROCE] = (struct sockaddr  *)si;
	m->sa[INFINIBAND] = m->sa[ROCE];

	if (m->mgid_mode->signature) {
		/*
		 * MGID is build according to according to RFC 4391 Section 4
		 * by taking 28 bits and putting them into the mgid
		 *
		 * But then CLLM and others include the full 32 bit...
		 * Deal with this crappy situation.
		 */
		struct sockaddr_ib *saib	= calloc(1, sizeof(struct sockaddr_ib));
		unsigned short *mgid_header	= (unsigned short *)saib->sib_addr.sib_raw;
		unsigned short *mgid_signature	= (unsigned short *)(saib->sib_addr.sib_raw + 2);
		unsigned short *mgid_pkey	= (unsigned short *)(saib->sib_addr.sib_raw + 4);
		unsigned short *mgid_port	= (unsigned short *)(saib->sib_addr.sib_raw + 10);
		unsigned int *mgid_ipv4		= (unsigned int *)(saib->sib_addr.sib_raw + 12);
		unsigned int multicast = ntohl(m->addr.s_addr);
		struct mgid_signature *mg = m->mgid_mode;

		saib->sib_family = AF_IB,
		saib->sib_sid = si->sin_port;

		*mgid_header = htons(0xff15);
		*mgid_signature = htons(mg->signature);

		if (mg->pkey)
			/* WTF? Where do we get the pkey from ? */
			*mgid_pkey = 0xFFFF;

		if (mg->port)
			*mgid_port = si->sin_port;

		if (!mg->full_ipv4)
			/* Strip to 28 bits according to RFC */
			multicast &= 0x0fffffff;

		*mgid_ipv4 = htonl(multicast);

		m->sa[INFINIBAND] = (struct sockaddr *)saib;
	}
}

/* Multicast group specifications on the command line */
static int new_mc_addr(char *arg,
	bool sendonly_infiniband,
	bool sendonly_roce)
{
	struct sockaddr_in *si;
	struct mc *m = mcs + nr_mc;
	int ret;

	if (nr_mc == MAX_MC) {
		fprintf(stderr, "Too many multicast groups\n");
		return 1;
	}

	m->sendonly[INFINIBAND] = sendonly_infiniband;
	m->sendonly[ROCE] = sendonly_roce;
	m->text = strdup(arg);

	si = parse_addr(arg, default_mc_port, &m->mgid_mode, true);
	if (!si)
		return 1;

	m->addr = si->sin_addr;
	ret = hash_add_mc(m);
	if (ret) {
		fprintf(stderr, "Duplicate multicast address (%s)\n", arg);
		goto out;
	}

	setup_mc_addrs(m, si);
	nr_mc++;
	ret = 0;

out:
	return ret;
}

static int _join_mc(struct in_addr addr, struct sockaddr *sa,
				unsigned port,enum interfaces i,
				bool sendonly, void *private)
{
	struct rdma_cm_join_mc_attr_ex mc_attr = {
		.comp_mask = RDMA_CM_JOIN_MC_ATTR_ADDRESS | RDMA_CM_JOIN_MC_ATTR_JOIN_FLAGS,
		.join_flags = sendonly ? RDMA_MC_JOIN_FLAG_SENDONLY_FULLMEMBER
                                       : RDMA_MC_JOIN_FLAG_FULLMEMBER,
		.addr = sa
	};
	int ret;

	ret = rdma_join_multicast_ex(id(i), &mc_attr, private);

	if (ret) {
		logg(LOG_ERR, "Failed to create join request %s:%d on %s. Error %s\n",
			inet_ntoa(addr), port,
			interfaces_text[i],
			errname());
		return 1;
	}
	logg(LOG_NOTICE, "Join Request %sMC group %s:%d on %s.\n",
		sendonly ? "Sendonly " : "",
		inet_ntoa(addr), port,
		interfaces_text[i]);
	st(i2r[i].multicast, join_requests);
	return 0;
}

static int _leave_mc(struct in_addr addr,struct sockaddr *si, enum interfaces i)
{
	int ret;

	ret = rdma_leave_multicast(id(i), si);
	if (ret) {
		perror("Failure to leave");
		return 1;
	}
	logg(LOG_NOTICE, "Leaving MC group %s on %s .\n",
		inet_ntoa(addr),
		interfaces_text[i]);
	st(i2r[i].multicast, leave_requests);
	return 0;
}

static int leave_mc(enum interfaces i)
{
	int j;
	int ret;

	for (j = 0; j < nr_mc; j++) {
		struct mc *m = mcs + j;

		ret = _leave_mc(m->addr, m->sa[i], i);
		if (ret)
			return 1;
	}
	return 0;
}

/*
 * Manage freelist using simple single linked list with the pointer
 * to the next free element at the beginning of the free buffer
 */

static unsigned nr_buffers = 100000;
static bool huge = false;

#define BUFFER_SIZE 8192
#define META_SIZE 1024
#define DATA_SIZE (BUFFER_SIZE - META_SIZE)
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
			struct rdma_channel *c;	/* Which Channels does this buffer belong to */
			struct ibv_wc *w;	/* Work Completion struct */
			struct endpoint *source_ep;
			struct in_addr addr;

			bool ether_valid;	/* Ethernet header valid */
			bool ip_valid;		/* IP header valid */
			bool udp_valid;		/* Valid UDP header */
			bool grh_valid;		/* Valid GRH header */
			bool imm_valid;		/* unsigned imm is valid */
			bool ip_csum_ok;	/* Hardware check if IP CSUM was ok */

			uint8_t *cur;		/* Current position in the buffer */
			uint8_t *end;		/* Pointer to the last byte in the packet + 1 */
			unsigned imm;		/* Immediate data from the WC */

			/* Structs pulled out of the frame */
			struct immdt immdt;	/* BTH subheader */
			struct ibv_grh grh;
			struct ether_header e;
			struct iphdr ip;
			struct udphdr udp;
			struct pgm_header pgm;	/* RFC3208 header */
			struct umad_hdr umad;
		};
		uint8_t meta[META_SIZE];
	};
};

static void pull(struct buf *buf, void *dest, unsigned length)
{
	memcpy(dest, buf->cur, length);
	buf->cur += length;
}

#define PULL(__BUF, __VAR) pull(__BUF, &(__VAR), sizeof(__VAR))

static void beacon_received(struct buf *buf);

static int send_buf(struct buf *buf, struct rdma_unicast *ra);

static struct buf *buffers;

static struct buf *nextbuffer;	/* Pointer to next available RDMA buffer */

static void free_buffer(struct buf *buf)
{
#ifdef DEBUG
	memset(buf->raw, 0, DATA_SIZE);
#endif
	buf->free = true;
	buf->next = nextbuffer;
	nextbuffer = buf;
}

/* Remove all buffers related to a channel */
static void clear_channel_bufs(struct rdma_channel *c)
{
	struct buf *buf;

	for (buf = buffers; buf < buffers + nr_buffers; buf++) {

		if (!buf->free && buf->c == c)
			free_buffer(buf);
	}
}

static void init_buf(void)
{
	int i;
	unsigned flags;

	if (sizeof(struct buf) != BUFFER_SIZE) {
		logg(LOG_CRIT, "struct buf is not 8k as required\n");
		abort();
	}

	flags = MAP_PRIVATE | MAP_ANONYMOUS;
	if (huge)
		flags |= MAP_HUGETLB;

	buffers = mmap(0, nr_buffers * BUFFER_SIZE, PROT_READ|PROT_WRITE, flags, -1, 0);
	if (!buffers) {
		logg(LOG_CRIT, "Cannot allocate %d KB of memory required for %d buffers. Error %s\n",
				nr_buffers * (BUFFER_SIZE / 1024), nr_buffers, errname());
		abort();
	}

	/*
	 * Free in reverse so that we have a linked list
	 * starting at the first element which points to
	 * the second and so on.
	 */
	for (i = nr_buffers; i > 0; i--)
		free_buffer(&buffers[i-1]);
}

static struct buf *alloc_buffer(struct rdma_channel *c)
{
	struct buf *buf = nextbuffer;

	if (buf) {
		nextbuffer = buf->next;
		buf->free = false;
	}
	buf->c = c;

#ifdef DEBUG
	buf->next = NULL;

	for(uint8_t *q = buf->raw; q < buf->raw + DATA_SIZE; q++)
		if (*q)
			abort();
#endif
	return buf;
}

static char hexbyte(unsigned x)
{
	if (x < 10)
		return '0' + x;

	return x - 10 + 'a';
}

static char *__hexbytes(char *b, uint8_t *q, unsigned len, char separator)
{
	unsigned i;
	char *p = b;

	for(i = 0; i < len; i++) {
		unsigned n = *q++;
		*p++ = hexbyte( n >> 4 );
		*p++ = hexbyte( n & 0xf);
		if (i < len - 1)
			*p++ = separator;
		else
			*p++ = 0;
	}
	return b;
}

static char *hexbytes(uint8_t *q, unsigned len, char separator)
{
	static char b[1000];

	if (3* len >= sizeof(b)) {
		logg(LOG_NOTICE, "hexbytes: string length constrained\n");
		len = sizeof(b) / 3;
	}
	return __hexbytes(b, q, len, separator);
}

static char *_hexbytes(uint8_t *q, unsigned len)
{
	return hexbytes(q, len, ' ');
}

static char *payload_dump(uint8_t *p)
{
	return _hexbytes(p, 48);
}

#if 0
static char *w_str(struct ibv_wc *w)
{
	static char buf[200];

	sprintf(buf, "WC(PKEY_INDEX=%d SLID=%d SL=%d DLID_PATH=%d SRC_QP=%d QP_NUM=%d)",
			w->pkey_index, w->slid, w->sl, w->dlid_path_bits, w->src_qp, w->qp_num);
	return buf;
}

static char *global_r_str(struct ibv_global_route *g)
{
	char xbuf[INET6_ADDRSTRLEN];
	static char buf[200];

	sprintf(buf, "GlobalRoute(flow=%u SGIDINDEX=%u hop_limit=%u TrClass=%x  DGID:%s)",
			ntohl(g->flow_label), g->sgid_index, g->hop_limit, g->traffic_class,
			inet_ntop(AF_INET6, &g->dgid, xbuf, INET6_ADDRSTRLEN));
	return buf;
}

#endif
static char *grh_str(struct ibv_grh *g)
{
        struct iphdr *i = (void *)g + 20;
        char xbuf[INET6_ADDRSTRLEN];
        char xbuf2[INET6_ADDRSTRLEN];
        char hbuf1[30];
        char hbuf2[30];
        struct in_addr saddr, daddr;
        static char buf[200];

        saddr.s_addr = i->saddr;
        daddr.s_addr = i->daddr;

        strcpy(hbuf1, inet_ntoa(saddr));
        strcpy(hbuf2, inet_ntoa(daddr));

        sprintf(buf, "GRH(flow=%u Len=%u next_hdr=%u hop_limit=%u SGID=%s DGID:%s SourceIP=%s DestIP=%s)",
                        ntohl(g->version_tclass_flow), ntohs(g->paylen), g->next_hdr, g->hop_limit,
                        inet_ntop(AF_INET6, &g->sgid, xbuf2, INET6_ADDRSTRLEN),
                        inet_ntop(AF_INET6, &g->dgid, xbuf, INET6_ADDRSTRLEN),
                        hbuf1, hbuf2);
	return buf;
}

/* Dump GRH and the beginning of the packet */
static void dump_buf_grh(struct buf *buf)
{
	char xbuf[INET6_ADDRSTRLEN];
	char xbuf2[INET6_ADDRSTRLEN];

	logg(LOG_NOTICE, "Unicast GRH flow=%u Len=%u next_hdr=%u hop_limit=%u SGID=%s DGID:%s Packet=%s\n",
			ntohl(buf->grh.version_tclass_flow), ntohs(buf->grh.paylen), buf->grh.next_hdr, buf->grh.hop_limit,
			inet_ntop(AF_INET6, &buf->grh.sgid, xbuf2, INET6_ADDRSTRLEN),
			inet_ntop(AF_INET6, &buf->grh.dgid, xbuf, INET6_ADDRSTRLEN),
			payload_dump(buf->cur));
}

static char *pgm_dump(struct pgm_header *p)
{
	static char buf[250];

	snprintf(buf, sizeof(buf), "PGM SPORT=%d DPORT=%d PGM-Type=%x Opt=%x Checksum=%x GSI=%s TSDU=%d\n",
			p->pgm_sport, p->pgm_dport, p->pgm_type, p->pgm_options, p->pgm_checksum,
			_hexbytes(p->pgm_gsi, 6), p->pgm_tsdu_length);
	return buf;
}

/*
 * Handling of RDMA work requests
 */
static int post_receive(struct rdma_channel *c, int limit)
{
	struct ibv_recv_wr recv_wr, *recv_failure;
	struct ibv_sge sge;
	int ret = 0;

	if (!nextbuffer)
		return -ENOMEM;

	if (c->active_receive_buffers >= limit)
		return 0;

	recv_wr.next = NULL;
	recv_wr.sg_list = &sge;
	recv_wr.num_sge = 1;

	sge.length = DATA_SIZE;
	sge.lkey = c->mr->lkey;

	while (c->active_receive_buffers < limit) {

		struct buf *buf = alloc_buffer(c);

		if (!buf) {
			logg(LOG_NOTICE, "No free buffers left\n");
			ret = -ENOMEM;
			break;
		}

		/* Use the buffer address for the completion handler */
		recv_wr.wr_id = (uint64_t)buf;
		sge.addr = (uint64_t)buf->raw;
		ret = ibv_post_recv(c->qp, &recv_wr, &recv_failure);
		if (ret) {
			free_buffer(buf);
			logg(LOG_WARNING, "ibv_post_recv failed: %s\n", errname());
			break;
                }
		c->active_receive_buffers++;
	}
	return ret;
}

static int post_receive_buffers(struct i2r_interface *i)
{
	int ret = 0;

	if (!nextbuffer)
		return -EAGAIN;

	ret = post_receive(i->multicast, i->multicast->nr_cq / 2);
	if (ret)
		goto out;

	if (i->raw && i->raw->type == channel_raw)
		ret = post_receive(i->raw, 100);

	if (ret)
		goto out;

	if (i->ud)
		ret = post_receive(i->ud, 100);

	if (i->qp1)
		ret = post_receive(i->qp1, 100);

out:
	return ret;
}


static void channel_destroy(struct rdma_channel *c)
{
	if (!c)
		return;

	if (c->type == channel_rdmacm) {

		if (c->qp)
			rdma_destroy_qp(c->id);

		if (c->cq)
			ibv_destroy_cq(c->cq);

		ibv_dereg_mr(c->mr);
		if (c->pd)
			ibv_dealloc_pd(c->pd);

		rdma_destroy_id(c->id);
	} else
	if (c->type != channel_packet)	{
		ibv_destroy_qp(c->qp);

		if (c->cq)
			ibv_destroy_cq(c->cq);

	}
	clear_channel_bufs(c);
	free(c);
}

#ifdef HAVE_MSTFLINT
static void shutdown_sniffer(int arg) {
	struct i2r_interface *i = i2r + INFINIBAND;

	if (clear_ib_sniffer(i->port, i->raw->qp))
		logg(LOG_ERR, "Failed to switch off sniffer mode on %s\n", i->raw->text);
	else
		logg(LOG_NOTICE, "ABORT handler cleared the sniffer mode on Infiniband\n");
}
#endif

static void qp_destroy(struct i2r_interface *i)
{
#ifdef HAVE_MSTFLINT
	if (i == i2r + INFINIBAND && i->raw && i->raw->type == channel_raw) {
		if (clear_ib_sniffer(i->port, i->raw->qp))
			logg(LOG_ERR, "Failed to switch off sniffer mode on %s\n", i->raw->text);
	}
#endif

	channel_destroy(i->multicast);
	i->multicast = NULL;

	channel_destroy(i->raw);
	i->raw = NULL;

	channel_destroy(i->ud);
	i->ud = NULL;

	channel_destroy(i->qp1);
	i->qp1 = NULL;
}

/* Retrieve Kernel Stack info about the interface */
static void get_if_info(struct i2r_interface *i)
{
	int fh = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	struct ifreq ifr;
	const char *reason = "socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)";

	if (fh < 0)
		goto err;

	/*
	 * Work around the quirk of ifindex always being zero for
	 * INFINIBAND interfaces. Just assume its ib0.
	 */
	if (!i->ifindex && i - i2r == INFINIBAND) {

		if (!i->if_name[0]) {

			logg(LOG_WARNING, "Assuming ib0 is the IP device name for %s\n",
			     ibv_get_device_name(i->context->device));
			strcpy(i->if_name, "ib0");
		}

		memcpy(ifr.ifr_name, i->if_name, IFNAMSIZ);

		/* Find if_index */
		reason = "ioctl SIOCGIFINDEX";
		if (ioctl(fh, SIOCGIFINDEX, &ifr) < 0)
			goto err;

		i->ifindex = ifr.ifr_ifindex;

	} else {

		ifr.ifr_ifindex = i->ifindex;

		reason= "ioctl SIOGCIFNAME";
		if (ioctl(fh, SIOCGIFNAME, &ifr) < 0)
			goto err;

		memcpy(i->if_name, ifr.ifr_name, IFNAMSIZ);
	}

	reason="ioctl SIOCGIFADDR";
	if (ioctl(fh, SIOCGIFADDR, &ifr) < 0)
		goto err;

	memcpy(&i->if_addr, &ifr.ifr_addr, sizeof(struct sockaddr_in));

	ioctl(fh, SIOCGIFNETMASK, &ifr);
	memcpy(&i->if_netmask, &ifr.ifr_netmask, sizeof(struct sockaddr_in));
	ioctl(fh, SIOCGIFHWADDR, &ifr);
	memcpy(&i->if_mac, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	goto out;

err:
	logg(LOG_CRIT, "Cannot determine IP interface setup for %s %s : %s\n",
		     ibv_get_device_name(i->context->device), reason, errname());

	abort();

out:
	close(fh);
}

static void start_channel(struct rdma_channel *c)
{
	if (c->type == channel_rdmacm) {
		/* kick off if necessary */
	} else {
		int ret;
		bool send = c->type == channel_ud;

		c->attr.qp_state = IBV_QPS_RTR;
		/* Only Ethernet can send on a raw socket */
		ret = ibv_modify_qp(c->qp, &c->attr, IBV_QP_STATE);
		if (ret)
			logg(LOG_CRIT, "ibv_modify_qp: Error when moving %s to RTR state. %s\n", c->text, errname());

		if (send) {
			c->attr.qp_state = IBV_QPS_RTS;
			ret = ibv_modify_qp(c->qp, &c->attr,
				       c->type == channel_ud ? (IBV_QP_STATE | IBV_QP_SQ_PSN) : IBV_QP_STATE);

			if (ret)
				logg(LOG_CRIT, "ibv_modify_qp: Error when moving %s to RTS state. %s\n", c->text, errname());

		}
		logg(LOG_NOTICE, "QP %s moved to state %s\n", c->text,  send ? "RTS/RTR" : "RTR" );
	}
}

static struct rdma_channel *new_rdma_channel(struct i2r_interface *i, receive_callback receive, enum channel_type type)
{
	struct rdma_channel *c = calloc(1, sizeof(struct rdma_channel));

	c->i = i;
	c->type = type;
	c->receive = receive;

	return c;
}

static const char *make_ifname(struct i2r_interface *i, const char *x)
{
	char *p;

	p = malloc(strlen(i->text) + strlen(x) + 1);
	strcpy(p, i->text);
	strcat(p, x);
	return p;
}

static struct rdma_channel *create_rdma_id(struct i2r_interface *i, struct sockaddr *sa)
{
	struct rdma_channel *c = new_rdma_channel(i, receive_multicast, channel_rdmacm);
	int ret;


	c->text = make_ifname(i, "-multicast");

	c->bindaddr = sa;
	ret = rdma_create_id(i->rdma_events, &c->id, c, RDMA_PS_UDP);
	if (ret) {
		logg(LOG_CRIT, "Failed to allocate RDMA CM ID for %s failed (%s).\n",
			c->text, errname());
		return NULL;
	}

	ret = rdma_bind_addr(c->id, c->bindaddr);
	if (ret) {
		logg(LOG_CRIT, "Failed to bind %s interface. Error %s\n",
			c->text, errname());
		return NULL;
	}
	return c;
}

static int allocate_rdmacm_qp(struct rdma_channel *c, unsigned nr_cq, bool multicast)
{
	struct ibv_qp_init_attr_ex init_qp_attr_ex;
	int ret;

	/*
	 * Must alloc pd for each rdma_cm_id due to limitation in rdma_create_qp
	 * There a multiple struct ibv_context *s around . Need to use the right one
	 * since rdma_create_qp validates the alloc pd ibv_context pointer.
	 */
	c->pd = ibv_alloc_pd(c->id->verbs);
	if (!c->pd) {
		logg(LOG_CRIT, "ibv_alloc_pd failed for %s.\n",
			c->text);
		return 1;
	}

	/*
	 * Must alloate comp_events channel using the context created by rdmacm
	 * otherwise ibv_create_cq will fail.
	 */
	c->comp_events = ibv_create_comp_channel(c->id->verbs);
	if (!c->comp_events) {
		logg(LOG_CRIT, "ibv_create_comp_channel failed for %s : %s.\n",
			c->text, errname());
		abort();
	}

	c->nr_cq = nr_cq;
	c->cq = ibv_create_cq(c->id->verbs, nr_cq, c, c->comp_events, 0);
	if (!c->cq) {
		logg(LOG_CRIT, "ibv_create_cq failed for %s : %s nr_cq=%d.\n",
			c->text, errname(), nr_cq);
		return 1;
	}

	memset(&init_qp_attr_ex, 0, sizeof(init_qp_attr_ex));
	init_qp_attr_ex.cap.max_send_wr = nr_cq;
	init_qp_attr_ex.cap.max_recv_wr = nr_cq;
	init_qp_attr_ex.cap.max_send_sge = 1;	/* Highly sensitive settings that can cause -EINVAL if too large (10 f.e.) */
	init_qp_attr_ex.cap.max_recv_sge = 1;
	init_qp_attr_ex.cap.max_inline_data = MAX_INLINE_DATA;
	init_qp_attr_ex.qp_context = c;
	init_qp_attr_ex.sq_sig_all = 0;
	init_qp_attr_ex.qp_type = IBV_QPT_UD;
	init_qp_attr_ex.send_cq = c->cq;
	init_qp_attr_ex.recv_cq = c->cq;

	init_qp_attr_ex.comp_mask = IBV_QP_INIT_ATTR_CREATE_FLAGS|IBV_QP_INIT_ATTR_PD;
	init_qp_attr_ex.pd = c->pd;

	if (multicast && loopback_blocking)
		init_qp_attr_ex.create_flags = IBV_QP_CREATE_BLOCK_SELF_MCAST_LB;

	ret = rdma_create_qp_ex(c->id, &init_qp_attr_ex);

	if (ret && errno == ENOTSUP && loopback_blocking) {
		logg(LOG_WARNING, "QP create: MC loopback blocking failed. Retrying without\n");
		init_qp_attr_ex.create_flags = 0;
		ret = rdma_create_qp_ex(c->id, &init_qp_attr_ex);
	}

	if (ret) {
		logg(LOG_CRIT, "rdma_create_qp_ex failed for %s. Error %s. #CQ=%d\n",
				c->text, errname(), nr_cq);
		return 1;
	}

	/* Copy QP to convenient location that is shared by all types of channels */
	c->qp = c->id->qp;
	c->mr = ibv_reg_mr(c->pd, buffers, nr_buffers * sizeof(struct buf), IBV_ACCESS_LOCAL_WRITE);
	if (!c->mr) {
		logg(LOG_CRIT, "ibv_reg_mr failed for %s:%s.\n", c->text, errname());
		return 1;
	}
	return 0;
}

/* Not using rdmacm so this is easier on the callbacks */
static struct rdma_channel *create_channel(struct i2r_interface *i, uint32_t qkey,
		int port, unsigned nr_cq, const char *text, int qp_type, enum channel_type type)
{
	struct rdma_channel *c = new_rdma_channel(i,
		       type == channel_raw ? receive_raw : receive_ud, type);
	int ret;
	struct ibv_qp_init_attr_ex init_qp_attr_ex;

	c->i = i;
	c->text = make_ifname(i, text);
	c->mr = i->mr;
	c->comp_events = i->comp_events;
	c->pd = i->pd;

	c->nr_cq = nr_cq;
	c->cq = ibv_create_cq(i->context, nr_cq, c, i->comp_events, 0);
	if (!c->cq) {
		logg(LOG_CRIT, "ibv_create_cq failed for %s.\n",
			c->text);
		return NULL;
	}

	memset(&init_qp_attr_ex, 0, sizeof(init_qp_attr_ex));
	init_qp_attr_ex.cap.max_send_wr = nr_cq;
	init_qp_attr_ex.cap.max_recv_wr = nr_cq;
	init_qp_attr_ex.cap.max_send_sge = 1;	/* Highly sensitive settings that can cause -EINVAL if too large (10 f.e.) */
	init_qp_attr_ex.cap.max_recv_sge = 1;
	init_qp_attr_ex.cap.max_inline_data = MAX_INLINE_DATA;
	init_qp_attr_ex.qp_context = c;
	init_qp_attr_ex.sq_sig_all = 0;
	init_qp_attr_ex.qp_type = qp_type,
	init_qp_attr_ex.send_cq = c->cq;
	init_qp_attr_ex.recv_cq = c->cq;

	init_qp_attr_ex.comp_mask = IBV_QP_INIT_ATTR_CREATE_FLAGS|IBV_QP_INIT_ATTR_PD;
	init_qp_attr_ex.pd = i->pd;
	init_qp_attr_ex.create_flags = 0;

	c->qp = ibv_create_qp_ex(i->context, &init_qp_attr_ex);
	if (!c->qp) {
		logg(LOG_CRIT, "ibv_create_qp_ex failed for %s. Error %s. Port=%d #CQ=%d\n",
				c->text, errname(), port, nr_cq);
		free(c);
		return NULL;
	}

	c->attr.port_num = port;
	c->attr.qp_state = IBV_QPS_INIT;
	c->attr.pkey_index = 0;
	c->attr.qkey = qkey;

//	c->attr.qkey = 0x12345;		/* Default QKEY from ibdump source code */

	ret = ibv_modify_qp(c->qp, &c->attr,
		       (i == i2r + ROCE && type == channel_raw) ?
				(IBV_QP_STATE | IBV_QP_PORT) :
				( IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_QKEY)
	);

	if (ret) {
		logg(LOG_CRIT, "ibv_modify_qp: Error when moving %s to Init state. %s\n", c->text, errname());
		ibv_destroy_qp(c->qp);
		ibv_destroy_cq(c->cq);
		free(c);
		return NULL;
	}

#ifdef HAVE_MSTFLINT
	if (c->i == i2r + INFINIBAND && type == channel_raw) {
		if (set_ib_sniffer(ibv_get_device_name(c->i->context->device), c->i->port, c->qp)) {
			logg(LOG_ERR, "Failure to set sniffer mode on %s\n", c->text);
			ibv_destroy_qp(c->qp);
			ibv_destroy_cq(c->cq);
			free(c);
			return NULL;
		}
		/* Install abort handler so that we can be sure that the capture mode is switched off */
		signal(SIGABRT, &shutdown_sniffer);
	}
#endif
	return c;
}

static struct rdma_channel *create_ud_channel(struct i2r_interface *i, int port, unsigned nr_cq, uint32_t qkey)
{
	return create_channel(i, qkey, port, nr_cq, "-ud", IBV_QPT_UD, channel_ud);
}

static struct rdma_channel *create_packet_socket(struct i2r_interface *i, int port)
{
	struct rdma_channel *c;
	int fh;
	struct sockaddr_ll ll  = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = port,
		.sll_hatype = ARPHRD_ETHER,
		.sll_pkttype = PACKET_BROADCAST | PACKET_HOST | PACKET_OTHERHOST,
		.sll_halen = sizeof(struct in_addr),
	};

	if (i == i2r + INFINIBAND) {
		logg(LOG_ERR, "Packet Sockets do not work right on Infiniband");
		return NULL;
	}

	fh = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (fh < 0) {
		logg(LOG_ERR, "Raw Socker creation failed for %s:%s\n", i->text, errname());
		return NULL;
	}

	if (bind(fh, (struct sockaddr *)&ll, sizeof(struct sockaddr_ll))) {
		logg(LOG_ERR, "Cannot bind raw socket for %s:%s\n", i->text, errname());
		return NULL;
	}

	c = new_rdma_channel(i, receive_raw, channel_packet);
	c->i = i;
	c->text = make_ifname(i, "-packet");
	c->type = channel_packet;
	c->fh = fh;
	register_callback(handle_receive_packet, fh, c);
	return c;
}

static struct rdma_channel *create_raw_channel(struct i2r_interface *i, int port, unsigned nr_cq)
{
	struct rdma_channel *c = NULL;

	if (!packet_socket) {
		c = create_channel(i, RDMA_UDP_QKEY, port, nr_cq, "-raw", i == i2r + ROCE  ? IBV_QPT_RAW_PACKET : IBV_QPT_UD, channel_raw);

		if (!c)
			logg(LOG_WARNING, "Falling back to raw socket on %s to monitor traffic\n", i->text);
	}

	if (!c)
		c = create_packet_socket(i, i->ifindex);

	return c;
}

static void setup_interface(enum interfaces in)
{
	struct i2r_interface *i = i2r + in;
	struct ibv_gid_entry *e;
	char buf[INET6_ADDRSTRLEN];
	struct sockaddr_in *sin;

	if (in == INFINIBAND)
		i->maclen = 20;
	else
		i->maclen = 6;

	if (!i->context)
		return;

	i->text = interfaces_text[in];

	/* Determine the GID */
	i->iges = ibv_query_gid_table(i->context, i->ige, MAX_GID, 0);

	if (i->iges <= 0) {
		logg(LOG_CRIT, "Error %s. Failed to obtain GID table for %s\n",
			errname(), i->text);
		abort();
	}

	/* Find the correct gid entry */
	for (e = i->ige; e < i->ige + i->iges; e++) {

		if (e->port_num != i->port)
			continue;

		if (in == INFINIBAND && e->gid_type == IBV_GID_TYPE_IB)
			break;

		if (in == ROCE && e->gid_type == IBV_GID_TYPE_ROCE_V2 &&
				e->gid.global.subnet_prefix == 0)
			break;
	}

	if (e >= i->ige + i->iges) {
		logg(LOG_CRIT, "Failed to find GIDs in GID table for %s\n",
			i->text);
		abort();
	}

	/* Copy our connection info from GID table */
	i->gid = e->gid;
	i->gid_index = e->gid_index;
	i->ifindex = e->ndev_ifindex;

	/* Get more info about the IP network attached to the RDMA device */
	get_if_info(i);

	/* Create RDMA interface setup */
	i->rdma_events = rdma_create_event_channel();
	if (!i->rdma_events) {
		logg(LOG_CRIT, "rdma_create_event_channel() for %s failed (%s).\n",
			i->text, errname());
		abort();
	}

	sin = calloc(1, sizeof(struct sockaddr_in));
	sin->sin_family = AF_INET;
	sin->sin_addr = i->if_addr.sin_addr;
	sin->sin_port = htons(default_port);

	i->multicast = create_rdma_id(i, (struct sockaddr *)sin);
	i->ru_hash = hash_create(offsetof(struct rdma_unicast, sin), sizeof(struct sockaddr_in));

	if (!i->multicast)
		abort();

	if (allocate_rdmacm_qp(i->multicast, 1000, true))
		abort();

	i->pd = ibv_alloc_pd(i->context);
	if (!i->pd) {
		logg(LOG_CRIT, "ibv_alloc_pd failed for %s.\n", i->text);
		abort();
	}

	i->comp_events = ibv_create_comp_channel(i->context);
	if (!i->comp_events) {
		logg(LOG_CRIT, "ibv_create_comp_channel failed for %s : %s.\n",
					i->text, errname());
		abort();
	}

	i->mr = ibv_reg_mr(i->pd, buffers, nr_buffers * sizeof(struct buf), IBV_ACCESS_LOCAL_WRITE);
	if (!i->mr) {
		logg(LOG_CRIT, "ibv_reg_mr failed for %s.\n", i->text);
		abort();
	}

	if (unicast) {
		i->ud = create_ud_channel(i, i->port, 100, RDMA_UDP_QKEY);
		i->qp1 = create_ud_channel(i, i->port, 1, IB_DEFAULT_QP1_QKEY);
		i->raw = create_raw_channel(i, i->port, 100);
		i->ip_to_ep = hash_create(offsetof(struct endpoint, addr), sizeof(struct in_addr));
		if (i == i2r + INFINIBAND)
			i->ep = hash_create(offsetof(struct endpoint, lid), sizeof(uint16_t));
		else
			i->ep = i->ip_to_ep;;
	}

	logg(LOG_NOTICE, "%s interface %s/%s(%d) port %d GID=%s/%d IPv4=%s:%d CQs=%u/%u/%u MTU=%u.\n",
		i->text,
		ibv_get_device_name(i->context->device),
		i->if_name, i->ifindex,
		i->port,
		inet_ntop(AF_INET6, e->gid.raw, buf, INET6_ADDRSTRLEN),i->gid_index,
		inet_ntoa(i->if_addr.sin_addr), default_port,
		i->multicast ? i->multicast->nr_cq: 0,
		i->ud ? i->ud->nr_cq : 0,
		i->raw ? i->raw->nr_cq : 0,
		i->mtu
	);
}

static void shutdown_ib(void)
{
	if (!i2r[INFINIBAND].context)
		return;

	leave_mc(INFINIBAND);

	/* Shutdown Interface */
	qp_destroy(i2r + INFINIBAND);
}

static void shutdown_roce(void)
{
	if (!i2r[ROCE].context)
		return;

	leave_mc(ROCE);

	/* Shutdown Interface */
	qp_destroy(i2r + ROCE);
}

/*
 * Join MC groups. This is called from the event loop every second
 * as long as there are unjoined groups
 */
static void join_processing(void)
{
	int i;
	enum interfaces in;
	int mcs_per_call = 0;

	for (i = 0; i < nr_mc; i++) {
		struct mc *m = mcs + i;
		unsigned port = ntohs(((struct sockaddr_in *)(m->sa[ROCE]))->sin_port);

		if (m->status[ROCE] == MC_JOINED && m->status[INFINIBAND] == MC_JOINED)
			continue;

		for(in = 0; in < 2; in++)
			if (i2r[in].context) {
				switch(m->status[in]) {

				case MC_OFF:
					if (_join_mc(m->addr, m->sa[in], port, in, m->sendonly[in], m) == 0)
						m->status[in] = MC_JOINING;
					break;

				case MC_ERROR:

					_leave_mc(m->addr, m->sa[in], in);
					m->status[in] = MC_OFF;
					logg(LOG_WARNING, "Left Multicast group %s on %s due to MC_ERROR\n",
						m->text, interfaces_text[in]);
					break;

				case MC_JOINED:
					break;

				default:
					logg(LOG_ERR, "Bad MC status %d MC %s on %s\n",
					       m->status[in], m->text, interfaces_text[in]);
					break;
			}
		}

		mcs_per_call++;

		if (mcs_per_call > 10)
			break;

	}
}

static void resolve_start(struct rdma_unicast *);

static void zap_channel(struct rdma_unicast *ru)
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
static void resolve_end(struct rdma_unicast *ru)
{
	struct i2r_interface *i = ru->i;

	if (ru != fifo_get(&i->resolve_queue))
		abort();

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
		ru->c = create_rdma_id(i, (struct sockaddr *)sin);
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
static void resolve(struct rdma_unicast *ru)
{
	struct i2r_interface *i = ru->i;

	if (fifo_put(&i->resolve_queue, ru))
		resolve_start(ru);
}

static void handle_rdma_event(void *private)
{
	struct i2r_interface *i = private;
	struct rdma_cm_event *event;
	int ret;
	enum interfaces in = i - i2r;
	struct rdma_unicast *ru = fifo_first(&i->resolve_queue);

	ret = rdma_get_cm_event(i->rdma_events, &event);
	if (ret) {
		logg(LOG_WARNING, "rdma_get_cm_event()_ failed. Error = %s\n", errname());
		return;
	}

	switch(event->event) {
		/* Connection events */
		case RDMA_CM_EVENT_MULTICAST_JOIN:
			{
				struct rdma_ud_param *param = &event->param.ud;
				struct mc *m = (struct mc *)param->private_data;
				struct ah_info *a = m->ai + in;
				char buf[40];

				a->remote_qpn = param->qp_num;
				a->remote_qkey = param->qkey;
				a->ah = ibv_create_ah(i->multicast->pd, &param->ah_attr);
				if (!a->ah) {
					logg(LOG_ERR, "Failed to create AH for Multicast group %s on %s \n",
						m->text, i->text);
					m->status[in] = MC_ERROR;
					break;
				}
				m->status[in] = MC_JOINED;

				/* Things actually work if both multicast groups are joined */
				if (!bridging || m->status[in ^ 1] == MC_JOINED)
					active_mc++;

				logg(LOG_NOTICE, "Joined %s QP=%x QKEY=%x MLID 0x%x sl %u on %s\n",
					inet_ntop(AF_INET6, param->ah_attr.grh.dgid.raw, buf, 40),
					param->qp_num,
					param->qkey,
					param->ah_attr.dlid,
					param->ah_attr.sl,
					i->text);
				st(i->multicast, join_success);
			}
			break;

		case RDMA_CM_EVENT_MULTICAST_ERROR:
			{
				struct rdma_ud_param *param = &event->param.ud;
				struct mc *m = (struct mc *)param->private_data;

				logg(LOG_ERR, "Multicast Error. Group %s on %s\n",
					m->text, i->text);

				/* If already joined then the bridging may no longer work */
				if (!bridging || (m->status[in] == MC_JOINED && m->status[in ^ 1] == MC_JOINED))
				       active_mc--;

				m->status[in] = MC_ERROR;
				st(i->multicast, join_failure);
			}
			break;

		case RDMA_CM_EVENT_ADDR_RESOLVED:
			logg(LOG_NOTICE, "RDMA_CM_EVENT_ADDR_RESOLVED for %s:%d\n",
				inet_ntoa(ru->sin.sin_addr), ntohs(ru->sin.sin_port));

			if (rdma_resolve_route(ru->c->id, 2000) < 0) {

				logg(LOG_ERR, "rdma_resolve_route error %s on %s  %s:%d. Packet dropped.\n",
					errname(), ru->c->text,
					inet_ntoa(ru->sin.sin_addr),
					ntohs(ru->sin.sin_port));
					goto err;
			}
			ru->state = UC_ROUTE_REQ;
			break;

		case RDMA_CM_EVENT_ADDR_ERROR:
			logg(LOG_ERR, "Address resolution error %d on %s  %s:%d. Packet dropped.\n",
				event->status, ru->c->text,
				inet_ntoa(ru->sin.sin_addr),
				ntohs(ru->sin.sin_port));

			goto err;
			break;

		case RDMA_CM_EVENT_ROUTE_RESOLVED:
			{
				struct rdma_conn_param rcp = { };

				logg(LOG_NOTICE, "RDMA_CM_EVENT_ROUTE_RESOLVED for %s:%d\n",
					inet_ntoa(ru->sin.sin_addr), ntohs(ru->sin.sin_port));

				allocate_rdmacm_qp(ru->c, 100, false);

				post_receive(ru->c, 50);
				ibv_req_notify_cq(ru->c->cq, 0);

				if (rdma_connect(ru->c->id, &rcp) < 0) {
					logg(LOG_ERR, "rdma_connecte error %s on %s  %s:%d. Packet dropped.\n",
						errname(), ru->c->text,
						inet_ntoa(ru->sin.sin_addr),
						ntohs(ru->sin.sin_port));

					goto err;
				}
				ru->state = UC_CONN_REQ;
			}
			break;

		case RDMA_CM_EVENT_ROUTE_ERROR:
			logg(LOG_ERR, "Route resolution error %d on %s  %s:%d. Packet dropped.\n",
				event->status, ru->c->text,
				inet_ntoa(ru->sin.sin_addr),
				ntohs(ru->sin.sin_port));

			goto err;
			break;

		case RDMA_CM_EVENT_CONNECT_REQUEST:
			{
				struct rdma_conn_param rcp = { };
				struct rdma_channel *c = new_rdma_channel(i, receive_main, channel_rdmacm);

				logg(LOG_NOTICE, "RDMA_CM_CONNECT_REQUEST id=%p listen_id=%p\n",
					event->id, event->listen_id);

				c->id->context = c;
				c->text = "incoming-ud-qp";

				if (allocate_rdmacm_qp(c, 100, false))
					goto err;

				if (post_receive(c, 50))
					goto err;

				ibv_req_notify_cq(c->cq, 0);

				rcp.qp_num = c->id->qp->qp_num;
				if (rdma_accept(c->id, &rcp)) {
					logg(LOG_ERR, " rdma_accept error %s\n", errname());
					channel_destroy(c);
				}
				/* Create a structure just for tracking buffers */
				c->ru = new_rdma_unicast(i, NULL);
				c->ru->c = c;
				c->ru->state = UC_CONNECTED;

			}
			break;

		case RDMA_CM_EVENT_DISCONNECTED:
			{
				struct rdma_channel *c = event->id->context;

				logg(LOG_NOTICE, "RDMA_CM_EVENT_DISCONNECTED id=%p %s\n",
					event->id, c->text);

				if (c->ru)
					zap_channel(c->ru);
				else
					channel_destroy(c);
			}
			break;

		case RDMA_CM_EVENT_ESTABLISHED:
			{
				struct ah_info *ai = &ru->ai;

				logg(LOG_NOTICE, "RDMA_CM_EVENT_ESTABLISHED for %s:%d\n",
					inet_ntoa(ru->sin.sin_addr), ntohs(ru->sin.sin_port));

				ai->ah = ibv_create_ah(ru->c->pd, &event->param.ud.ah_attr);
				ai->remote_qpn = event->param.ud.qp_num;
				ai->remote_qkey = event->param.ud.qkey;

				rdma_ack_cm_event(event);
				ru->state = UC_CONNECTED;
				resolve_end(ru);
				return;
			}
			break;

		case RDMA_CM_EVENT_UNREACHABLE:
			logg(LOG_ERR, "Unreachable Port error %d on %s  %s:%d. Packet dropped.\n",
				event->status, ru->c->text,
				inet_ntoa(ru->sin.sin_addr),
				ntohs(ru->sin.sin_port));

			goto err;
			break;

		default:
			logg(LOG_NOTICE, "RDMA Event handler:%s status: %d\n",
				rdma_event_str(event->event), event->status);
			break;
	}

	rdma_ack_cm_event(event);
	return;

err:
	rdma_ack_cm_event(event);
	ru->state = UC_ERROR;
	resolve_end(ru);
}

/*
 * Do not use a buffer but simply include data directly into WR.
 * Advantage: No buffer used and therefore faster since no memory
 * fetch has to be done by the RDMA subsystem and no completion
 * event has to be handled.
 *
 * Space in the WR is limited, so it only works for very small packets.
 */
static int send_inline(struct rdma_channel *c, void *addr, unsigned len, struct ah_info *ai, bool imm_used, unsigned imm)
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
		logg(LOG_WARNING, "Failed to post inline send: %s on %s\n", errname(), c->text);
	} else
		if (log_packets > 1)
			logg(LOG_NOTICE, "Inline Send to QPN=%x QKEY=%x %d bytes\n",
				wr.wr.ud.remote_qpn, wr.wr.ud.remote_qkey, len);

	return ret;
}

/*
 * Send data to target using native RDMA structs. This one does not support RDMACM since
 * it uses the shared i->mr and not the c->mr required by rdma cm..
 */
static int send_ud(struct rdma_channel *c, struct buf *buf, struct ibv_ah *ah, unsigned remote_qpn)
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
	wr.opcode = IBV_WR_SEND;
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.wr_id = (uint64_t)buf;

	/* Get addr info  */
	wr.wr.ud.ah = ah;
	wr.wr.ud.remote_qpn = remote_qpn;
	wr.wr.ud.remote_qkey = c->attr.qkey;

	sge.length = buf->end - buf->cur;
	sge.lkey = c->i->mr->lkey;
	sge.addr = (uint64_t)buf->cur;

	if (len <= MAX_INLINE_DATA) {
		wr.send_flags = IBV_SEND_INLINE;
		ret = ibv_post_send(c->qp, &wr, &bad_send_wr);
		free_buffer(buf);
	} else
		ret = ibv_post_send(c->qp, &wr, &bad_send_wr);

	if (ret) {
		errno = - ret;
		logg(LOG_WARNING, "Failed to post send: %s on %s\n", errname(), c->text);
	} else
		if (log_packets > 1)
			logg(LOG_NOTICE, "RDMA Send to QPN=%x QKEY=%x %d bytes\n",
				wr.wr.ud.remote_qpn, wr.wr.ud.remote_qkey, len);

	return ret;
}

/*
 * Send data to a target. No metadata is used in struct buf. However, the buffer must be passed to the wc in order
 * to be able to free up resources when done.
 */
static int send_to(struct rdma_channel *c,
	void *addr, unsigned len, struct ah_info *ai,
	bool imm_used, unsigned imm,
	struct buf *buf)
{
	struct ibv_send_wr wr, *bad_send_wr;
	struct ibv_sge sge;
	int ret;

	if (!ai->ah)
		abort();	/* Send without a route */

	buf->c = c;	/* Change ownership to sending channel */
	buf->w = NULL;

	memset(&wr, 0, sizeof(wr));
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.opcode = imm_used ? IBV_WR_SEND_WITH_IMM: IBV_WR_SEND;
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.wr_id = (uint64_t)buf;
	wr.imm_data = imm;

	/* Get addr info  */
	wr.wr.ud.ah = ai->ah;
	wr.wr.ud.remote_qpn = ai->remote_qpn;
	wr.wr.ud.remote_qkey = ai->remote_qkey;

	sge.length = len;
	sge.lkey = c->mr->lkey;
	sge.addr = (uint64_t)addr;

	ret = ibv_post_send(c->qp, &wr, &bad_send_wr);
	if (ret) {
		errno = - ret;
		logg(LOG_WARNING, "Failed to post send: %s on %s\n", errname(), c->text);
	} else
		if (log_packets > 1)
			logg(LOG_NOTICE, "RDMA Send to QPN=%x QKEY=%x %d bytes\n",
				wr.wr.ud.remote_qpn, wr.wr.ud.remote_qkey, len);

	return ret;
}

/* Send buffer based on state in struct buf. Unicast only */
static int send_buf(struct buf *buf, struct rdma_unicast *ra)
{
	unsigned len = buf->end - buf->cur;
	int ret;

	if (len < MAX_INLINE_DATA) {
		ret = send_inline(ra->c, buf->cur, len, &ra->ai, buf->imm_valid, buf->imm);
		if (ret == 0)
			free_buffer(buf);
	} else
		ret = send_to(ra->c, buf->cur, len, &ra->ai, buf->imm_valid, buf->imm, buf);

	return ret;
}

static struct rdma_unicast *new_rdma_unicast(struct i2r_interface *i, struct sockaddr_in *sin)
{
	struct rdma_unicast *ra = calloc(1, sizeof(struct rdma_unicast));

	ra->i = i;
	memcpy(&ra->sin, sin, sizeof(struct sockaddr_in));
	fifo_init(&ra->pending);
	return ra;
}

static void setup_flow(struct rdma_channel *c)
{
	if (!c)
		return;

	/* Sadly flow steering is not supported on Infiniband */
	if (c->i == i2r + INFINIBAND)
		return;

	if (flow_steering) {
			struct i2r_interface *i = c->i;
			enum interfaces in = i - i2r;
			struct i2r_interface *di = i2r + (in ^ 1);
			unsigned netmask = di->if_netmask.sin_addr.s_addr;
			struct {
				struct ibv_flow_attr attr;
				struct ibv_flow_spec_ipv4 ipv4;
				struct ibv_flow_spec_tcp_udp udp;
			} flattr = {
				{
					0, IBV_FLOW_ATTR_SNIFFER, sizeof(flattr),
					0, 2, i->port, 0
				},
				{
					IBV_FLOW_SPEC_IPV4, sizeof(struct ibv_flow_spec_ipv4),
					{ 0, di->if_addr.sin_addr.s_addr & netmask },
					{ 0, netmask }
				},
				{
					IBV_FLOW_SPEC_UDP, sizeof(struct ibv_flow_spec_tcp_udp),
					{ ROCE_PORT, ROCE_PORT},
					{ 0xffff, 0xffff}
				}
			};

			c->flow = ibv_create_flow(c->qp, &flattr.attr);

	} else {

		struct ibv_flow_attr flattr = {
				0, IBV_FLOW_ATTR_SNIFFER, sizeof(struct ibv_flow_spec),
				0, 0, c->i->port, 0
		};

		c->flow = ibv_create_flow(c->qp, &flattr);
	}

	if (!c->flow)
		logg(LOG_ERR, "Failure to create flow on %s. Errno %s\n", c->text, errname());
}

static void unicast_packet(struct rdma_channel *c, struct buf *buf, struct in_addr dest_addr)
{
	unsigned long l;

	memcpy(&l, buf->cur, sizeof(long));
	if (l == BEACON_SIGNATURE) {
		beacon_received(buf);
		return;
	}

	dump_buf_grh(buf);
}

static void send_buf_to(struct i2r_interface *i, struct buf *buf, struct sockaddr_in *sin);

static void list_endpoints(struct i2r_interface *i)
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
			if (e[j]->lid) {
				if (e[j]->addr.s_addr)
					n += snprintf(buf + n, sizeof(buf) - n, " %s/lid=%d", inet_ntoa(e[j]->addr), e[j]->lid);
				else
					n += snprintf(buf + n, sizeof(buf) - n, " lid=%d", e[j]->lid);
			} else
				n += snprintf(buf + n, sizeof(buf) - n, " %s", inet_ntoa(e[j]->addr));
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
static void add_forward(struct endpoint *source, uint32_t source_qp, struct endpoint *dest, uint32_t dest_qp, uint32_t qkey)
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
 */
static struct forward *find_forward(struct endpoint *source, uint32_t source_qp)
{
	struct forward *f = source->forwards;

	while (f && f->source_qp != source_qp)
		f = f->next;

	return f;
}

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

/*
 * Remove all forwards of an endpoint and indicate how many
 * were removed.
 */
static unsigned int remove_forwards(struct endpoint *source)
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

/*
 * Update the forwarder if the source point changes
 */
static struct forward *update_forward(struct endpoint *source, uint32_t old_source_qp, uint32_t new_source_qp)
{
	struct forward *f = source->forwards;

	while (f && f->source_qp != old_source_qp)
		f = f->next;

	if (!f)
		return NULL;

	f->source_qp = new_source_qp;
	return f;
}

static inline void map_ipv4_addr_to_ipv6(__be32 ipv4, struct in6_addr *ipv6)
{
	ipv6->s6_addr32[0] = 0;
	ipv6->s6_addr32[1] = 0;
	ipv6->s6_addr32[2] = htobe32(0x0000FFFF);
	ipv6->s6_addr32[3] = ipv4;
}

static bool valid_addr(struct i2r_interface *i, struct in_addr addr) {
	unsigned netmask = i->if_netmask.sin_addr.s_addr;

	return ((addr.s_addr & netmask) ==  (i->if_addr.sin_addr.s_addr & netmask));
}

static bool multicast_lid(uint16_t lid) {
	return lid & 0xc000;
}

static bool unicast_lid(uint16_t lid) {
	return lid > 0 && lid < 0xc000;
}

/* Create endpoint from the ah_attr values */
static struct endpoint *at_to_ep(struct i2r_interface *i, struct ibv_ah_attr *at)
{
	struct endpoint *ep;
	struct in_addr addr;
	struct ibv_ah *ah;

	memcpy(&addr, (void *)&at->grh.dgid + 12, sizeof(struct in_addr));

	if (!at->dlid && !addr.s_addr)
		abort();		/* Nothing given that could be resolved */


	if (at->dlid) {
		ep = hash_find(i->ep, &at->dlid);
		if (ep) {
			if (ep->addr.s_addr == 0 && addr.s_addr) {
				/* Ok we can add the IP address that was unknown earlier */
				ep->addr = addr;
				hash_add(i->ip_to_ep, &ep);
			}
			return ep;
		}
	}

	if (addr.s_addr) {
		ep = hash_find(i->ip_to_ep, &addr.s_addr);
		if (ep) {
			if (at->dlid && ep->lid == 0 && unicast_lid(at->dlid)) {
				/* Add earlier unknown LID */
				ep->lid = at->dlid;
				hash_add(i->ep, &ep);
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
			abort();

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

	ah = ibv_create_ah(i->pd, at);
	if (!ah) {
		logg(LOG_ERR, "create_ep: Failed to create Endpoint on %s: %s. IP=%s\n",
				i->text, errname(), inet_ntoa(ep->addr));
		return NULL;
	}

	ep = calloc(1, sizeof(struct endpoint));
	if (!ep)
		abort();

	ep->c = i->ud;
	ep->addr = addr;
	ep->lid = at->dlid;
	ep->ah = ah;

	/* Dont add the address if it has not been determined yet */
	if (addr.s_addr)
		hash_add(i->ip_to_ep, ep);

	/* But IB must have the LID defined so we can at least add that hash */
	if (i2r + INFINIBAND == i)
		hash_add(i->ep, ep);

	return ep;
}



/* Create Endpoint just from the IP address */
static struct endpoint *ip_to_ep(struct i2r_interface *i, struct in_addr addr)
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
static struct endpoint *buf_to_ep(struct buf *buf)
{
	struct i2r_interface *i = buf->c->i;
	struct endpoint *ep = NULL;
	struct rdma_channel *c = buf->c;
	struct ibv_wc *w = buf->w;
	struct in_addr addr = buf->addr;

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

	if (buf->ip_valid) { /* ROCE. This may be called without buf->grh_valid from the raw path */

		if (!addr.s_addr)
			addr.s_addr = buf->ip.saddr;

	} else
        if (i == i2r + INFINIBAND) {	/* Infiniband */

		if (!unicast_lid(w->slid)) {

			/* No source LID */
			logg(LOG_ERR, "Invalid Source LID %x on %s\n", w->slid, c->text);
			free(ep);

			return NULL;
		}
		if (buf->grh_valid) {
			void *position = buf->cur;

			memcpy(&at.grh.dgid, buf->grh.sgid.raw, sizeof(union ibv_gid));

			if (!addr.s_addr && !hash_find(i->ep, &at.dlid)) {

				PULL(buf, buf->pgm);

				if (w->src_qp != 1) {
					/* Direct PGM packet inspection without verification if this is really PGM */
					memcpy(&addr, buf->pgm.pgm_gsi, sizeof(struct in_addr));
					logg(LOG_NOTICE, "Extracted IP address from PGM header: %s %s\n",
						c->text, inet_ntoa(ep->addr));
				} else
					logg(LOG_ERR, "No IP address for QP1 packet on %s\n", c->text);
			}
			buf->cur = position;
		}
	}

	buf->addr.s_addr = 0;

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
static void learn_source_address(struct buf *buf)
{
	if (!unicast)	/* If unicast is not enabled then dont bother to gather addresses */
		return;

	buf->source_ep = buf_to_ep(buf);
}

/*
 * We have an GRH header so the packet has been processed by the RDMA
 * Subsystem and we can take care of it using the RDMA calls
 */
static void receive_multicast(struct buf *buf)
{
	struct mc *m;
	struct rdma_channel *c = buf->c;
	enum interfaces in = c->i - i2r;
	char xbuf[INET6_ADDRSTRLEN];
	struct ib_addr *dgid = (struct ib_addr *)&buf->grh.dgid.raw;
	struct in_addr dest_addr;
	int ret;
	struct pgm_header pgm;

	learn_source_address(buf);

	if (!buf->grh_valid) {
		logg(LOG_WARNING, "No GRH on %s. Packet discarded: %s\n",
			c->text, payload_dump(buf->cur));
		goto invalid_packet;
	}

	if ((buf->ip_valid && !IN_MULTICAST(ntohl(buf->ip.daddr))) || (!buf->ip_valid && buf->grh.dgid.raw[0] !=  0xff)) {
		logg(LOG_WARNING, "Unicast Packet on multicast channel %s: GRH=%s %s\n", c->text, grh_str(&buf->grh), payload_dump(buf->cur));
		goto invalid_packet;
	}

	dest_addr.s_addr = dgid->sib_addr32[3];
	m = hash_lookup_mc(dest_addr);

	if (log_packets > 1) {
		memcpy(&pgm, buf->cur, sizeof(struct pgm_header));
		logg(LOG_NOTICE, "From %s: MC=%s %s\n", c->text, inet_ntoa(dest_addr), pgm_dump(&pgm));
	}

	if (!m) {
		if (log_packets) {
			logg(LOG_WARNING, "Discard Packet: Multicast group %s not found\n",
				inet_ntoa(dest_addr));
			dump_buf_grh(buf);
		}
		goto invalid_packet;
	}

	if (m->sendonly[in]) {

		if (log_packets) {
			logg(LOG_WARNING, "Discard Packet: Received data from Sendonly MC group %s from %s\n",
				m->text, c->text);
			dump_buf_grh(buf);
		}
		goto invalid_packet;
	}

	if (!buf->ip_valid) {
		unsigned char *mgid = buf->grh.dgid.raw;
		unsigned short signature = ntohs(*(unsigned short*)(mgid + 2));

		if (mgid[0] != 0xff) {
			if (log_packets) {
				logg(LOG_WARNING, "Discard Packet: Not multicast. MGID=%s/%s\n",
					inet_ntop(AF_INET6, mgid, xbuf, INET6_ADDRSTRLEN), c->text);
				dump_buf_grh(buf);
			}
			goto invalid_packet;
		}

		if (memcmp(&buf->grh.sgid, &c->i->gid, sizeof(union ibv_gid)) == 0) {

			if (log_packets > 3)
				logg(LOG_WARNING, "Discard Packet: Loopback from this host. MGID=%s/%s\n",
					inet_ntop(AF_INET6, mgid, xbuf, INET6_ADDRSTRLEN), c->text);

			goto invalid_packet;
		}

		if (m->mgid_mode->signature) {
			if (signature == m->mgid_mode->signature) {
//				if (m->mgid_mode->port)
//					port = ntohs(*((unsigned short *)(mgid + 10)));
			} else {
				if (log_packets) {
					logg(LOG_WARNING, "Discard Packet: MGID multicast signature(%x)  mismatch. MGID=%s\n",
							signature,
							inet_ntop(AF_INET6, mgid, xbuf, INET6_ADDRSTRLEN));
					dump_buf_grh(buf);
				}
				goto invalid_packet;
			}
		}

	} else { /* ROCE */
		if (buf->ip.saddr == c->i->if_addr.sin_addr.s_addr) {
			if (log_packets > 3)
				logg(LOG_WARNING, "Discard Packet: Loopback from this host. %s/%s\n",
					inet_ntoa(c->i->if_addr.sin_addr), c->text);
			goto invalid_packet;
		}
	}

	if (m->beacon) {
		beacon_received(buf);
		goto free_out;
	}

	if (!bridging)
		goto free_out;

	ret = send_to(i2r[in ^ 1].multicast, buf->cur, buf->end - buf->cur, m->ai + (in ^ 1), false, 0, buf);

	if (ret)
		goto free_out;

	st(c, packets_bridged);
	return;

invalid_packet:
	st(c, packets_invalid);
free_out:
	free_buffer(buf);
}

/*
 * We have an GRH header so the packet has been processed by the RDMA
 * Subsystem and we can take care of it using the RDMA calls
 */
static void recv_buf_grh(struct rdma_channel *c, struct buf *buf)
{
	enum interfaces in = c->i - i2r;
	struct in_addr dest_addr;

	if (unicast &&
		((in == INFINIBAND && buf->grh.dgid.raw[0] != 0xff) ||
		((in == ROCE && (buf->grh.dgid.raw[13] & 0x1))))) {

		unicast_packet(c, buf, dest_addr);
		return;
	}

	logg(LOG_WARNING, "Multicast packet on Unicast QP %s:%s\n", c->text, payload_dump(buf->cur));

	st(c, packets_invalid);
	free_buffer(buf);
}

/* Figure out what to do with the packet we got */
static void receive_main(struct buf *buf)
{
	struct rdma_channel *c = buf->c;

	if (buf->grh_valid) {
		recv_buf_grh(c, buf);
		return;
	}

	if (log_packets)
		logg(LOG_WARNING, "No GRH on %s. Packet discarded: %s.\n", c->text, payload_dump(buf->cur));

	st(c, packets_invalid);
	free_buffer(buf);
}

/*
 * Simple listener to quickly gather IP/ GID information off the wire
 */
static const char *process_arp(struct i2r_interface *i, struct buf *buf, uint16_t lids[2])
{
	uint8_t mac[20];
	unsigned j;
	struct arphdr arp;

	PULL(buf, arp);
	
	if (ntohs(arp.ar_op) != ARPOP_REPLY)
       		return "-Only ARP replies supported";

	if (arp.ar_pln != sizeof(struct in_addr))
		return "ARP protocol length != 4";

	if (ntohs(arp.ar_hrd) != ARPHRD_ETHER &&
	    ntohs(arp.ar_hrd) != ARPHRD_INFINIBAND)
		return "ARP implementation supports only Ethernet and Infiniband";

	for (j = 0; j < 2; j++, buf->cur += arp.ar_hln + sizeof(struct in_addr)) {
		struct endpoint *ep;

		memcpy(mac, buf->cur, arp.ar_hln);
		memcpy(&buf->addr, buf->cur + arp.ar_hln, sizeof(struct in_addr));

		if (!valid_addr(i, buf->addr)) {
			logg(LOG_NOTICE, "ARP REPLY: Invalid %sIP=%s MAC=%s\n",
				j ? "Dest" : " Source",
			       inet_ntoa(buf->addr),
				hexbytes(mac, arp.ar_hln,':'));
			continue;
		}

		ep = hash_find(i->ep, i2r + ROCE == i ? (void *)&buf->addr : (void *)(lids + j));
		if (ep) {
			if (!ep->addr.s_addr) {

				ep->addr = buf->addr;
				hash_add(i->ip_to_ep, ep);

			} else if(ep->addr.s_addr != buf->addr.s_addr)

				return "IP address for MAC changed!";

			continue;
		}

		buf->w->slid = lids[j];
		ep = buf_to_ep(buf);
		if (!ep)
			return "Cannot create Endpoint";

		logg(LOG_NOTICE, "ARP: Created Endpoint IP=%s LID=%x\n", inet_ntoa(ep->addr), ep->lid);
		memcpy(&ep->gid, mac, arp.ar_hln);
		if (lids[j]) {
			if (ep->lid) {
				hash_del(i->ep, ep);
				ep->lid = lids[j];
				hash_add(i->ep, ep);
			}
		}
	}
	return NULL;
}

/* SIDR handshake with gateway involved. This is based on the assumption
 * that we are dealing with rdmacm data streams where an
 * rdma_listen/accept/rdma_disconnect and rdma_connect/rdma_disconnect
 * handshake is occurring. That means a QP on one side will only send
 * and receive to one QP on the other side via the connection that
 * has been established. Therefore it is possible to determine the
 * target QP# on one side for incoming datagrams by recognizing the
 * QP # on the other side.
 *
 * The connection is established by a successel SIDR REQ/REP
 * We insert our own QP# into this sequence.
 *
 * DREQs/DREP are not send by RDMA CM for ID channels and therefore
 * also not handled by the logic here. If another request is
 * made with overlapping ports then the old ones are simply erased.
 *
 * Lets say a SIDR REQ is used to establish a connection from
 * Source IP(SIP)/SQP to the Destination IP(DIP)/DQP:
 *
 * SIDR REQ is send on the QP for MADs:
 *
 * SIDR REQ SIP(O-QP):DIP(1) -> GW -> SIDR REQ SIP(GW-QP1):DIP(1)
 *
 * The gateway here has used its own QP# to resend the request
 * to the Gateway. The Destination does not see the MAD request
 * arriving from QP1.
 *
 * The gateway will remove existing translations if O-QP is in use
 * The forward for O-QP will be established so that the gatway
 * can recognize the SIDR-RESP
 *
 * Now the Response from the destination will be
 *
 * SIDR RESP DIP(1):SIP(GW-QP1) -> GW- > SIDR RESP DIP(GW-QP2):SIP(O-QP)
 *
 * Gatway will establish forwards for both QP# removing prior existing ones
 * and also the provisional O-QP entry.
 *
 * Data may now be flowing in both directions using
 *
 * DATA SIP(SQP) -> DIP(GW-QP1) -> GW -> DATA SIP(GW_QP2) -> DIP(DQP)
 *
 * State needed by GW
 *
 * 1. Resolution from IP -> ibv_ah and GID->LID to ibv_ah
 *
 * 2. Map from IP/QPN ib <-> IP/QPN roce
 *
 * SIP:DIP SQP:DQP SQP:DQP
 *
 * On the IB side we need to ID the sender by LID also but generally prefer GIDs
 *
 * Need the SM to do routing paths and GID->LID etc conversions.
 */


/* Could not find a struct anywhere so this may do the trick */
struct sidr_req {
	uint32_t	request_id;
	uint16_t	pkey;
	uint16_t	reserved;
	uint64_t	service_id;
} __packed;

struct sidr_rep {
	uint32_t request_id;
	uint8_t	status;
	uint8_t ail;
	uint16_t vendorid1;
	uint32_t qpn;
	uint64_t service_id;
	uint32_t q_key;
	char add_info[72];
	char private[136];
} __packed;

struct sidr_state {
	uint32_t request_id;            /* Should be generated locally in the future */
	struct endpoint *source;
	struct endpoint *dest;
};

static struct hash *sidrs;

static void sidr_state_init(void)
{
	if (sizeof(struct umad_hdr) != 3 * 8)
		abort();

	if (sizeof(struct sidr_req) != 2 * 8)
		abort();

	if (sizeof(struct sidr_rep) != 3* 8 + 72 + 136)
		abort();

	sidrs = hash_create(offsetof(struct sidr_state, request_id), sizeof(uint32_t));
}


static const char *sidr_req(struct buf *buf, void *mad_pos, unsigned short dlid)
{
	struct i2r_interface *source_i = buf->c->i;

	enum interfaces in = source_i - i2r;
	struct i2r_interface *dest_i = i2r + (in ^ 1);
	struct endpoint *source_ep = buf->source_ep;
	struct in_addr dest;
	struct endpoint *dest_ep = NULL;
	struct ibv_wc *w = buf->w;
	char source_str[40];
	struct sidr_req sr;

	PULL(buf, sr);
	buf->c = dest_i->ud;

	/* Establish Destination */
	if (buf->ip_valid) {	/* ROCE */

		dest.s_addr = buf->ip.daddr;

	} else { /* Infiniband */
		struct in_addr source;
		struct cma_hdr ch; 

		PULL(buf, ch);

		if (ch.cma_version != CMA_VERSION)
			return "SIDR REQ: Unsupported CMA version";

		if (cma_get_ip_ver(&ch) != 4)
			return "SIDR REQ: Only IPv4 private data supported";


		source.s_addr = ch.src_addr.ip4.addr;
		dest.s_addr = ch.dst_addr.ip4.addr;

		if (dest.s_addr && !valid_addr(dest_i, dest))
			return "SIDR REQ: Invalid Destination address";

		if (valid_addr(source_i, source) && source_ep->addr.s_addr == 0) {
			struct endpoint *sep = hash_find(source_i->ip_to_ep, &source);

			if (sep) {
				char b[40];
				struct endpoint *tep;

				strcpy(b, inet_ntoa(source_ep->addr));

				logg(LOG_NOTICE, "SIDR_REQ: Two endpoints claim the same IP : EP1(%p by ip)= (%s,%x) EP2(from receive_raw) = (%p %s,%x)\n",
					sep, inet_ntoa(sep->addr), sep->lid, source_ep, b, source_ep->lid);

				tep = hash_find(source_i->ep, &source_ep->lid);
				if (tep)
					logg(LOG_NOTICE, "SIDR REQ lookup by lid = %p %s, %x\n", tep, tep ? inet_ntoa(tep->addr) : "--", tep ? tep->lid : 0);
				else
					logg(LOG_NOTICE, "SIDR REQ nothing found when looking up by lid =%x\n", source_ep->lid); 

				if (source_ep->forwards) {
					logg(LOG_WARNING, "SIDR REQ: Removing forwards frp, EP %p lid=%u\n", source_ep, source_ep->lid);
					remove_forwards(source_ep);
				}
				logg(LOG_WARNING, "SIDR REQ: Removing EP=%p\n", source_ep);
				hash_del(source_i->ep, source_ep);
				free(source_ep);
				buf->source_ep = sep;

			} else {
			
				source_ep->addr = source;
				hash_add(source_i->ip_to_ep, source_ep);
				logg(LOG_NOTICE, "SIDR REQ: Private data supplied IP address %s to Endpoint at LID %x\n",
					inet_ntoa(source), w->slid);
			}
		}
	}

	strcpy(source_str, inet_ntoa(source_ep->addr));
	dest_ep = ip_to_ep(dest_i, dest);
	if (!dest_ep)
		return "Cannot forward SIDR REP since the address is unknown";

	if (bridging) {
		struct sidr_state *ss = malloc(sizeof(struct sidr_state));

		buf->cur = mad_pos;
		buf->end = mad_pos + 256;
		send_ud(dest_i->qp1, buf, dest_ep->ah, 1);
		logg(LOG_NOTICE, "SIDR REQ forwarded from %s to %s\n",
			source_str, inet_ntoa(dest_ep->addr));

		/* Save state */
		ss->request_id = sr.request_id;
		ss->source = source_ep;
		ss->dest = dest_ep;
		if (hash_find(sidrs, &ss->request_id)) {
			logg(LOG_ERR, "SIDR_REQ: Removed earlier pending request\n");
			hash_del(sidrs, ss);
		}
		hash_add(sidrs, ss);
		
	} else
		free_buffer(buf);

	return NULL;
}

/*
 * SDIR REP needs to do the whole work since we do not keep state
 * elsewhere
 *
 * SDIR REQ was forwarded to EP. Now the SDIR_REP is coming back
 *
 * The Dest is the EP that sends us the response.
 *
 * We need to determine the true source (tm) and replace
 * the QPN so that future packets arriving from
 * the EP will be properly forwarded and also the other
 * way around.
 */
static const char * sidr_rep(struct buf *buf, void *mad_pos)
{
	struct sidr_rep sr;
	struct sidr_state *ss;

	PULL(buf, sr);

	if (sr.status)
		return "SIDR_REP: Request rejected";

	ss = hash_find(sidrs, &sr.request_id);
	if (!ss)
		return "SDIR_REP: Cannot find outstanding SIDR_REQ";

	hash_del(sidrs, ss);

	if (ss->dest != buf->source_ep)
		abort();

	/*
	 * We do not know the source QPN. So just accept anything that
 	 * has the right destination. Not good
 	 */
	add_forward(ss->source, 0, ss->dest, sr.qpn, RDMA_UDP_QKEY);

	sr.qpn = ss->source->c->i->ud->qp->qp_num;

	logg(LOG_NOTICE, "SIDR_REP: %s method=%s status=%s qpn=%x attr_id=%s attr_mod=%x SID=%x RID=%x Q_KEY=%x QPN=%x Status=%x\n",
		buf->c->text, umad_method_str(buf->umad.mgmt_class, buf->umad.method),
		umad_common_mad_status_str(buf->umad.status), ntohl(sr.qpn), 
		umad_attribute_str(buf->umad.mgmt_class, buf->umad.attr_id), ntohl(buf->umad.attr_mod),
		ntohl(sr.service_id), ntohl(sr.request_id), ntohs(sr.q_key), ntohl(sr.qpn), sr.status);

	if (bridging) {
		char source_str[40];

		strcpy(source_str, inet_ntoa(ss->source->addr));

		buf->cur = buf->raw;
		buf->end = buf->cur + 256;
		memcpy(buf->raw, &sr, sizeof(sr));

		send_ud(ss->source->c->i->qp1, buf, ss->source->ah, 1);
		logg(LOG_NOTICE, "SIDR REP forwarded from %s to %s\n",
			inet_ntoa(ss->dest->addr), source_str);
	} else
		free_buffer(buf);

	free(ss);
	return NULL;
}

static void receive_raw(struct buf *buf)
{
	struct rdma_channel *c = buf->c;
	struct i2r_interface *i = c->i;
	struct ibv_wc *w = buf->w;
	struct endpoint *ep;
	uint16_t lids[2] = { 0, 0 };
	unsigned short dlid = 0;
	void *mad_pos;
	const char *reason;
	int len = w->byte_len;
	struct bth bth = { };
	struct deth deth;	/* BTH subheader */
	char header[200] = "";

	if (i == i2r + INFINIBAND) {
		__be16 lrh[4];
		struct ib_header *ih = (void *)&lrh;

		PULL(buf, lrh);

		len = ntohs(lrh[2]) *4;
		if (len != w->byte_len) {
			buf->end = buf->raw + len;
		}

		lids[0] = w->slid = ib_get_slid(ih);
		lids[1] = ib_get_dlid(ih);
		w->sl = ib_get_sl(ih);

		if (!unicast_lid(w->slid) || !lids[1]) {
			logg(LOG_NOTICE, "SLID=%x DLID=%x\n", lids[0], lids[1]);
			reason = "Invalid SLID or DLID";
			goto discard;
		}

		if (w->slid == i->port_attr.lid) {
			reason = "Unicast Loopback";
			goto discard;
		}

		buf->addr.s_addr = 0;
		ep = buf_to_ep(buf);

		snprintf(header, sizeof(header), "SLID=%x/%s DLID=%x SL=%d LVer=%d",
			w->slid, inet_ntoa(ep->addr), dlid, w->sl, ib_get_lver(ih));

		if (ib_get_lnh(ih) < 2) {
			reason = "IP v4/v6 packet";
			goto discard;
		}

		if (ib_get_lnh(ih) == 3) {
			char *xbuf = alloca(40);
			char *xbuf2 = alloca(40);

			PULL(buf, buf->grh);
			buf->grh_valid = true;

			snprintf(header + strlen(header), 100-strlen(header), " SGID=%s DGID=%s",
				inet_ntop(AF_INET6, &buf->grh.sgid, xbuf2, INET6_ADDRSTRLEN),
				inet_ntop(AF_INET6, &buf->grh.dgid, xbuf, INET6_ADDRSTRLEN));

			if (ep->gid.global.interface_id == 0) /* No GID yet ? */
				memcpy(&ep->gid, &buf->grh.sgid, sizeof(union ibv_gid));

		}

		if (multicast_lid(dlid)) {
			reason = "-Multicast";
			goto discard;
		}

	} else { /* Ethernet. We expect a ROCE packet */
		unsigned ethertype;
		char source_str[30];
		char dest_str[30];
		struct in_addr source, dest;

		pull(buf, &buf->e, sizeof(struct ether_header));

		ethertype = ntohs(buf->e.ether_type);
		if (ethertype < 0x600) {
			len = ethertype;
			ethertype = ETHERTYPE_IP;
		}

		buf->ether_valid = true;

		if (memcmp(i->if_mac, buf->e.ether_shost, ETH_ALEN) == 0) {

			reason = "-Loopback";
			goto discard;
		}

		buf->end -= 4;		/* Remove Ethernet FCS */

		/* buf->cur .. buf->end is the ethernet payload */
		switch (ethertype) {

		case ETHERTYPE_ROCE:

			reason = "Roce V1 not supported";
			goto discard;

		case ETHERTYPE_ARP:

			reason = process_arp(i, buf, lids);

			if (!reason)
				goto packet_done;

			goto discard;

		case ETHERTYPE_IP:

			PULL(buf, buf->ip);
			buf->ip_valid = true;
			len = ntohs(buf->ip.tot_len);

			source.s_addr = buf->ip.saddr;
			dest.s_addr = buf->ip.daddr;
			strcpy(source_str, inet_ntoa(source));
			strcpy(dest_str, inet_ntoa(dest));
			snprintf(header, sizeof(header), "%s -> %s",
				source_str, dest_str);

			buf->addr = source;

			if (!valid_addr(i, buf->addr)) {
				reason = "-Invalid source IP";
				goto discard;
			}

			ep = buf_to_ep(buf);

			if (buf->ip.protocol != IPPROTO_UDP) {

				reason = "-Only UDP packets";
				goto discard;

			}

			if (buf->e.ether_dhost[0] & 0x1) {
				reason = "-Multicast on RAW channel";
				goto discard;
			}

			if (!buf->ip_csum_ok)
				logg(LOG_NOTICE, "TCP/UDP CSUM not valid on raw RDMA channel %s\n", c->text);

			PULL(buf, buf->udp);
			buf->udp_valid = true;

			if (ntohs(buf->udp.dest) != ROCE_PORT) {

				reason = "Not the ROCE UDP port";
				goto discard;
			}
			break;
		default:
			reason = "-Not IP traffic";
			goto discard;
		}
	}

	buf->source_ep = ep;


	PULL(buf, bth);
	buf->end -= ICRC_SIZE;

	if (__bth_qpn(&bth) == 0) {
		reason = "Raw channels do not handle QP0 traffic";
		goto discard;
	}

	if (__bth_opcode(&bth) != IB_OPCODE_UD_SEND_ONLY &&
		__bth_opcode(&bth) !=  IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE) {
			reason = "Only UD Sends are supported";
                        goto discard;
        }

	PULL(buf, deth);
	w->src_qp = __deth_sqp(&deth);

	if (__bth_opcode(&bth) == IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE) {
		PULL(buf, buf->immdt);
		buf->imm_valid = true;
		buf->imm = buf->immdt.imm;
	}

	buf->cur += __bth_pad(&bth);

	if (__bth_qpn(&bth) > 2) {
		struct {
			unsigned short type;
			unsigned short reserved;
		} ec_header;

		PULL(buf, ec_header);

		if (ec_header.type == ETHERTYPE_ARP)
			process_arp(i, buf, lids);
		else
			reason = "-Only ARPs when QP > 1";

		if (reason)
			goto discard;

		goto packet_done;
	}

	mad_pos = buf->cur;

	/* Start MAD payload */
	PULL(buf, buf->umad);

	logg(LOG_NOTICE, "QP1 packet %s from %s LID %x LRH_LEN=%u WC_LEN=%u SQP=%x DQP=%x method=%s status=%s attr_id=%s\n", i->text,
		inet_ntoa(ep->addr), ep->lid, len, w->byte_len,
		 w->src_qp, __bth_qpn(&bth),
 		umad_method_str(buf->umad.mgmt_class, buf->umad.method),
		umad_common_mad_status_str(buf->umad.status),
		umad_attribute_str(buf->umad.mgmt_class, buf->umad.attr_id));

	if (buf->umad.mgmt_class != UMAD_CLASS_CM) {
		reason = "-Only CM Class MADs are supported";
		goto discard;
	}

	if (ntohs(buf->umad.attr_id) == UMAD_CM_ATTR_SIDR_REQ) {
		reason = sidr_req(buf, mad_pos, lids[1]);
		if (reason)
			goto discard;
		return;
	}

	if (ntohs(buf->umad.attr_id) == UMAD_CM_ATTR_SIDR_REP) {
		reason = sidr_rep(buf, mad_pos);
		if (reason)
			goto discard;
		return;
	}

	reason = "Only SIDR_REQ";

discard:
	if (reason[0] != '-' || log_packets > 1) 
		logg(LOG_NOTICE, "Discard %s %s: %s Length=%u/prot=%u/pos=%lu\n",
			c->text, reason, header,
			buf->w->byte_len, len, buf->cur - buf->raw);

	st(c, packets_invalid);
packet_done:
	free_buffer(buf);
}

/* Unicast packet reception */
static void receive_ud(struct buf *buf)
{
	struct rdma_channel *c = buf->c;
	const char *reason;
	struct endpoint *e;
	struct forward *f;
	struct ibv_wc *w = buf->w;

	learn_source_address(buf);

	if (!buf->grh_valid)
		/* Even if there is no GRH there is space reserved at the beginning for UD packets */
		buf->cur += 40;

	e = buf->source_ep;
	if (!e) {
		reason = "Cannot find endpoint";
		goto discard;
	}

	f = find_forward(e, w->src_qp);

 	if (!f) {
		/* This is dodgy and dangerous but currently I have
 		 * no better idea. Since we do not know the source
 		 * QPN when processing SIDRS we just let the
 		 * source qpn be zero until we get the first
 		 * package from the endpoint...
 		 * If there are multiple apps running then I guess
 		 * desaster may follow.
 		 */
		f = find_forward(e, 0);
		if (f)
			f->source_qp = w->src_qp;
 	}
 
	if (!f) {
		reason = "No QPN is connected";
		goto discard;
 	}

 	return;
 
discard:
	logg(LOG_NOTICE, "receive_ud:Discard %s %s LEN=%ld\n", c->text, reason, buf->end - buf->cur);
	st(c, packets_invalid);
	free_buffer(buf);
}

static void reset_flags(struct buf *buf)
{
	memset(&buf->ether_valid, 0, (void *)&buf->ip_csum_ok - (void *)&buf->ether_valid);
}

static void handle_comp_event(void *private)
{
	struct ibv_comp_channel *events = private;
	struct rdma_channel *c;
	struct i2r_interface *i;
	struct ibv_cq *cq;
	int cqs;
	struct ibv_wc wc[100];
	int j;

	ibv_get_cq_event(events, &cq, (void **)&c);
	i = c->i;

	ibv_ack_cq_events(cq, 1);
	if (ibv_req_notify_cq(cq, 0)) {
		logg(LOG_CRIT, "ibv_req_notify_cq: Failed\n");
		abort();
	}

	/* Retrieve completion events and process incoming data */
	cqs = ibv_poll_cq(cq, 100, wc);
	if (cqs < 0) {
		logg(LOG_WARNING, "CQ polling failed with: %s on %s\n",
			errname(), c->text);
		goto exit;
	}

	if (cqs == 0)
		goto exit;

	if (cqs > cq_high)
		cq_high = cqs;

	for (j = 0; j < cqs; j++) {
		struct ibv_wc *w = wc + j;
		struct buf *buf = (struct buf *)w->wr_id;

		if (w->status == IBV_WC_SUCCESS && w->opcode == IBV_WC_RECV) {

			c->active_receive_buffers--;
			st(c, packets_received);

			if (c != buf->c) {
				logg(LOG_CRIT, "RDMA Channel mismatch CQ channel/buffer.\n");
				abort();
			}

			buf->cur = buf->raw;
			buf->end = buf->raw + w->byte_len;
			buf->w = w;
			reset_flags(buf);
			if (w->wc_flags & IBV_WC_WITH_IMM) {

				buf->imm = w->imm_data;
				buf->imm_valid = true;

			} else {
				buf->imm = 0;
				buf->imm_valid = false;
			}

			if (w->wc_flags & IBV_WC_GRH) {
				PULL(buf, buf->grh);
				buf->grh_valid = true;
				if (i == i2r + ROCE) {
					/*
					 * In the ROCE ipv4 case the IP header is
					 * at the end of the GRH instead of a
					 * SGID and DGID
					 */
					memcpy(&buf->ip, (void *)buf->cur - 20, 20);
					buf->ip_valid = true;
				}
			} else
				buf->grh_valid = false;

			buf->ip_csum_ok = (w->wc_flags & IBV_WC_IP_CSUM_OK) != 0;

			c->receive(buf);

		} else {
			if (w->status == IBV_WC_SUCCESS && w->opcode == IBV_WC_SEND) {
				/* Completion entry */
				st(c, packets_sent);
				free_buffer(buf);
			} else
				logg(LOG_NOTICE, "Strange CQ Entry %d/%d: Status:%x Opcode:%x Len:%u QP=%x SRC_QP=%x Flags=%x\n",
					j, cqs, w->status, w->opcode, w->byte_len, w->qp_num, w->src_qp, w->wc_flags);

		}
	}

exit:
	/* Since we freed some buffers up we may be able to post more of them */
	post_receive_buffers(i);
}

/* Special handling using raw socket */
static void handle_receive_packet(void *private)
{
	struct rdma_channel *c = private;
	struct ibv_wc w = {};
	unsigned ethertype;
	ssize_t len;
	struct buf *buf = alloc_buffer(c);

	len = recv(c->fh, buf->raw, DATA_SIZE, 0);

	if (len < 0) {
		logg(LOG_ERR, "recv error on %s:%s\n", c->text, errname());
		return;
	}

	if (len < 10) {
		logg(LOG_ERR, "Packet size below minimal %ld\n", len);
		return;
	}
		
	st(c, packets_received);

	w.byte_len = len;
	buf->cur = buf->raw;
	buf->end = buf->raw + w.byte_len;
	buf->w = &w;
	reset_flags(buf);
	PULL(buf, buf->e);

	ethertype = ntohs(buf->e.ether_type);
	if (ethertype < 0x600)
		ethertype = ETHERTYPE_IP;

	if (ethertype == ETHERTYPE_IP) {
		PULL(buf, buf->ip);
		buf->ip_valid = true;

		memcpy((void *)&buf->grh + 20, &buf->ip, 20);
		buf->grh_valid = true;
	}
	buf->ip_csum_ok = true;
	/* Reset scan to the beginning of the raw packet */
	buf->cur = buf->raw;
	c->receive(buf);
}


static void handle_async_event(void *private)
{
	struct i2r_interface *i = private;
	struct ibv_async_event event;

	if (!ibv_get_async_event(i->context, &event))
		logg(LOG_ALERT, "Async event retrieval failed on %s.\n", i->text);
	else
		logg(LOG_ALERT, "Async RDMA EVENT %d on %s\n", event.event_type, i->text);

	/*
	 * Regardless of what the cause is the first approach here
	 * is to simply terminate the program.
	 * We can make exceptions later.
	 */

	terminated = true;

        ibv_ack_async_event(&event);
}

static int status_fd;

static int channel_stats(char *b, struct rdma_channel *c, const char *interface, const char *type)
{
	int n = 0;
	int j;

	n += sprintf(b + n, "\nPacket Statistics for %s(%s):\n", interface, type);

	for(j =0; j < nr_stats; j++)
		if (c->stats[j]) {
			n += sprintf(b + n, "%s=%u\n", stats_text[j], c->stats[j]);
	}
	return n;
}


static void status_write(void)
{
	static char b[10000];
	struct i2r_interface *i;
	int n = 0;
	int free = 0;
	struct buf *buf;
	int fd = status_fd;
	struct mc *m;

	if (update_requested) {

		char name[40];
		time_t t = time(NULL);
		struct tm *tm;

		tm = localtime(&t);

		snprintf(name, 40, "ib2roce-%d%02d%02dT%02d%02d%02d",
				tm->tm_year + 1900, tm->tm_mon +1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec);
		fd = open(name, O_CREAT | O_RDWR,  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	} else
		lseek(fd, SEEK_SET, 0);

	for(buf = buffers; buf < buffers + nr_buffers; buf++)
		if (buf->free)
		       free++;

	n+= sprintf(b + n, "Multicast: Active=%u NR=%u Max=%u\nBuffers: Active=%u Total=%u CQ#High=%u\n\n",
		active_mc, nr_mc, MAX_MC, nr_buffers-free , nr_buffers, cq_high);

	for(m = mcs; m < mcs + nr_mc; m++)

		n += sprintf(n + b, "%s INFINIBAND: %s %s%s ROCE: %s %s\n",
			inet_ntoa(m->addr),
			mc_text[m->status[INFINIBAND]],
			m->sendonly[INFINIBAND] ? "Sendonly " : "",
			m->mgid_mode->id,
			mc_text[m->status[ROCE]],
			m->sendonly[ROCE] ? "Sendonly" : "");

	for(i = i2r; i < i2r + NR_INTERFACES; i++) {

		if (i->multicast)
			n += channel_stats(b + n, i->multicast, i->text, "Multicast");
		if (i->ud)
			n += channel_stats(b + n, i->ud, i->text, "UD");
		if (i->raw)
			n += channel_stats(b + n, i->raw, i->text, "Raw");

	}

	for(i = i2r; i < i2r + NR_INTERFACES; i++)
		if (i->context && i->ep) {
		struct endpoint *e[20];
		char xbuf[30];
		unsigned nr;
		unsigned offset = 0;

		printf("\nEndpoints on %s", i->text);
		while ((nr = hash_get_objects(i->ep, offset, 20, (void **)e))) {
			int j;

			for (j = 0; j < nr; j++) {
				struct endpoint *ep = e[j];
				struct forward *f;

				n += snprintf(b + n, sizeof(buf) - n, "\n%3d. %s", offset + j + 1, inet_ntoa(e[j]->addr));

				if (ep->lid)
					n += snprintf(b + n, sizeof(buf) - n, " LID=%x", ep->lid);

				if (ep->gid.global.interface_id)
					n += snprintf(b + n, sizeof(buf) - n, " GID=%s",
						inet_ntop(AF_INET6, &ep->gid, xbuf, INET6_ADDRSTRLEN));

				for (f = ep->forwards; f; f = f->next) {
					n += snprintf(b + n, sizeof(buf) - n, " Q%d->%sQ%d",
					      f->source_qp, inet_ntoa(f->dest->addr), f->dest_qp);
				}
			}
			offset += 20;
		}
	}

	n += sprintf(n + b, "\n\n\n\n\n\n\n\n");
	write(fd, b, n);

	if (update_requested) {
		close(fd);
		update_requested = false;
	}
	add_event(timestamp() + 60000, status_write);
}

/*
 * Beacon processing
 */
struct beacon_info {
	unsigned long signature;
	char version[10];
	struct in_addr destination;
	struct in_addr infiniband;
	struct in_addr roce;
	unsigned port;
	unsigned nr_mc;
	struct timespec t;
};

struct mc *beacon_mc;		/* == NULL if unicast */
struct sockaddr_in *beacon_sin;

static void timespec_diff(struct timespec *start, struct timespec *stop,
                   struct timespec *result)
{
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        result->tv_sec = stop->tv_sec - start->tv_sec - 1;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
    } else {
        result->tv_sec = stop->tv_sec - start->tv_sec;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }

    return;
}

static void beacon_received(struct buf *buf)
{
	struct beacon_info *b = (struct beacon_info *)buf->cur;
	char ib[40];
	struct timespec diff;
	struct timespec now;

	if (b->signature != BEACON_SIGNATURE) {
		logg(LOG_ERR, "Received non beacon traffic on beacon MC group %s\n", beacon_mc->text);
		return;
	}

	clock_gettime(CLOCK_REALTIME, &now);
	strcpy(ib, inet_ntoa(b->infiniband));
	timespec_diff(&b->t, &now, &diff);

	logg(LOG_NOTICE, "Received Beacon on %s Port %d Version %s IB=%s, ROCE=%s MC groups=%u. Latency %ld ns\n",
		beacon_mc->text, ntohs(b->port), b->version, ib, inet_ntoa(b->roce), b->nr_mc, diff.tv_sec * 1000000000 + diff.tv_nsec);
	free_buffer(buf);
}

/* A mini router follows */
static struct i2r_interface *find_interface(struct sockaddr_in *sin)
{
	struct i2r_interface *i;

	for(i = i2r; i < i2r + NR_INTERFACES; i++)
	    if (i->context) {
		unsigned netmask = i->if_netmask.sin_addr.s_addr;

		if ((sin->sin_addr.s_addr & netmask) ==  (i->if_addr.sin_addr.s_addr & netmask))
			return i;
	}

	return NULL;
}

/* Ship a unicast datagram to an IP address .... */
static void send_buf_to(struct i2r_interface *i, struct buf *buf, struct sockaddr_in *sin)
{
	struct rdma_unicast *ra;
	int ret;

	/* Find address */
	ra = hash_find(i->ru_hash,  sin);
	if (!ra) {
		ra = new_rdma_unicast(i, sin);
		hash_add(i->ru_hash, ra);
	}

	switch (ra->state) {
		case UC_NONE:	/* We need to resolve the address. Queue up the buffer and initiate */
			fifo_put(&ra->pending, buf);
			resolve(ra);
			return;

		case UC_CONNECTED: /* Channel is open. We can send now */
			ret = send_buf(buf, ra);
			if (!ret)
				logg(LOG_ERR, "Failed to send to %s:%d\n",
					inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
			return;

		default:		/* Resolution is in progress. Just queue it up on the address */
			fifo_put(&ra->pending, buf);
			return;

	}
}

static void beacon_send(void)
{
	struct beacon_info b;
	struct buf *buf;

	b.signature = BEACON_SIGNATURE;
	memcpy(b.version, VERSION, 10);
	b.destination = beacon_sin->sin_addr;
	b.port = beacon_sin->sin_port;
	b.infiniband = i2r[INFINIBAND].if_addr.sin_addr;
	b.roce = i2r[ROCE].if_addr.sin_addr;
	b.nr_mc = nr_mc;
	clock_gettime(CLOCK_REALTIME, &b.t);

	if (beacon_mc) {
		int in;

		for(in = 0; in < NR_INTERFACES; in++) {
			struct i2r_interface *i = i2r + in;

			if (i->context && beacon_mc->status[in] == MC_JOINED) {
				if (sizeof(b) > MAX_INLINE_DATA) {
					buf = alloc_buffer(i->multicast);
					memcpy(buf->raw, &b, sizeof(b));
					send_to(i->multicast, buf, sizeof(b), beacon_mc->ai + in, false, 0, buf);
				} else
					send_inline(i->multicast, &b, sizeof(b), beacon_mc->ai + in, false, 0);
			}
		}

	} else {
		struct i2r_interface *i = find_interface(beacon_sin);

		if (!i) {
			logg(LOG_ERR, "Beacon IP %s unreachable\n", inet_ntoa(beacon_sin->sin_addr));
			beacon = false;
			return;
		}
		buf = alloc_buffer(i->multicast);
		memcpy(buf->raw, &b, sizeof(b));

		reset_flags(buf);
		buf->cur = buf->raw;
		buf->end = buf->cur + sizeof(b);

		send_buf_to(i, buf, beacon_sin);

	}
	add_event(timestamp() + 10000, beacon_send);
}

static void beacon_setup(const char *opt_arg)
{
	struct mgid_signature *mgid;
	struct in_addr addr;

	if (!opt_arg)
		opt_arg = "239.1.2.3";

	beacon_mc = NULL;
	beacon_sin = parse_addr(opt_arg, default_mc_port, &mgid, false);
	addr = beacon_sin->sin_addr;
	if (IN_MULTICAST(ntohl(addr.s_addr))) {
		struct mc *m = mcs + nr_mc++;

		memset(m, 0, sizeof(*m));
		m->beacon = true;
		m->text = strdup(opt_arg);
		m->mgid_mode = mgid;
		m->addr = addr;

		setup_mc_addrs(m, beacon_sin);

		if (hash_add_mc(m)) {
			logg(LOG_ERR, "Beacon MC already in use.\n");
			beacon = false;
			free(beacon_sin);
			beacon_sin = NULL;
		} else
			beacon_mc = m;
	}
	add_event(timestamp() + 1000, beacon_send);
}

/* Events are timed according to milliseconds in the current epoch */
struct timed_event {
	unsigned long time;		/* When should it occur */
	void (*callback)(void);		/* function to run */
	struct timed_event *next;	/* The following event */
};

static struct timed_event *next_event;

static void add_event(unsigned long time, void (*callback))
{
	struct timed_event *t;
	struct timed_event *prior = NULL;
	struct timed_event *new_event;

	new_event = calloc(1, sizeof(struct timed_event));
	new_event->time = time;
	new_event->callback = callback;

	for(t = next_event; t && time > t->time; t = t->next)
		prior = t;

	new_event->next = t;

	if (prior)
		prior->next = new_event;
	else
		next_event = new_event;
}

static void check_joins(void)
{
	struct i2r_interface *i;

	/* Maintenance tasks */
	if (nr_mc > active_mc) {
		join_processing();
		add_event(timestamp() + 1000, check_joins);
	} else {
		/*
		 * All active so start listening. This means we no longer
		 * are able to subscribe to Multicast groups
		 */
		for(i = i2r; i < i2r + NR_INTERFACES; i++)
		   if (i->context)	{
			struct rdma_channel *c = i->multicast;

			if (rdma_listen(c->id, 50))
				logg(LOG_ERR, "rdma_listen on %s error %s\n", c->text, errname());

			c->listening = true;
		}
	}
}

static void logging(void)
{
	char buf[100];
	char buf2[150];
	char counts[200];

	unsigned n = 0;
	unsigned interval = 5000;
	const char *events;

	for(struct timed_event *z = next_event; z; z = z->next)
		n += sprintf(buf + n, "%ldms,", z->time - timestamp());

	if (n > 0)
		buf[n -1] = 0;
	else
		buf[0] = 0;

	if (n == 0) {
		events = "No upcoming events";
		interval = 60000;
	} else {
		snprintf(buf2, sizeof(buf2), "Events in %s", buf);
		events = buf2;
	}

	n = 0;
	for(struct i2r_interface *i = i2r; i < i2r + NR_INTERFACES;i++)
      	   if (i->context)	{
		n+= sprintf(counts + n, "%s(MC %d/%d, UD %d/%d, %s %d) ",
			i->text,
			i->multicast->stats[packets_received],
			i->multicast->stats[packets_sent],
			i->ud ? i->ud->stats[packets_received] : 0,
			i->ud ?	i->ud->stats[packets_sent] : 0,
			i->raw ? (i->raw->type == channel_raw ? "RAW" : "PACKET") : "-",
			i->raw ? i->raw->stats[packets_received]: 0);
	}

	logg(LOG_NOTICE, "%s. Groups=%d/%d. Packets=%s\n", events, active_mc, nr_mc, counts);
	add_event(timestamp() + interval, logging);

	list_endpoints(i2r + INFINIBAND);
	list_endpoints(i2r + ROCE);

}

/*
 * Logic to support building a pollfd table for the event loop
 */
#define MAX_POLL_ITEMS 20

unsigned poll_items = 0;

struct pollfd pfd[MAX_POLL_ITEMS];
static void (*poll_callback[MAX_POLL_ITEMS])(void *);
void *poll_private[MAX_POLL_ITEMS];

static void register_callback(void (*callback)(void *), int fd, void *private)
{
	struct pollfd e = { fd, POLLIN, 0};

	if (poll_items == MAX_POLL_ITEMS)
		abort();

	poll_callback[poll_items] = callback;
	pfd[poll_items] = e;
	poll_private[poll_items] = private;
	poll_items++;
}

static void register_poll_events(void)
{
	struct i2r_interface *i;

	for(i = i2r; i < i2r + NR_INTERFACES; i++)
	   if (i->context) {

		register_callback(handle_rdma_event, i->rdma_events->fd, i);
		register_callback(handle_comp_event, i->multicast->comp_events->fd, i->multicast->comp_events);
		register_callback(handle_async_event, i->context->async_fd, i);

		if (i->raw || i->ud)	/* They share the interface comp_events notifier */
			register_callback(handle_comp_event, i->comp_events->fd, i->comp_events);

	}

}

static void setup_timed_events(void)
{
	unsigned long t;

	t = timestamp();

	if (background)
		add_event(t + 30000, status_write);

	add_event(t + 1000, logging);
	add_event(t + 100, check_joins);
}

static void arm_channels(void)
{
	struct i2r_interface *i;

	for(i = i2r; i < i2r + NR_INTERFACES; i++)
	   if (i->context) {
		/* Receive Buffers */
		post_receive_buffers(i);
		/* And request notifications if something happens */
		if (i->multicast) {
			ibv_req_notify_cq(i->multicast->cq, 0);
		}

		if (i->raw && i->raw->type == channel_raw) {
			start_channel(i->raw);
			ibv_req_notify_cq(i->raw->cq, 0);

			setup_flow(i->raw);
		}

		if (i->ud) {
			start_channel(i->ud);
			ibv_req_notify_cq(i->ud->cq, 0);
		}

		if (i->qp1) {
			start_channel(i->qp1);
			ibv_req_notify_cq(i->qp1->cq, 0);
		}
	}

}


static int event_loop(void)
{
	unsigned timeout;
	int events = 0;
	int waitms;
	unsigned long t;

	arm_channels();
	setup_timed_events();
loop:
	timeout = 10000;

	if (next_event) {
		/* Time till next event */
		waitms = next_event->time - timestamp();

		/*
		 * If we come from processing poll events then
		 * give priority to more poll event processing
		 */
		if ((waitms <= 0 && events == 0) || waitms < -10) {
			/* Time is up for an event */
			struct timed_event *te;

			te = next_event;
			next_event = next_event->next;
			te->callback();
			free(te);
			goto loop;
		}
		if (waitms < 1)
			/* There is a pending event but we are processing
			 * poll events.
			 * Make sure we check for more and come back soon
			 * after processing additional poll actions
			*/
			timeout = 3;
		else
			/* Maximum timeout is 10 seconds */
			if (waitms < 10000)
				timeout = waitms;
	}

	events = poll(pfd, poll_items, timeout);

	if (terminated)
		goto out;

	if (events < 0) {
		logg(LOG_WARNING, "Poll failed with error=%s\n", errname());
		goto out;
	}

	if (events == 0)
		goto loop;

	for(t = 0; t < poll_items; t++)
		if (pfd[t].revents & POLLIN)
			poll_callback[t](poll_private[t]);

	goto loop;
out:
	return 0;
}

/*
 * Daemon Management functions
 */

static void terminate(int x)
{
	terminated = true;
}


static void update_status(int x)
{
	update_requested = true;
}

static void setup_termination_signals(void)
{
	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);
	signal(SIGHUP, terminate);	/* Future: Reload a potential config file */
}

static void daemonize(void)
{
	pid_t pid;

	pid = fork();

	if (pid < 0)
		exit(EXIT_FAILURE);

	if (pid > 0)
		exit(EXIT_SUCCESS);

	if (setsid() < 0)
		exit(EXIT_FAILURE);

	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	pid = fork();

	if (pid < 0)
		exit(EXIT_FAILURE);

	/* Terminate parent */
	if (pid > 0)
		exit(EXIT_SUCCESS);

	/* Set new file permissions */
	umask(0);

	if (chdir("/var/lib/ib2roce")) {
		perror("chdir");
		exit(EXIT_FAILURE);
	}

	/* Close all open file descriptors */
	int x;
	for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
		close (x);

	openlog ("ib2roce", LOG_PID, LOG_DAEMON);

	signal(SIGUSR1, update_status);
}

static int pid_fd;

static void pid_open(void)
{
	struct flock fl = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0
	};
	int n;
	char buf[10];

	pid_fd = open("ib2roce.pid", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

	if (pid_fd < 0) {
		logg(LOG_CRIT, "Cannot open pidfile. Error %s\n", errname());
		abort();
	}

	if (fcntl(pid_fd, F_SETLK, &fl) < 0) {
		logg(LOG_CRIT, "ib2roce already running.\n");
		abort();
	}

	if (ftruncate(pid_fd, 0) < 0) {
		logg(LOG_CRIT, "Cannot truncate pidfile. Error %s\n", errname());
		abort();
	}

	n = snprintf(buf, sizeof(buf), "%ld", (long) getpid());

	if (write(pid_fd, buf, n) != n) {
		logg(LOG_CRIT, "Cannot write pidfile. Error %s\n", errname());
		abort();
	}
}

static void pid_close(void)
{
	unlink("ib2roce.pid");
	close(pid_fd);
}

struct option opts[] = {
	{ "device", required_argument, NULL, 'd' },
	{ "roce", required_argument, NULL, 'r' },
	{ "multicast", required_argument, NULL, 'm' },
	{ "inbound", required_argument, NULL, 'i' },
	{ "mgid", optional_argument, NULL, 'l' },
	{ "beacon", optional_argument, NULL, 'b' },
	{ "debug", no_argument, NULL, 'x' },
	{ "nobridge", no_argument, NULL, 'n' },
	{ "port", required_argument, NULL, 'p' },
	{ "flow", no_argument, NULL, 'f' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "test", no_argument, NULL, 't' },
	{ "unicast", no_argument, NULL, 'u' },
	{ "config", required_argument, NULL, 'c' },
	{ NULL, 0, NULL, 0 }
};

char *beacon_arg = NULL;

static void exec_opt(int op, char *optarg);

static void readconfig(char *file)
{
	char *line = NULL;
	size_t chars = 0;
	FILE *f = fopen(file, "r");

	if (!f) {
		fprintf(stderr, "Config file %s not found:%s\n", file, errname());
		return;
	}

	while (getline(&line, &chars, f) > 0) {
		char *p = line;
		char *q, *optarg;
		struct option *o;

		while (isspace(*p))
			p++;

		if (!isalpha(*p))
			goto skip;

		q = p;
		while (isalpha(*p))
			p++;

		*p++ = 0;

		optarg = p;
		while (!isspace(*p))
			p++;

		*p = 0;

		for(o = opts; o->name; o++)
			if (strcasecmp(o->name, q) == 0) {
				exec_opt(o->val, optarg);
				goto skip;
			}

		fprintf(stderr, "Unknown option: %s %s\n", q, optarg);
		exit(1);
skip:
		free(line);
		line = NULL;
		chars = 0;
	}
	fclose(f);
}

static void exec_opt(int op, char *optarg)
{
	int ret = 0;
	int n;

	switch (op) {
		case 'c':
			readconfig(optarg);
			break;

		case 'd':
			ib_name = optarg;
			break;

		case 'r':
			roce_name = optarg;
			break;

		case 'm':
			ret = new_mc_addr(optarg, false, false);
			if (ret)
				exit(1);
			break;

		case 'i':
			ret = new_mc_addr(optarg, false, true);
			if (ret)
				exit(1);
			break;

		case 'o':
			ret =  new_mc_addr(optarg, true, false);
			if (ret)
				exit(1);
			break;

		case 'l':
			if (optarg) {
				mgid_mode = find_mgid_mode(optarg);
				if (mgid_mode)
					break;
			}
			printf("List of supported MGID formats via -l<id>\n");
			printf("=================================\n");
			printf(" ID    | Signature | Port in MGID\n");
			printf("-------+-----------+-------------\n");
			for (n = 0; n < nr_mgid_signatures; n++) {
				struct mgid_signature *m = mgid_signatures + n;

				printf("%7s|    0x%04x | %s\n",
					m->id, m->signature, m->port ? "true" : "false");
			}
			exit(1);
			break;

		case 'x':
			debug = true;
			break;

		case 'b':
			beacon = true;
			beacon_arg = optarg;
			break;

		case 'n':
			bridging = false;
			break;

		case 'p':
			default_port = atoi(optarg);
			break;

		case 'u':
			unicast = true;
			break;

		case 'f':
			flow_steering = true;
			break;

		case 'a':
			loopback_blocking = false;
			break;

		case 'y':
			packet_socket = true;
			break;

		case 'v':
			log_packets++;
			break;

		case 't':
			fifo_test();
			hash_test();
			testing = true;
			break;

		default:
			printf("ib2roce " VERSION " Mar 3,2022 (C) 2022 Christoph Lameter <cl@linux.com>\n");
			printf("Usage: ib2roce [<option>] ...\n");
                        printf("-d|--device <if[:portnumber][/<netdev>]	Infiniband interface\n");
                        printf("-r|--roce <if[:portnumber]>		ROCE interface\n");
                        printf("-m|--multicast <multicast address>[:port][/mgidformat] (bidirectional)\n");
                        printf("-i|--inbound <multicast address>	Incoming multicast only (ib traffic in, roce traffic out)\n");
                        printf("-o|--outbound <multicast address>	Outgoing multicast only / sendonly /(ib trafic out, roce traffic in)\n");
			printf("-l|--mgid				List availabe MGID formats for Infiniband\n");
			printf("-l|--mgid <format>			Set default MGID format\n");
			printf("-x|--debug				Do not daemonize, enter debug mode\n");
			printf("-p|--port >number>			Set default port number\n");
			printf("-b|--beacon <multicast address>		Send beacon every second\n");
			printf("-n|--nobridge				Do everything but do not bridge packets\n");
			printf("-u|--unicast		*experimental*	Unicast forwarding support\n");
			printf("-f|--flow		*experimental*	Enable flow steering to do hardware filtering of packets\n");
			printf("-v|--log-packets			Show detailed information about discarded packets\n");
			printf("-c|--config <file>			Read config from file\n");
			printf("-y|--packetsocket			Use Packet Socket instead of RAW QP\n");
			printf("-a|--loopback				Do not request loopback blocking\n");
			exit(1);
	}
}


int main(int argc, char **argv)
{
	int op, ret = 0;

	mc_hash = hash_create(offsetof(struct mc, addr), sizeof(struct in_addr));

	sidr_state_init();

	while ((op = getopt_long(argc, argv, "vtfunb::xl::i:r:m:o:d:p:c:ya",
					opts, NULL)) != -1)
		exec_opt(op, optarg);

	init_buf();

	if (debug || !bridging)
		openlog("ib2roce", LOG_PERROR, LOG_USER);
	else {
		background = true;
		daemonize();
		pid_open();
	}

	setup_termination_signals();

	ret = find_rdma_devices();
	if (ret && !testing)
		return ret;

	syslog (LOG_NOTICE, "Infiniband device = %s:%d, ROCE device = %s:%d. Multicast Groups=%d MGIDs=%s Buffers=%u\n",
			i2r[INFINIBAND].context ? ibv_get_device_name(i2r[INFINIBAND].context->device) : "<disabled>",
			i2r[INFINIBAND].port,
			i2r[ROCE].context ? ibv_get_device_name(i2r[ROCE].context->device) : "<disabled>",
			i2r[ROCE].port,
			nr_mc,
			mgid_mode->id,
			nr_buffers);

	setup_interface(INFINIBAND);
	setup_interface(ROCE);

	if (background)
		status_fd = open("ib2roce-status", O_CREAT | O_RDWR | O_TRUNC,  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (beacon)
		beacon_setup(beacon_arg);

	register_poll_events();

	event_loop();

	if (background)
		close(status_fd);

	shutdown_roce();
	shutdown_ib();

	if (background)
		pid_close();

	syslog (LOG_NOTICE, "Shutdown complete.\n");
	closelog();

	return EXIT_SUCCESS;
}
