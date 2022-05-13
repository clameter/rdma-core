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
#include <threads.h>
#include <numa.h>
#include <stdatomic.h>
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
#include <execinfo.h>
#include "packet.h"
#include "errno.h"
#include "bth_hdr.h"
#include "ib_hdrs.h"
#include "fifo.h"
#include "ring.h"
#include "hash.h"
#include "ibraw.h"
#include "cma-hdr.h"

#define VERSION "2022.0512"

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
static bool raw = false;		/* Use raw channels */
static bool flow_steering = false;	/* Use flow steering to filter packets */
static bool testing = false;		/* Run some tests on startup */
static bool latency = true;		/* Perform Latency tests and provide stats */
static bool packet_socket = false;	/* Do not use RAW QPs, use packet socket instead */
static bool loopback_blocking = true;	/* Ask for loopback blocking on Multicast QPs */
static int drop_packets = 0;		/* Packet dropper */
static int rate = IBV_RATE_10_GBPS;	/* Limit sending rate */
static int rrate = 0;			/* Software delay per message for ROCE */
static int irate = 0;			/* Software delay per message for Infiniband */
static int max_rburst = 10;		/* Dont delay until # of packets for ROCE */
static int max_iburst = 10;		/* Dont delay until # of packets for Infiniband */
static int stat_interval = 10;		/* Interval for statistics */
static int loglevel = LOG_INFO;		/* LOG level for console output */

#define ONE_SECOND (1000000000UL)
#define ONE_MILLISECOND (ONE_SECOND/1000UL)
#define ONE_MICROSECOND (1000UL)

/* Conversion of constants to microseconds */
#define seconds(x) ((x)*ONE_SECOND)
#define milliseconds(x) ((x)*ONE_MILLISECOND)


/* Timestamp in nanoseconds */
static uint64_t timestamp(void)
{
	struct timespec t;

	clock_gettime(CLOCK_REALTIME, &t);
	return seconds(t.tv_sec) + t.tv_nsec;
}

#define cpu_relax()	asm volatile("rep; nop")

thread_local uint64_t now;		/* We do not want contention on this one */

__attribute__ ((format (printf, 2, 3)))
static void logg(int prio, const char *fmt, ...);

static const char *inet6_ntoa(void *x)
{
	char buf[INET6_ADDRSTRLEN];

	return inet_ntop(AF_INET6, x, buf, INET6_ADDRSTRLEN);
}

__attribute__ ((format (printf, 1, 2)))
static void panic(const char *fmt, ...);


static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;		/* Generic serialization mutex */

/* Is the lock taken */
bool locked = false;

/* Are we running concurrent threads ? */
bool multithreaded = false;

static void lock(void)
{
	if (multithreaded) {
 		if (pthread_mutex_lock(&mutex))
 			logg(LOG_CRIT, "Mutex lock failed: %s\n", errname());
	}

	if (locked)
	       	panic("lock() called when already locked\n");

	locked = true;
}
 
static void unlock(void)
{
	if (!locked)
		panic("unlock() called when not locked\n");

	locked = false;
	if (multithreaded) {
 		if (pthread_mutex_unlock(&mutex))
 			panic("Mutex unlock failed: %s\n", errname());

	}
}
 
#if 0
static bool trylock(void)
{
	if (multithreaded) {
 		if (pthread_mutex_trylock(&mutex)) {
 			if (errno != EBUSY)
 				logg(LOG_ERR, "Mutex trylock failed: %s\n", errname());
 			return false;
 		}
	} else {
		if (locked)
			abort();
	}

	locked = true;

out:
 	return true;
}
#endif

const struct in_addr ip_none = { .s_addr = 0 };

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

enum stats { packets_received, packets_sent, packets_bridged, packets_invalid, packets_queued,
		join_requests, join_failure, join_success,
		leave_requests,
		pgm_dup, pgm_odata, pgm_rdata, pgm_spm, pgm_nak, pgm_ack,
		nr_stats
};

static const char *stats_text[nr_stats] = {
	"PacketsReceived", "PacketsSent", "PacketsBridged", "PacketsInvalid", "PacketsQueued",
	"JoinRequests", "JoinFailures", "JoinSuccess", "LeaveRequests",
	"pgmdup", "pgm_odata", "pgm_rdata", "pgm_spm", "pgm_nak"
};

enum channel_type { channel_rdmacm, channel_ud, channel_qp1,
	channel_raw, channel_ibraw,
	channel_packet, channel_incoming,
	channel_err, nr_channel_types };

struct buf;

typedef void receive_callback(struct buf *);
typedef void event_callback(void *);

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
	unsigned int nr_cq;		/* Number of items for the CQ */
	unsigned int nr_send;		/* Maximum number of write buffers to use */
	unsigned int nr_receive;	/* Number of read buffer to post */
	unsigned stats[nr_stats];
	enum channel_type type;
	struct fifo send_queue;	/* Packets that were deferred for write */
	bool listening;		/* rdmacm Channel is listening for connections */
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
	struct i2r_interface *i;
	struct in_addr addr;
	union ibv_gid gid;
	uint16_t lid;
	struct ibv_ah *ah;
	struct forward *forwards;
};

static struct i2r_interface {
	/* Not changed when multithreading */
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
	const char *rdma_name;
	uint8_t if_mac[ETH_ALEN];
	struct sockaddr_in if_addr;
	struct sockaddr_in if_netmask;
	unsigned ifindex;
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
static void add_event(uint64_t  when, event_callback *callback, void *private, const char *text);
static uint64_t run_events(void);
static struct rdma_unicast *new_rdma_unicast(struct i2r_interface *i, struct sockaddr_in *sin);
static void register_callback(void (*callback)(void *), int fd, void *private);
static void handle_receive_packet(void *private);
static void handle_comp_event(void *private);
static void handle_rdma_event(void *private);
static void handle_async_event(void *private);


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
	i2r[i].rdma_name = rdmadev;
	return 1;
}

/* Scan through available RDMA devices in order to locate the devices for bridging */
static int find_rdma_devices(void)
{
	int nr;
	int i;
	struct ibv_device **list;

	i2r[ROCE].rdma_name = i2r[INFINIBAND].rdma_name = "<disabled>";
	list = ibv_get_device_list(&nr);

	if (nr <= 0) {
		logg(LOG_EMERG, "No RDMA devices present.\n");
		return 1;
	}

	for (i = 0; i < nr; i++) {
		struct ibv_device *d = list[i];
		const char *name = ibv_get_device_name(d);
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
			logg(LOG_EMERG, "Cannot open device %s\n", name);
			return 1;
		}

		if (ibv_query_device(c, &dattr)) {
			logg(LOG_EMERG, "Cannot query device %s\n", name);
			return 1;
		}

		for (port = 1; port <= dattr.phys_port_cnt; port++) {
			struct ibv_port_attr attr;

			if (ibv_query_port(c, port, &attr)) {
				logg(LOG_CRIT, "Cannot query port %s:%d\n", name, port);
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
				logg(LOG_EMERG, "ROCE device %s not found\n", roce_name);
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
				logg(LOG_EMERG, "Infiniband device %s not found.\n", ib_name);
			else {
				if (!bridging) {
					logg(LOG_EMERG, "No RDMA Devices available.\n");
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
 * Multicast Handling (follows the limit per QP as stated in device_attr for ConnectX6)
 */
#define MAX_MC 240

static unsigned nr_mc;
static unsigned active_mc;	/* MC groups actively briding */

enum mc_status { MC_OFF, MC_JOINING, MC_JOINED, MC_ERROR, NR_MC_STATUS };

const char *mc_text[NR_MC_STATUS] = { "Inactive", "Joining", "Joined", "Error" };

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
	enum mc_status status;
	bool sendonly;
	struct ah_info ai;
	struct sockaddr *sa;
	uint32_t packet_time;		/* How much time must elapse for a packet to be sent 0 = disabled */
	uint32_t max_burst;		/* How long can a burst last */
	uint64_t last_sent;		/* Last time a packet was sent */
	uint64_t last_delayed;		/* Last a delayed packet was scheduled */
	unsigned pending;		/* How many packets are waiting to be sent */
	unsigned burst;			/* # of packets encountered with pacing below packet_time */
	unsigned long delayed;		/* Packets delayed */
};

static struct mc {
	struct in_addr addr;
	struct mc_interface interface[2];
	bool beacon;
	uint16_t port;
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
	lock();

	if (hash_find(mc_hash, &m->addr)) {
		unlock();
		return -EEXIST;
	}

	hash_add(mc_hash, m);

	unlock();
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
	m->interface[ROCE].sa = (struct sockaddr  *)si;
	m->port = ntohs(si->sin_port);
	m->interface[INFINIBAND].sa = m->interface[ROCE].sa;

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

		m->interface[INFINIBAND].sa = (struct sockaddr *)saib;
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

	m->interface[INFINIBAND].sendonly = sendonly_infiniband;
	m->interface[ROCE].sendonly = sendonly_roce;
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
	unsigned port, enum interfaces i, bool sendonly, void *private)
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
		logg(LOG_CRIT, "Failed to create join request %s:%d on %s. Error %s\n",
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
		logg(LOG_ERR, "Failure on rdma_leave_multicast on %s:%s\n", interfaces_text[i], inet_ntoa(addr));
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

		ret = _leave_mc(m->addr, m->interface[i].sa, i);
		if (ret)
			return 1;
	}
	return 0;
}

/*
 * Manage freelist using simple single linked list with the pointer
 * to the next free element at the beginning of the free buffer
 */
static int nr_buffers = 100000;
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

static struct buf *alloc_buffer(struct rdma_channel *c)
{
	struct buf *buf, *next;

	do {
		buf = nextbuffer;
		if (!buf)
			return NULL;

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
}
 
static void free_buffer(struct buf *buf)
{
#ifdef DEBUG
	memset(buf->raw, 0, DATA_SIZE);
#endif
	buf->free = true;

	do {
		buf->next = nextbuffer;

	} while (!buf_cmpxchg(&nextbuffer, buf->next, buf));
}
 
static void __get_buf(struct buf *buf)
{
	if (!buf->refcount)
		panic("Buf refcount zero on __get_buf()\n");

	buf->refcount++;
}

static void __put_buf(struct buf *buf)
{
 	buf->refcount--;
 	if (buf->refcount) {
 		return;
 	}
 
	free_buffer(buf);
}
 
static void get_buf(struct buf *buf)
{
	unsigned x;

	if (multithreaded) {
		x = atomic_fetch_add(&buf->refcount, 1);
		if (!x)
			panic("Buf refcount zero in get_buf()\n");
	} else
		__get_buf(buf);
}
 
static void put_buf(struct buf *buf)
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
	unsigned long x = nr_buffers;

	if (sizeof(struct buf) != BUFFER_SIZE)
		panic("struct buf is not 8k as required\n");

	numa_run_on_node(i2r[INFINIBAND].context ? i2r[INFINIBAND].numa_node : i2r[ROCE].numa_node);

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

	numa_run_on_node(-1);

	/*
	 * Free in reverse so that we have a linked list
	 * starting at the first element which points to
	 * the second and so on.
	 */
	for (i = nr_buffers; i > 0; i--)
		free_buffer(&buffers[i-1]);
}

typedef bool setup_callback(struct rdma_channel *c);
static receive_callback receive_main, receive_multicast, receive_raw, receive_ud, receive_qp1;
static setup_callback setup_multicast, setup_channel, setup_raw, setup_packet, setup_incoming;

#define NO_CORE (-1)
/*
 * Matrix of channel types and their characteristics
 */
struct channel_info {

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

} channel_infos[nr_channel_types] = {
	{ "multicast",	0, 0,	10000,	1000,	0,		IBV_QPT_UD,		setup_multicast, receive_multicast, channel_err },
	{ "ud",		1, 1,	500,	200,	RDMA_UDP_QKEY,	IBV_QPT_UD,		setup_channel,	receive_ud,	channel_err }, 
	{ "qp1",	2, 1,	10,	5,	IB_DEFAULT_QP1_QKEY, IBV_QPT_UD,	setup_channel,	receive_qp1,	channel_err },
	{ "raw",	3, 1,	1000, 	5,	0x12345,	IBV_QPT_RAW_PACKET,	setup_raw,	receive_raw,	channel_packet },
	{ "ibraw",	3, 1,	1000,	5,	0x12345,	IBV_QPT_UD,		setup_raw,	receive_raw,	channel_packet },
	{ "packet",	-1, -1,	0,	0,	0,		0,			setup_packet,	receive_raw,	channel_err },
	{ "incoming",	-1, -1,	100,	50,	0,		0,			setup_incoming,	receive_main,	channel_err },
	{ "error",	-1, -1,	0,	0,	0,		0,			NULL,		NULL,		channel_err },
};

/*
 * Core layout
 *
 * The basic ib2roce thread is outside of the cores here running
 * in high latency mode which is used for management and for all
 * activities not pushed to the polling cores.
 *
 * Cores always contain pairs of QPs on both interfaces. That reduces
 * lock contention and optimizes the behavior overall.
 *
 */

#define MAX_CORE 8
#define MAX_CQS_PER_CORE 4

static unsigned cores = 0;		/* How many cores can we consume */

enum core_state { core_off, core_init, core_running, core_err, nr_core_states };
 
/*
 * Determine the core to be used for a channel
 */
static short core_lookup(struct i2r_interface *i,  enum channel_type type)
{
	short core = channel_infos[type].core;

	if (!cores)
		goto nocore;

	if (core == NO_CORE)
		goto nocore;
	
	if (core < cores)
		return core;

	core = channel_infos[type].alt_core;
	if (core < cores)
		return core;

	/* If nothing worked put it onto the first core */
	return 0;

nocore:
	return NO_CORE;
}

typedef void thread_callback(void *);
thread_local struct core_info *current = NULL;

struct core_info {
	unsigned nr_channels;
	struct rdma_channel channel[MAX_CQS_PER_CORE];
	/* Statistics */
	unsigned samples;
	long sum_latency;
	unsigned max_latency;
	unsigned min_latency;
	struct ring ring;
	/* Rarely used */
	enum core_state state;
	int numa_node;
	pthread_t thread;			/* Thread */
	pthread_attr_t attr;
} core_infos[MAX_CORE];

static void show_core_config(void)
{
	unsigned i;

	for(i = 0; i < cores; i++) {
		char b[200];
		unsigned n = 0;
		unsigned j;
		struct core_info *ci = core_infos + i;

		if (ci->nr_channels) {
			for (j = 0; j < ci->nr_channels; j++) {
				n += sprintf(b + n, "%s ", ci->channel[j].text);
			}
		} else {
			n += sprintf(b + n, "<not used>");
		}

		n += sprintf(b +n,"\n");
		logg(LOG_NOTICE, "Core %d: NUMA=%d %s", i, ci->numa_node, b);

	}
}

__attribute__ ((format (printf, 2, 3)))
static void logg(int prio, const char *fmt, ...)
{
	va_list valist;

	if ((prio & 0x7) > loglevel)
		return;

	va_start(valist, fmt);

	if (current) {
		int n;
		char b[150];
		b[0] = '0' + prio;

		n = vsnprintf(b + 1, 149, fmt, valist);
		ring_put(&current->ring, b, n);

	} else if (background)
		vsyslog(prio, fmt, valist);
	else
		vprintf(fmt, valist);
}

#define NR_FRAMES 100
__attribute__ ((format (printf, 1, 2)))
static void panic(const char *fmt, ...)
{
	va_list valist;
	void *frames[NR_FRAMES];
	int nrframes;
	int j;
	char **strings;

	printf("IB2ROCE Panic: ");
	va_start(valist, fmt);
	vprintf(fmt, valist);
	
	nrframes = backtrace(frames, NR_FRAMES);
	strings = backtrace_symbols(frames, nrframes);

	for( j= 0; j < nrframes; j++) {
		printf("%d. %s\n", j, strings[j]);
	}
	free(strings);
	abort();
}


static struct rdma_channel *new_rdma_channel(struct i2r_interface *i, enum channel_type type)
{
	struct rdma_channel *c;
	struct channel_info *ci;
	struct core_info *coi = NULL;
	char *p;
	short core;
	int channel_nr;

retry:
	ci = channel_infos + type;
	channel_nr = -1;

	core = core_lookup(i, type);
	if (core != NO_CORE) {
		coi = core_infos + core;

		channel_nr = coi->nr_channels;
		c = coi->channel + channel_nr;
		memset(c, 0, sizeof(struct rdma_channel));
		coi->nr_channels++;
		if (coi->nr_channels > MAX_CQS_PER_CORE)
			panic("Too many RDMA channels per core. Max = %d\n", MAX_CQS_PER_CORE);

		c->core = coi;

	} else
		c = calloc(1, sizeof(struct rdma_channel));

	if (type == channel_err)
		goto err;

	c->i = i;
	c->type = type;
	c->receive = ci->receive;

	p = malloc(strlen(i->text) + strlen(ci->suffix) + 2);
	strcpy(p, i->text);
	strcat(p, "-");
	strcat(p, ci->suffix);
	c->text = p;

	c->nr_cq = ci->nr_cq;
	c->nr_send = ci->nr_send;
	c->nr_receive = ci->nr_cq - ci->nr_send;
	fifo_init(&c->send_queue);
	
	if (ci->setup(c)) {
		/* Channel setup ok */

		if (coi) {
			if (channel_nr == 0) {
				coi->numa_node = c->i->numa_node;
			} else {
				if (coi->numa_node != c->i->numa_node) {
					logg(LOG_WARNING, "Core %d has NUMA %d but Channel %s NUMA %d are has conflicting requirements about NUMA placement\n",
						core, coi->numa_node, c->text, c->i->numa_node);
					/* Cannot bind since we are dealing with hardware from multiple nodes */
					coi->numa_node = -1;
				}
			}
		}
		return c;
	}

	if (type != ci->fallback) {
		type = ci->fallback;
		free(p);
		if (channel_nr < 0)
			free(c);
		else
			coi->nr_channels--;
		goto retry;
	}

err:
	if (channel_nr < 0)
		free(c);

	return NULL;
}

static void process_cqes(struct rdma_channel *c, struct ibv_wc *w, unsigned cqs);
static void arm_channels(struct core_info *core);

/*
 * Polling function for each core enabling low latency operations.
 * This currently does not support NUMA affinities. It may need
 * to benefit from manually setting affinities but -- aside from the
 * obvious need to run on the NIC numa node that it serves --
 * the Linux scheduler should take care of most of what is needed.
 *
 * NOHZ should be enabled though to avoid hiccups from timer interrupts
 */
static void *busyloop(void *private)
{
	struct rdma_channel *c;
	int cqs;
	int i;
	unsigned cpu;

	struct ibv_wc wc[10];

	current = private;
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	numa_run_on_node(current->numa_node);

	current->state = core_init;

	cpu = sched_getcpu();
	logg(LOG_NOTICE, "Busyloop started (core %ld) on CPU %d NUMA=%d\n", current - core_infos, cpu, current->numa_node);

	/*
	 * Initialize relevant data structures for this thread. These must be allocated
	 * from the thread to ensure that they are thread local
	 */
	arm_channels(current);

	current->state = core_running;

	now = timestamp(); 	/* Will be done by run_events in the future */
	do {
		uint64_t tdiff;
	
		cpu_relax();
		/* Scan CQs */
		for(i = 0; i < current->nr_channels; i++) {
			c = current->channel + i;
			cqs = ibv_poll_cq(c->cq, 10, wc);
			if (cqs) {

				if (cqs > 0)
					process_cqes(c, wc, cqs);
				else {
					logg(LOG_ERR, "Busyloop: CQ polling failed with: %s on %s\n",
						errname(), c->text);
					current->state = core_err;
					continue;
				}
			}
		}


		if (latency) {
			tdiff = timestamp() - now;

			if (tdiff > current->max_latency)
				current->max_latency = tdiff;
			if (tdiff < current->min_latency || !current->min_latency)
				current->min_latency = tdiff;

			if (tdiff > 5000) {
				current->sum_latency += tdiff;
				current->samples++;
				if (current->samples > 1000000000) {
					current->samples = 1;
					current->sum_latency = tdiff;
				}
				if (tdiff > ONE_MILLISECOND)
					logg(LOG_NOTICE, "Busyloop took longer than a millisecond %ld\n", tdiff);
			}
		}

		run_events();

	} while (!terminated);

	return NULL;
}

static void get_core_logs(void *private)
{
	struct core_info *c = private;
	char msg[251];
	unsigned len;

	while ((len = ring_get(&c->ring, msg, sizeof(msg) - 1))) {
		int prio;

		msg[len] = 0;
		prio = msg[0] - '0';
		logg(prio, "%s\n", msg + 1);
	}
	add_event(now + milliseconds(100), get_core_logs, c, "Get Core Logs");
}

/* Called after all the channels have been setup */
static void start_cores(void)
{
	int j;

	multithreaded = true;

	for(j = 0; j < cores; j++) {
		struct core_info *ci = core_infos + j;

		if (!ci->nr_channels)
			continue;

		ring_init(&ci->ring);
		get_core_logs(ci);

		if (pthread_create(&ci->thread, &ci->attr, &busyloop, core_infos + j))
			panic("Pthread create failed: %s\n", errname());
	}
}

static void stop_cores(void)
{
	int i;

	for(i = 0; i < cores; i++) {
		struct core_info *ci = core_infos + i;

		if (!ci->thread)
			continue;

		pthread_cancel(ci->thread);

		if (pthread_join(ci->thread, NULL))
			panic("pthread_join failed: %s\n", errname());
	}

	multithreaded = false;
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

/*
 * Handling of RDMA work requests
 */
static void post_receive(struct rdma_channel *c)
{
	struct ibv_recv_wr recv_wr, *recv_failure;
	struct ibv_sge sge;
	int ret = 0;

	if (!c || !nextbuffer)
		return;

	if (c->active_receive_buffers >= c->nr_receive)
		return;

	recv_wr.next = NULL;
	recv_wr.sg_list = &sge;
	recv_wr.num_sge = 1;

	sge.length = DATA_SIZE;
	sge.lkey = c->mr->lkey;

	while (c->active_receive_buffers < c->nr_receive) {

		struct buf *buf = alloc_buffer(c);

		if (!buf) {
			logg(LOG_WARNING, "%s: No free buffers left\n", c->text);
			return;
		}

		/* Use the buffer address for the completion handler */
		recv_wr.wr_id = (uint64_t)buf;
		sge.addr = (uint64_t)buf->raw;
		ret = ibv_post_recv(c->qp, &recv_wr, &recv_failure);
		if (ret) {
			free_buffer(buf);
			errno = ret;
			logg(LOG_ERR, "ibv_post_recv failed: %s:%s\n", c->text, errname());
			return;
                }
		c->active_receive_buffers++;
	}
}

static void post_receive_buffers(void)
{
	struct i2r_interface *i;

	for(i = i2r; i < i2r + NR_INTERFACES; i++) {
		post_receive(i->multicast);
		post_receive(i->raw);
		post_receive(i->qp1);
		post_receive(i->ud);
	}
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
	if (!c->core)
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
	if (i == i2r + INFINIBAND && i->raw && i->raw->type == channel_ibraw) {
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
	char buffer[80];
	const char *reason = "socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)";

	if (fh < 0)
		goto err;

	/*
	 * Work around the quirk of ifindex always being zero for
	 * INFINIBAND interfaces. Just assume its ib0.
	 */
	if (!i->ifindex && i - i2r == INFINIBAND) {

		if (!i->if_name[0]) {
			strcpy(ifr.ifr_name, "ib0");
			if (ioctl(fh, SIOCGIFINDEX, &ifr) == 0)
				logg(LOG_WARNING, "Assuming ib0 is the IP device name for %s\n",
				     i->rdma_name);
			else {
				strcpy(ifr.ifr_name, "ib1");
				if (ioctl(fh, SIOCGIFINDEX, &ifr) == 0)
					logg(LOG_WARNING, "Assuming ib1 is the IP device name for %s\n",
						i->rdma_name);
				else
					panic("Cannot determine device name for %s\n", i->rdma_name);
			}
			strcpy(i->if_name, ifr.ifr_name);
		} else
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
	close(fh);

	/* Read NUMA node of the IF */
	snprintf(buffer, sizeof(buffer), "/sys/class/net/%s/device/numa_node", i->if_name);
	fh = open(buffer, O_RDONLY);
	if (read(fh, buffer, sizeof(buffer)) < 0)
		logg(LOG_CRIT, "Cannot read from sysfs. %s\n", errname());
	close(fh);

	i->numa_node = atoi(buffer);
	return;

err:
	panic("Cannot determine IP interface setup for %s %s : %s\n",
		     i->rdma_name, reason, errname());
}

static void start_channel(struct rdma_channel *c)
{
	int ret;

	if (!c)
		return;

	if (c->type == channel_rdmacm)
       		return;

	c->attr.qp_state = IBV_QPS_RTR;

	ret = ibv_modify_qp(c->qp, &c->attr, IBV_QP_STATE);
	if (ret)
		logg(LOG_CRIT, "ibv_modify_qp: Error when moving %s to RTR state. %s\n", c->text, errname());

	if (c->type == channel_ud || c->type == channel_qp1) {

		c->attr.qp_state = IBV_QPS_RTS;
		ret = ibv_modify_qp(c->qp, &c->attr, IBV_QP_STATE | IBV_QP_SQ_PSN);

		if (ret)
			logg(LOG_CRIT, "ibv_modify_qp: Error when moving %s to RTS state. %s\n", c->text, errname());

	}
	logg(LOG_NOTICE, "QP %s moved to state %s: QPN=%d\n",
		 c->text,  (c->type == channel_ud || c->type == channel_qp1)? "RTS/RTR" : "RTR", c->qp->qp_num);
}

static void stop_channel(struct rdma_channel *c)
{
	int ret;

	if (c->type == channel_rdmacm)
		return;

	c->attr.qp_state = IBV_QPS_INIT;

	ret = ibv_modify_qp(c->qp, &c->attr, IBV_QP_STATE);
	if (ret)
		logg(LOG_CRIT, "ibv_modify_qp: Error when moving %s to INIT state. %s\n", c->text, errname());

	logg(LOG_NOTICE, "QP %s moved to state QPS_INIT\n", c->text);
}

static int allocate_rdmacm_qp(struct rdma_channel *c, bool multicast)
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
		return false;
	}

	/*
	 * Must alloate comp_events channel using the context created by rdmacm
	 * otherwise ibv_create_cq will fail.
	 * Only needed if the rdma cm channel is not served by polling.
	 */
	if (!c->core) {
		c->comp_events = ibv_create_comp_channel(c->id->verbs);
		if (!c->comp_events)
			panic("ibv_create_comp_channel failed for %s : %s.\n",
				c->text, errname());
		register_callback(handle_comp_event, c->comp_events->fd, c->comp_events);
	} else
		c->comp_events = NULL;

	c->cq = ibv_create_cq(c->id->verbs, c->nr_cq, c, c->comp_events, 0);
	if (!c->cq) {
		logg(LOG_CRIT, "ibv_create_cq failed for %s : %s nr_cq=%d.\n",
			c->text, errname(), c->nr_cq);
		return false;
	}

	memset(&init_qp_attr_ex, 0, sizeof(init_qp_attr_ex));
	init_qp_attr_ex.cap.max_send_wr = c->nr_send;
	init_qp_attr_ex.cap.max_recv_wr = c->nr_receive;
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
				c->text, errname(), c->nr_cq);
		return false;
	}

	/* Copy QP to convenient location that is shared by all types of channels */
	c->qp = c->id->qp;
	c->mr = ibv_reg_mr(c->pd, buffers, nr_buffers * sizeof(struct buf), IBV_ACCESS_LOCAL_WRITE);
	if (!c->mr) {
		logg(LOG_CRIT, "ibv_reg_mr failed for %s:%s.\n", c->text, errname());
		return false;
	}
	return true;
}

bool setup_multicast(struct rdma_channel *c)
{
	struct i2r_interface *i = c->i;
	struct sockaddr_in *sin;
	int ret;

	sin = calloc(1, sizeof(struct sockaddr_in));
	sin->sin_family = AF_INET;
	sin->sin_addr = i->if_addr.sin_addr;
	sin->sin_port = htons(default_port);
	c->bindaddr = (struct sockaddr *)sin;

	ret = rdma_create_id(i->rdma_events, &c->id, c, RDMA_PS_UDP);
	if (ret) {
		logg(LOG_CRIT, "Failed to allocate RDMA CM ID for %s failed (%s).\n",
			c->text, errname());
		return false;
	}

	register_callback(handle_async_event, i->context->async_fd, i);

	ret = rdma_bind_addr(c->id, c->bindaddr);
	if (ret) {
		logg(LOG_CRIT, "Failed to bind %s interface. Error %s\n",
			c->text, errname());
		return false;
	}

	return allocate_rdmacm_qp(c, true);
}

bool setup_incoming(struct rdma_channel *c)
{
	return allocate_rdmacm_qp(c, true);
}

/* Not using rdmacm so this is easier on the callbacks */
static bool setup_channel(struct rdma_channel *c)
{
	struct i2r_interface *i = c->i;
	int ret;
	struct ibv_qp_init_attr_ex init_qp_attr_ex;

	c->mr = i->mr;
	c->pd = i->pd;

	if (!c->core)
		c->comp_events = i->comp_events;

	c->cq = ibv_create_cq(i->context, c->nr_cq, c, c->comp_events, 0);
	if (!c->cq) {
		logg(LOG_CRIT, "ibv_create_cq failed for %s.\n",
			c->text);
		return false;
	}

	memset(&init_qp_attr_ex, 0, sizeof(init_qp_attr_ex));
	init_qp_attr_ex.cap.max_send_wr = c->nr_send;
	init_qp_attr_ex.cap.max_recv_wr = c->nr_receive;
	init_qp_attr_ex.cap.max_send_sge = 1;	/* Highly sensitive settings that can cause -EINVAL if too large (10 f.e.) */
	init_qp_attr_ex.cap.max_recv_sge = 1;
	init_qp_attr_ex.cap.max_inline_data = MAX_INLINE_DATA;
	init_qp_attr_ex.qp_context = c;
	init_qp_attr_ex.sq_sig_all = 0;
	init_qp_attr_ex.qp_type = channel_infos[c->type].qp_type,
	init_qp_attr_ex.send_cq = c->cq;
	init_qp_attr_ex.recv_cq = c->cq;

	init_qp_attr_ex.comp_mask = IBV_QP_INIT_ATTR_CREATE_FLAGS|IBV_QP_INIT_ATTR_PD;
	init_qp_attr_ex.pd = i->pd;
	init_qp_attr_ex.create_flags = 0;

	c->qp = ibv_create_qp_ex(i->context, &init_qp_attr_ex);
	if (!c->qp) {
		logg(LOG_CRIT, "ibv_create_qp_ex failed for %s. Error %s. Port=%d #CQ=%d\n",
				c->text, errname(), i->port, c->nr_cq);
		return false;
	}

	c->attr.port_num = i->port;
	c->attr.qp_state = IBV_QPS_INIT;
	c->attr.pkey_index = 0;
	c->attr.qkey = channel_infos[c->type].qkey;

	ret = ibv_modify_qp(c->qp, &c->attr,
	       (i == i2r + ROCE && c->type == channel_raw) ?
			(IBV_QP_STATE | IBV_QP_PORT) :
			( IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_QKEY)
	);

	if (ret) {
		logg(LOG_CRIT, "ibv_modify_qp: Error when moving %s to Init state. %s\n", c->text, errname());
		ibv_destroy_qp(c->qp);
		ibv_destroy_cq(c->cq);
		c->qp = NULL;
		return false;
	}
	return true;
}

static bool setup_packet(struct rdma_channel *c)
{
	struct i2r_interface *i = c->i;
	int fh;
	struct sockaddr_ll ll  = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = i->ifindex,
		.sll_hatype = ARPHRD_ETHER,
		.sll_pkttype = PACKET_BROADCAST | PACKET_HOST | PACKET_OTHERHOST,
		.sll_halen = sizeof(struct in_addr),
	};

	if (i == i2r + INFINIBAND) {
		logg(LOG_ERR, "Packet Sockets do not work right on Infiniband\n");
		return false;
	}

	fh = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (fh < 0) {
		logg(LOG_ERR, "Raw Socket creation failed for %s:%s\n", i->text, errname());
		return false;
	}

	if (bind(fh, (struct sockaddr *)&ll, sizeof(struct sockaddr_ll))) {
		logg(LOG_ERR, "Cannot bind raw socket for %s:%s\n", i->text, errname());
		return false;
	}

	c->fh = fh;
	register_callback(handle_receive_packet, fh, c);
	return true;
}

static bool setup_raw(struct rdma_channel *c)
{
	if (!setup_channel(c))
		return false;

#ifdef HAVE_MSTFLINT
	if (c->i == i2r + INFINIBAND) {
		if (set_ib_sniffer(c->i->rdma_name, c->i->port, c->qp)) {

			logg(LOG_ERR, "Failure to set sniffer mode on %s\n", c->text);
			ibv_destroy_qp(c->qp);
			ibv_destroy_cq(c->cq);
			return false;

		} else 

		/* Install abort handler so that we can be sure that the capture mode is switched off */
		signal(SIGABRT, &shutdown_sniffer);
		signal(SIGSEGV, &shutdown_sniffer);
	}
#endif
	return true;
}

/* Check overrun counter */
static void check_out_of_buffer(void *private)
{
	struct i2r_interface *i = private;
	int fh;
	char buffer[100];
	unsigned long out_of_buffer;

	snprintf(buffer, sizeof(buffer), "/sys/class/infiniband/%s/ports/%d/hw_counters/out_of_buffer", i->rdma_name, i->port);
	fh = open(buffer, O_RDONLY);
	if (read(fh, buffer, sizeof(buffer)) < 0)
		logg(LOG_CRIT, "Cannot read out_of_buffer counter from sysfs. %s\n", errname());
	close(fh);

	out_of_buffer = atol(buffer);
	if (i->out_of_buffer != out_of_buffer) {
		if (i->out_of_buffer)
			logg(LOG_ERR, "Out of Buffer on %s. %ld packets dropped (was %ld, now %ld)\n",
					i->text, out_of_buffer - i->out_of_buffer, i->out_of_buffer, out_of_buffer);

		i->out_of_buffer = out_of_buffer;
	}
	add_event(now + ONE_SECOND, check_out_of_buffer, i, "Check out of buffers\n");
}

static void setup_interface(enum interfaces in)
{
	struct i2r_interface *i = i2r + in;
	struct ibv_gid_entry *e;

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
		i->context = NULL;
		return;
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
		logg(LOG_CRIT, "Failed to find a suitable entry GID table for %s\n",
			i->text);
		i->context = NULL;
		return;
	}

	/* Copy our connection info from GID table */
	i->gid = e->gid;
	i->gid_index = e->gid_index;
	i->ifindex = e->ndev_ifindex;

	/* Get more info about the IP network attached to the RDMA device */
	get_if_info(i);

	numa_run_on_node(i->numa_node);

	i->ru_hash = hash_create(offsetof(struct rdma_unicast, sin), sizeof(struct sockaddr_in));
	i->ip_to_ep = hash_create(offsetof(struct endpoint, addr), sizeof(struct in_addr));
	if (i == i2r + INFINIBAND)
		i->ep = hash_create(offsetof(struct endpoint, lid), sizeof(uint16_t));
	else
		i->ep = i->ip_to_ep;;


	/* Create RDMA elements that are interface wide */

	i->rdma_events = rdma_create_event_channel();
	if (!i->rdma_events)
		panic("rdma_create_event_channel() for %s failed (%s).\n",
			i->text, errname());

	register_callback(handle_rdma_event, i->rdma_events->fd, i);

	i->pd = ibv_alloc_pd(i->context);
	if (!i->pd)
       		panic("ibv_alloc_pd failed for %s.\n", i->text);

	i->comp_events = ibv_create_comp_channel(i->context);
	if (!i->comp_events)
       		panic("ibv_create_comp_channel failed for %s : %s.\n",
			i->text, errname());

	register_callback(handle_comp_event, i->comp_events->fd, i->comp_events);

	i->mr = ibv_reg_mr(i->pd, buffers, nr_buffers * sizeof(struct buf), IBV_ACCESS_LOCAL_WRITE);
	if (!i->mr)
		panic("ibv_reg_mr failed for %s:%s.\n", i->text, errname());

	i->multicast = new_rdma_channel(i, channel_rdmacm);

	if (!i->multicast)
		abort();

	if (unicast) {

		i->ud = new_rdma_channel(i, channel_ud);
		i->qp1 = new_rdma_channel(i, channel_qp1);

		if (raw) {
			if (i == i2r + INFINIBAND) {
				i->raw = new_rdma_channel(i, channel_ibraw);
				/* Sadly fallback is not working here */
			} else {
				if (packet_socket)
					i->raw = new_rdma_channel(i, channel_packet);
				else
					i->raw = new_rdma_channel(i, channel_raw);
			}
		}
	}

	check_out_of_buffer(i);
	numa_run_on_node(-1);

	logg(LOG_NOTICE, "%s interface %s/%s(%d) port %d GID=%s/%d IPv4=%s:%d CQs=%u/%u/%u MTU=%u NUMA=%d.\n",
		i->text,
		i->rdma_name,
		i->if_name, i->ifindex,
		i->port,
		inet6_ntoa(e->gid.raw), i->gid_index,
		inet_ntoa(i->if_addr.sin_addr), default_port,
		i->multicast ? i->multicast->nr_cq: 0,
		i->ud ? i->ud->nr_cq : 0,
		i->raw ? i->raw->nr_cq : 0,
		i->mtu,
		i->numa_node
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
		unsigned port = m->port;

		if (m->interface[ROCE].status == MC_JOINED && m->interface[INFINIBAND].status == MC_JOINED)
			continue;

		for(in = 0; in < 2; in++) {
			struct mc_interface *mi = m->interface + in;

			if (i2r[in].context) {
				switch(mi->status) {

				case MC_OFF:
					if (_join_mc(m->addr, mi->sa, port, in, mi->sendonly, m) == 0)
						m->interface[in].status = MC_JOINING;
					break;

				case MC_ERROR:

					_leave_mc(m->addr, mi->sa, in);
					mi->status = MC_OFF;
					logg(LOG_WARNING, "Left Multicast group %s on %s due to MC_ERROR\n",
						m->text, interfaces_text[in]);
					break;

				case MC_JOINED:
					break;

				default:
					logg(LOG_ERR, "Bad MC status %d MC %s on %s\n",
					       mi->status, m->text, interfaces_text[in]);
					break;
				}
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
		ru->c = new_rdma_channel(i, channel_incoming);
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

static void set_rate(struct mc *m)
{
	if (irate) {
			m->interface[INFINIBAND].packet_time = ONE_SECOND / irate;
			m->interface[INFINIBAND].max_burst = max_iburst;
	}

	if (rrate) {
			m->interface[ROCE].packet_time = ONE_SECOND / rrate;
			m->interface[ROCE].max_burst = max_rburst;
	}

}

static void set_rates(void)
{
	int j;

	for (j = 0; j < nr_mc; j++) {
		struct mc *m = mcs + j;

		set_rate(m);
		set_rate(m);
	}
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
				struct ah_info *a = &m->interface[in].ai;

				a->remote_qpn = param->qp_num;
				a->remote_qkey = param->qkey;
				if (rate)
					param->ah_attr.static_rate = rate;

				a->ah = ibv_create_ah(i->multicast->pd, &param->ah_attr);
				if (!a->ah) {
					logg(LOG_ERR, "Failed to create AH for Multicast group %s on %s \n",
						m->text, i->text);
					m->interface[in].status = MC_ERROR;
					break;
				}
				m->interface[in].status = MC_JOINED;

				/* Things actually work if both multicast groups are joined */
				if (!bridging || m->interface[in^1].status == MC_JOINED)
					active_mc++;

				logg(LOG_NOTICE, "Joined %s MLID 0x%x sl %u on %s\n",
					inet6_ntoa(param->ah_attr.grh.dgid.raw),
					param->ah_attr.dlid,
					param->ah_attr.sl,
					i->text);
				st(i->multicast, join_success);

				set_rate(m);
			}
			break;

		case RDMA_CM_EVENT_MULTICAST_ERROR:
			{
				struct rdma_ud_param *param = &event->param.ud;
				struct mc *m = (struct mc *)param->private_data;

				logg(LOG_ERR, "Multicast Error. Group %s on %s\n",
					m->text, i->text);

				/* If already joined then the bridging may no longer work */
				if (!bridging || (m->interface[in].status == MC_JOINED && m->interface[in^1].status == MC_JOINED))
				       active_mc--;

				m->interface[in].status = MC_ERROR;
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

				allocate_rdmacm_qp(ru->c, false);

				post_receive(ru->c);
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
				struct rdma_channel *c = new_rdma_channel(i, channel_rdmacm);

				logg(LOG_NOTICE, "RDMA_CM_CONNECT_REQUEST id=%p listen_id=%p\n",
					event->id, event->listen_id);

				c->id->context = c;

				if (!allocate_rdmacm_qp(c, false))
					goto err;

				post_receive(c);

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
 * No MR is being used so this works for any QP.
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
		logg(LOG_ERR, "Failed to post inline send: %s on %s\n", errname(), c->text);
	} else
		logg(LOG_INFO, "Inline Send to QPN=%d QKEY=%x %d bytes\n",
				wr.wr.ud.remote_qpn, wr.wr.ud.remote_qkey, len);

	return ret;
}

/*
 * Send data to target using native RDMA structs relying on state in struct buf.
 */
static int send_ud(struct rdma_channel *c, struct buf *buf, struct ibv_ah *ah, uint32_t remote_qpn, uint32_t qkey)
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
		stop_channel(c);
	} else
		logg(LOG_DEBUG, "RDMA Send to QPN=%d QKEY=%x %d bytes\n",
			wr.wr.ud.remote_qpn, wr.wr.ud.remote_qkey, len);

	return ret;
}

static int send_pending_buffers(struct rdma_channel *c)
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

#define SEND_QUEUE_MAX 20

struct rdma_channel *send_queue_table[SEND_QUEUE_MAX];

static void send_queue_monitor(void *private)
{
	int i;
	bool active;

	for(i = 0; i < SEND_QUEUE_MAX; i++) {
		struct rdma_channel *c = send_queue_table[i];

		if (!c)
			continue;

		active = true;
		if (send_pending_buffers(c)) {
			/* We just drained the queue */
			send_queue_table[i] = NULL;
		}

	}

	add_event(now + milliseconds(active ? 10: 100),
		send_queue_monitor, NULL, "SendQueue");

}

static void send_queue_add(struct rdma_channel *c)
{
	int free = -1;
	int i;

	for( i = 0; i < SEND_QUEUE_MAX; i++) {
		struct rdma_channel *r = send_queue_table[i];

		if (!r && free < 0)
			free = i;
		else if (r == c)
			return;
	}

	if (free >= 0)
		send_queue_table[free] = c;
	else
		panic("No slots left in send_queue\n");
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
	int ret;
	struct ibv_send_wr *bad_send_wr;

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

	if (!fifo_empty(&c->send_queue) || c->active_send_buffers >= c->nr_send)
		goto queue;

	c->active_send_buffers++;
	ret = ibv_post_send(c->qp, &buf->wr, &bad_send_wr);
	if (ret) {
		if (errno == ENOMEM)
			goto queue;

		errno = ret;
		logg(LOG_WARNING, "Failed to post send: %s on %s. Active Receive Buffers=%d/%d Active Send Buffers=%d\n", errname(), c->text, c->active_receive_buffers, c->nr_receive, c->active_send_buffers);
		put_buf(buf);
	} else {
		logg(LOG_DEBUG, "RDMA Send to QPN=%d QKEY=%x %d bytes\n",
			buf->wr.wr.ud.remote_qpn, buf->wr.wr.ud.remote_qkey, len);
	}

	return ret;

queue:
	if (fifo_put(&c->send_queue, buf) && !current)
		/*
		 * This moves the handling onto the high latency thread.
		 * Adding the queue is only required when we add the first
		 * buffer
		 */
		send_queue_add(c);

	st(c, packets_queued);
	return 0;
}

/* Send buffer based on state in struct buf. Unicast only */
static int send_buf(struct buf *buf, struct rdma_unicast *ra)
{
	unsigned len = buf->end - buf->cur;
	int ret;

	if (len < MAX_INLINE_DATA) {
		ret = send_inline(ra->c, buf->cur, len, &ra->ai, buf->imm_valid, buf->imm);
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
 *
 * dest == NULL enables wildcard search just based on source_qp
 *
 * source_qp = 0 indicated that the source_qp is not known yet.
 */
static struct forward *find_forward(struct endpoint *source, struct endpoint *dest, uint32_t source_qp)
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
 * PGM RFC3208 Support
 */

enum pgm_mode { pgm_none, pgm_passthrough, pgm_dlr, pgm_resend };

enum pgm_mode pgm_mode = pgm_passthrough;

struct nak {
	struct pgm_nak *next;
	unsigned sqn;
	bool nak_sent;
	bool ncf_sent;
	bool nnak_sent;
};

struct pgm_tsi {
	struct in_addr mcgroup;
	struct in_addr sender;
	uint16_t dport;
	uint16_t sport;
};

/* Stream information */
struct pgm_stream {
	struct pgm_tsi tsi;	
	struct i2r_interface *i;	/* Interface of the source */
	unsigned trail;			/* Sender trail */
	unsigned lead;			/* Sender lead */

	unsigned last;			/* Highest SQN received */
	unsigned rlast;			/* Last Repair data */
	unsigned last_seq;		/* Last in sequence */
	unsigned oldest;		/* The oldest message available locally */
	struct nak *nak;
	char text[60];
};

/* Records (ODATA/RDATA) in a stream */
struct pgm_record {
	struct pgm_tsi tsi;
	uint32_t sqn;			/* Message ID  */
	struct pgm_stream *stream;	
	struct buf *buf;		/* Address of buffer */
	void *start;			/* Beginning of ODATA/RDATA record */
	unsigned len;			/* Length of the message */
};

static void init_pgm_streams(void)
{
	struct i2r_interface *i;

	for(i = i2r; i < i2r + NR_INTERFACES; i++) {
		i->pgm_tsi_hash = hash_create(0, sizeof(struct pgm_tsi));
		i->pgm_record_hash = hash_create(0, sizeof(struct pgm_tsi) + sizeof(uint32_t));
	}
}

static void format_tsi(char *b, struct pgm_tsi *tsi)
{
	static char c[30];

	strcpy(c, inet_ntoa(tsi->sender));

	snprintf(b, 60, "%s:%d->%s:%d", c, ntohs(tsi->sport), inet_ntoa(tsi->mcgroup), ntohs(tsi->dport));
}

static bool add_record(struct buf *buf, struct pgm_tsi *tsi, uint32_t sqn, void *start, unsigned len)
{
	struct i2r_interface *i = buf->c->i;
	struct pgm_record *r = calloc(1, sizeof(struct pgm_record));
	struct pgm_record *q;

	r->tsi = *tsi;
	r->sqn = sqn;
	r->buf = buf;
	r->start = start;
	r->len = len;

	lock();
	if ((q = hash_find(i->pgm_record_hash, &r))) {
		unlock();
		return false;
	} else {
		__get_buf(buf);
		hash_add(i->pgm_record_hash, r);
		unlock();
		return true;
	}
}

static struct pgm_record *find_record(struct i2r_interface *i, struct pgm_tsi *tsi, uint32_t sqn)
{
	struct pgm_record f = { .tsi = *tsi, .sqn = sqn };

	return hash_find(i->pgm_record_hash, &f);
}

/* Forwarded packet if ib2roce behaves like a DLR */
static void forward_packet(struct buf *buf, struct pgm_tsi *tsi, uint32_t sqn)
{
}

/* Packet delivery in sequence */
static void deliver_in_seq(struct buf *buf, struct pgm_tsi *tsi, uint32_t sqn)
{
}

static bool pgm_process(struct rdma_channel *c, struct mc *m, struct buf *buf)
{
	struct i2r_interface *i = c->i;
	struct pgm_tsi tsi;
	struct pgm_stream *s;
	uint32_t sqn;
	uint32_t tdsu;
	uint16_t total_opt_length = 0;
	uint8_t *options_start;
	union {
		struct pgm_header pgm;
		struct {
			uint8_t skip[8];
			struct in_addr addr;
			uint16_t port;
		};
	} header;
	char text[60];
	struct pgm_spm spm;
	struct pgm_data data;
	struct pgm_nak nak;
#if 0
	struct pgm_poll poll;
	struct pgm_polr polr;
#endif
	struct pgm_ack ack;
	int ret = true;

	PULL(buf, header);

	tdsu = ntohs(header.pgm.pgm_tsdu_length);

	tsi.mcgroup = m->addr;
	memcpy(&tsi.sender, header.pgm.pgm_gsi, sizeof(struct in_addr));
	tsi.sport = ntohs(header.pgm.pgm_sport);
	tsi.dport = ntohs(header.pgm.pgm_dport);
	format_tsi(text, &tsi);

	s = hash_find(i->pgm_tsi_hash, &tsi);

	switch (header.pgm.pgm_type) {
		case PGM_SPM:		/* Multicast downstream */
			PULL(buf, spm);
			if (!s)
				break;

			st(c, pgm_spm);

			s->trail = ntohl(spm.spm_trail);
			s->lead = ntohl(spm.spm_lead);
			if (pgm_mode <= pgm_passthrough)
				break;

			if (s->last_seq < s->lead) {
				/* We are missing packets */
			}
			break;

/* 		These may not exist although described in the RFC. There is no definition of the spmr struct available
		case PGM_SPMR:		Unicast upstream
			PULL(buf, spmr);
			break;
*/
		case PGM_ODATA:		/* Multicast downstream */
		case PGM_RDATA:		/* Multicast downstream */
			PULL(buf, data);

			logg(LOG_DEBUG, "%s: %cDATA SQN=%d TRAIL=%d\n", text,
				header.pgm.pgm_type == PGM_RDATA ? 'R' : 'O', ntohl(data.data_sqn), ntohl(data.data_trail));

			sqn = ntohl(data.data_sqn);

			if (!s) {
				lock();
				s = hash_find(i->pgm_tsi_hash, &tsi);
				if (!s) {
					s = calloc(1, sizeof(struct pgm_stream));
					s->tsi = tsi;
					s->i = i;
					strcpy(s->text, text);
					hash_add(i->pgm_tsi_hash, s);

					/* First message on new stream */
					s->last_seq = sqn - 1;
					s->last = s->last_seq;
					s->oldest = sqn;

					i->nr_tsi++;

					logg(LOG_NOTICE, "%s: New Stream TSI %s\n", i->text, s->text);
				}
				unlock();
			}	

			if (header.pgm.pgm_type == PGM_RDATA)
				st(c, pgm_rdata);
			else
				st(c, pgm_odata);

			if (sqn < s->last_seq) {
				st(c, pgm_dup);
				ret = false;
				logg(LOG_NOTICE, "%s: Repeated data out of Window\n", s->text);
				break;
			}

			if (sqn == s->last) {
				st(c, pgm_dup);
				ret = false;
				logg(LOG_NOTICE, "%s: Sender is duplicating traffic %d\n", s->text, sqn);
				break;
			}


			if (sqn < s->last && find_record(i, &tsi, sqn)) {
				st(c, pgm_dup);
				ret = false;
				logg(LOG_NOTICE, "%s: Repeated data in Window SQN=%d\n", s->text, sqn);
				break;
			}

			/* Move trail/lead */
			if (ntohl(data.data_trail) > s->trail)
				s->trail = ntohl(data.data_trail);

			if (sqn > s->lead)
				s->lead = sqn;

			if (pgm_mode <= pgm_passthrough) {

				if (header.pgm.pgm_type == PGM_ODATA) {
					if (sqn != s->last +1)
						logg(LOG_NOTICE, "%s: Sequence error SQN %d->SQN %d diff %d\n", s->text, s->last, sqn, sqn-s->last);
					s->last = sqn;
				}
				break;
			}

			/* This is either the next data or missing data */

			if (!add_record(buf, &tsi, sqn, buf->cur, tdsu))
				panic("PGM: SQN exists\n");

			if (sqn == s->last_seq + 1) {
				/* The next packet that we need ! */
				s->last_seq = sqn;
				forward_packet(buf, &tsi, sqn);
				deliver_in_seq(buf, &tsi, sqn);

				if (sqn == s->last + 1) {
					/* Stream without pending holes in the sequence */
					s->last = sqn;
				} else {
					/* We just filled up in a missing piece check how long our consistent history goes now */
					while (s->last_seq < s->last) {
						struct pgm_record *r = find_record(i, &tsi, s->last_seq + 1);

						if (r) {
							logg(LOG_NOTICE, "Found earlier record %d\n", s->last_seq + 1);

							deliver_in_seq(r->buf, &tsi, s->last_seq + 1);
							s->last_seq++;
						} else
							break;
					}
					/* If this was RDATA and there still is a hole then send NAK */
				}
			} else {
				logg(LOG_NOTICE, "Out of sequence sqn=%d last_seq=%d s->last=%d\n", sqn, s->last_seq, s->last);
				forward_packet(buf, &tsi, sqn);
				s->last = sqn;
				/* We have opened up some hole between s->last_seq and s->last. Could send NAK */

				/* s->last_seq ... s->last -1 is missing at this point */

				if (s->last_seq < s->trail) {
					logg(LOG_ERR, "Unrecoverable Dataloss !\n");
				} else {
					logg(LOG_NOTICE, "Nak Processing not implemented yet\n");
				}
			}

			break;

		case PGM_NAK:		/* Unicast upstream */
		case PGM_NCF:		/* Multicast downstream */
		case PGM_NNAK:		/* Unicast upstream DLR ->source */
			PULL(buf, nak);
			st(c, pgm_nak);
			logg(LOG_NOTICE, "%s: NAK/NCF/NNAK SQN=%x NLA=%s GRP_NLA=%s\n",
				text, nak.nak_sqn, inet_ntoa(nak.nak_src_nla),
				inet_ntoa(nak.nak_grp_nla));
			break;

#if 0
		/* Is POLL really used I do not know of a DLR */
		case PGM_POLL:		/* DLR downstream multicast */
			PULL(buf, poll);
			logg(LOG_NOTICE, "%s: POLL\n", s->text);
			break;

		case PGM_POLR:		/* Unicast response upstream to DLR */
			PULL(buf, polr);
			logg(LOG_NOTICE, "%s: POLR\n", s->text);
			break;
#endif
		/* Not RFC compliant but it seems to be used sometimes */
		case PGM_ACK:		/* Unicast upstream */
			PULL(buf, ack);
			st(c, pgm_ack);
			logg(LOG_NOTICE, "%s: ACK RX_MAX=%x BITMAP=%x\n", text, ntohl(ack.ack_rx_max), ack.ack_bitmap);
			break;

		default:
			logg(LOG_NOTICE, "%s: Invalid PGM type=%x. Packet Skipped.\n", text, header.pgm.pgm_type);
			break;
	}

	options_start = buf->cur;
	if (header.pgm.pgm_options & 0x1) {
		bool last = false;

		do {
			struct pgm_opt_header opt;
			struct pgm_opt_length length;
			struct pgm_opt_fragment fragment;
			struct pgm_opt_nak_list nak_list;
			struct pgm_opt_join join;
			struct pgm_opt_redirect redirect;
			struct pgm_opt_fin fin;
			struct pgm_opt_syn syn;
			struct pgm_opt_rst rst;
			uint8_t *start_option = buf->cur;

			PULL(buf, opt);

			if (opt.opt_length == 0) {
				logg(LOG_NOTICE, "Invalid option length zero\n");
				break;
			}

			last = opt.opt_type & PGM_OPT_END;
			switch (opt.opt_type & PGM_OPT_MASK) {
				case PGM_OPT_LENGTH:
					buf->cur = start_option;
					PULL(buf, length);
					total_opt_length = ntohs(length.opt_total_length);
					break;
				case PGM_OPT_FRAGMENT:
					PULL(buf, fragment);
					logg(LOG_INFO, "%s: OPT Fragment SQN=%x offset=%d len=%d\n", text,
							ntohl(fragment.opt_sqn), ntohl(fragment.opt_frag_off), ntohl(fragment.opt_frag_len));
					break;
				case PGM_OPT_NAK_LIST:
					PULL(buf, nak_list);
					logg(LOG_INFO, "%s: OPT NAK list #%d\n", text, (opt.opt_length - 1) /4 );

					break;
				case PGM_OPT_JOIN:
					PULL(buf, join);
					logg(LOG_INFO, "%s: OPT Join MIN SQN=%d\n",
								text, ntohl(join.opt_join_min));
					break;
				case PGM_OPT_REDIRECT:
					PULL(buf, redirect);

					logg(LOG_INFO, "%s: OPT Redirect NLA=%s\n", text, inet_ntoa(redirect.opt_nla));
					break;

				/* Not sure if these options are in use.  They are mostly not necessary (?) */
				case PGM_OPT_SYN:
					PULL(buf, syn);
					logg(LOG_INFO, "%s: OPT SYN\n", text);
					break;
				case PGM_OPT_FIN:
					PULL(buf, fin);
					logg(LOG_NOTICE, "%s: End of Stream TSI %s\n", i->text, text);
					if (s) {
						/* Remove all records */
						hash_del(i->pgm_tsi_hash, &tsi);
						free(s);
						i->nr_tsi--;
						s = NULL;
					}
					break;
				case PGM_OPT_RST:
					PULL(buf, rst);
					logg(LOG_NOTICE, "%s: OPT RST\n", text);
					break;

				case 0x21:
				case 0x22:
				case 0x23:
				case 0x24:
					break;

				/* NAK Intervals */
				case PGM_OPT_NAK_BO_IVL:
				case PGM_OPT_NAK_BO_RNG:

				/* NLA redirection */
				case PGM_OPT_PATH_NLA:

				/* Broken Multicast ??? */
				case PGM_OPT_NBR_UNREACH:

				case PGM_OPT_INVALID:

				/* Congestion "Control" and avoidance. Traffic load feedback */
				case PGM_OPT_CR:
				case PGM_OPT_CRQST:

				/* Forward Error correction.... How would this work ??? */
				case PGM_OPT_PARITY_PRM:
				case PGM_OPT_PARITY_GRP:
				case PGM_OPT_CURR_TGSIZE:

				/* Extensions by PGMCC */
				case PGM_OPT_PGMCC_DATA:
				case PGM_OPT_PGMCC_FEEDBACK:

				default: 
					logg(LOG_NOTICE, "%s: Invalid PGM option=%x Option Skipped. D=%s\n",
						text, opt.opt_type & PGM_OPT_MASK,
						_hexbytes(start_option, opt.opt_length)); 
					break;
			}
			buf->cur = start_option + opt.opt_length;
		} while (!last);

		if (total_opt_length != buf->cur - options_start)
			logg(LOG_NOTICE, "%s: Option length mismatch. Expected %d but it is %ld\n", s->text, total_opt_length, buf->cur - options_start);
	}

	return ret;
}

#if 0
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
#endif

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
static struct endpoint *buf_to_ep(struct buf *buf, struct in_addr addr)
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
static void learn_source_address(struct buf *buf)
{
	struct in_addr addr = ip_none;

	if (!unicast)	/* If unicast is not enabled then dont bother to gather addresses */
		return;

	if (buf->ip_valid)
		addr.s_addr = buf->ip.saddr;

	buf->source_ep = buf_to_ep(buf, addr);
}

/* Delayed packet send due to traffic shaping */
static void delayed_send(void *private)
{
	struct buf *buf = private;
	struct rdma_channel *c = buf->c;
	struct mc_interface *mi = buf->mi;
	int ret;

	mi->delayed++;
	mi->pending--;
	if (!mi->pending) {
		/*
		 * The last pending packet so we are off rate limiting.
		 */
		c->i->mc_rate_limited--;
		mi->burst = 0;
		mi->last_sent = timestamp();
	}

	ret = send_to(c, buf->cur, buf->end - buf->cur, &mi->ai, buf->imm_valid, buf->imm, buf);
	if (!ret)
		st(c, packets_bridged);
	buf->mi = NULL;
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
	struct ib_addr *dgid = (struct ib_addr *)&buf->grh.dgid.raw;
	struct in_addr dest_addr;
	int ret;

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

	logg(LOG_DEBUG, "From %s: MC=%s\n", c->text, inet_ntoa(dest_addr));

	if (!m) {
		logg(LOG_INFO, "Discard Packet: Multicast group %s not found\n",
			inet_ntoa(dest_addr));
		goto invalid_packet;
	}

	if (m->interface[in].sendonly) {

		logg(LOG_INFO, "Discard Packet: Received data from Sendonly MC group %s from %s\n",
			m->text, c->text);
		goto invalid_packet;
	}

	if (!buf->ip_valid) {
		unsigned char *mgid = buf->grh.dgid.raw;
		unsigned short signature = ntohs(*(unsigned short*)(mgid + 2));

		if (mgid[0] != 0xff) {
			logg(LOG_INFO, "Discard Packet: Not multicast. MGID=%s/%s\n",
					inet6_ntoa(mgid), c->text);
			goto invalid_packet;
		}

		if (memcmp(&buf->grh.sgid, &c->i->gid, sizeof(union ibv_gid)) == 0) {

			logg(LOG_DEBUG, "Discard Packet: Loopback from this host. MGID=%s/%s\n",
				inet6_ntoa(mgid), c->text);

			goto invalid_packet;
		}

		if (m->mgid_mode->signature) {
			if (signature == m->mgid_mode->signature) {
//				if (m->mgid_mode->port)
//					port = ntohs(*((unsigned short *)(mgid + 10)));
			} else {
				logg(LOG_INFO, "Discard Packet: MGID multicast signature(%x)  mismatch. MGID=%s\n",
						signature, inet6_ntoa(mgid));
				goto invalid_packet;
			}
		}

	} else { /* ROCE */
		if (buf->ip.saddr == c->i->if_addr.sin_addr.s_addr) {
			logg(LOG_DEBUG, "Discard Packet: Loopback from this host. %s/%s\n",
				inet_ntoa(c->i->if_addr.sin_addr), c->text);
			goto invalid_packet;
		}
	}

	if (m->beacon) {
		beacon_received(buf);
		return;
	}

	if (pgm_mode != pgm_none) {
		uint8_t *saved = buf->cur;
		if (!pgm_process(c, m, buf))
			return;
		buf->cur = saved;
	}

	if (!bridging)
		return;

	if (drop_packets && (c->stats[packets_received] % drop_packets) == drop_packets - 1)
		return;

	struct mc_interface *mi = m->interface  + (in ^ 1);
	struct rdma_channel *ch_out = i2r[in ^ 1].multicast;

	if (mi->packet_time) {
		uint64_t t;

		if (mi->pending) {
			/* Packet must be sent after the last delayed one */
			mi->last_delayed += mi->packet_time;
delayed_packet:
			mi->pending++;
			get_buf(buf);	/* Dont free this buffer */
			buf->c = ch_out;
			buf->w = NULL;
			buf->mi = mi;
			add_event(mi->last_delayed, delayed_send, buf, "Delayed Send");
			return;
		}

	       	/* No pending I/O */
		t = timestamp();

		if (mi->last_sent && t < mi->last_sent + mi->packet_time) {

			/* Packet spacing too tight */
			mi->burst++;
			if (mi->burst > mi->max_burst) {
				c->i->mc_rate_limited++;
				mi->last_delayed = mi->last_sent + mi->packet_time;
				goto delayed_packet;
			}

		} else
			/* End of Burst */
			mi->burst = 0;

		/* Packet will be sent now. Record timestamp */
		mi->last_sent = t;
	}

	if (!mi->ai.ah)		/* After a join it may take awhile for the ah pointer to propagate */
 		sleep(1);
	get_buf(buf);	/* Packet will not be freed on return from this function */
 
	ret = send_to(ch_out, buf->cur, buf->end - buf->cur, &mi->ai, buf->imm_valid, buf->imm, buf);
 	if (ret)
		return;

	st(c, packets_bridged);
	return;

invalid_packet:
	st(c, packets_invalid);
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
}

/* Figure out what to do with the packet we got */
static void receive_main(struct buf *buf)
{
	struct rdma_channel *c = buf->c;

	if (buf->grh_valid) {
		recv_buf_grh(c, buf);
		return;
	}

	logg(LOG_INFO, "No GRH on %s. Packet discarded: %s.\n", c->text, payload_dump(buf->cur));

	st(c, packets_invalid);
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
		struct in_addr addr;

		memcpy(mac, buf->cur, arp.ar_hln);
		memcpy(&addr, buf->cur + arp.ar_hln, sizeof(struct in_addr));

		if (!valid_addr(i, addr)) {
			logg(LOG_NOTICE, "ARP REPLY: Invalid %sIP=%s MAC=%s\n",
				j ? "Dest" : " Source",
			       inet_ntoa(addr),
				hexbytes(mac, arp.ar_hln,':'));
			continue;
		}

		ep = hash_find(i->ep, i2r + ROCE == i ? (void *)&addr : (void *)(lids + j));
		if (ep) {
			if (!ep->addr.s_addr) {
				lock();

				ep = hash_find(i->ep, i2r + ROCE == i ? (void *)&addr : (void *)(lids + j));
				if (!ep->addr.s_addr) {

					ep->addr = addr;
					hash_add(i->ip_to_ep, ep);
				}

				unlock();

			} else if(ep->addr.s_addr != addr.s_addr)

				return "IP address for MAC changed!";

			continue;
		}

		buf->w->slid = lids[j];
		ep = buf_to_ep(buf, addr);
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
	uint32_t source_qp;
	struct endpoint *source;
	struct endpoint *dest;
};

static struct hash *sidrs;

static void sidr_state_init(void)
{
	if (sizeof(struct umad_hdr) != 3 * 8)
		panic("umad_hdr size mismatch\n");

	if (sizeof(struct sidr_req) != 2 * 8)
		panic("sidr_req size mismatch\n");

	if (sizeof(struct sidr_rep) != 3* 8 + 72 + 136)
		panic("sidr_rep size mismatch\n");

	sidrs = hash_create(offsetof(struct sidr_state, request_id), sizeof(uint32_t));
}

/*
 * Send a 256 byte MAD packet to QP1 on an endpoint
 * What to send is taken directly from the packet that came in.
 */
static void send_mad(struct endpoint *e, struct buf *buf, void *mad_pos)
{
	buf->cur = mad_pos;
	buf->end = mad_pos + 256;

	send_ud(e->i->qp1, buf, e->ah, 1, IB_DEFAULT_QP1_QKEY);
}

static const char *sidr_req(struct buf *buf, void *mad_pos)
{
	struct sidr_state *ss = malloc(sizeof(struct sidr_state));
	struct sidr_req *sr = (void *)buf->cur;
	struct cma_hdr *ch = (void *)(buf->cur + sizeof(struct sidr_req)); 
	struct i2r_interface *source_i = buf->c->i;
	struct i2r_interface *dest_i = i2r + ((source_i - i2r) ^ 1);
	struct in_addr dest;
	struct in_addr source;
	const char *reason = NULL;

	if (ch->cma_version != CMA_VERSION) {
		reason = "SIDR REQ: Unsupported CMA version";
		goto no_cma;
	}

	if (cma_get_ip_ver(ch) != 4) {
		reason = "SIDR REQ: Only IPv4 private data supported";
		goto no_cma;
	}

	ss->source = buf->source_ep;
	ss->source_qp = ntohl(ch->src_addr.ip4.sess_qpn);
	ss->request_id = sr->request_id;
	/* Setup the reply so that it will come back to our "QP1" and not to the kernel QP1 */


no_cma:
	/* Establish Destination */
	if (buf->ip_valid) {	/* ROCE */

		dest.s_addr = buf->ip.daddr;

	} else { /* Infiniband */

		if (reason)		/* CMA is required for Infiniband */
			goto err;
	
		source.s_addr = ch->src_addr.ip4.addr;
		dest.s_addr = ch->dst_addr.ip4.addr;

		if (dest.s_addr && !valid_addr(dest_i, dest)) {
			reason = "SIDR REQ: Invalid Destination address";
			goto err;
		}

		lock();

		if (valid_addr(source_i, source) && ss->source->addr.s_addr == 0) {
			struct endpoint *sep = hash_find(source_i->ip_to_ep, &source);

			if (sep) {
				char b[40];
				struct endpoint *tep;

				strcpy(b, inet_ntoa(ss->source->addr));

				logg(LOG_NOTICE, "SIDR_REQ: Two endpoints claim the same IP : EP1(%p by ip)= (%s,%x) EP2(from receive_raw) = (%p %s,%x)\n",
					sep, inet_ntoa(sep->addr), sep->lid, ss->source, b, ss->source->lid);

				tep = hash_find(source_i->ep, &ss->source->lid);
				if (tep)
					logg(LOG_NOTICE, "SIDR REQ lookup by lid = %p %s, %x\n", tep, tep ? inet_ntoa(tep->addr) : "--", tep ? tep->lid : 0);
				else
					logg(LOG_NOTICE, "SIDR REQ nothing found when looking up by lid =%x\n", ss->source->lid); 

				if (ss->source->forwards)
					remove_forwards(ss->source);

				logg(LOG_WARNING, "SIDR REQ: Removing EP=%p\n", ss->source);
				hash_del(source_i->ep, ss->source);
				free(ss->source);
				ss->source = sep;

			} else {
				struct ibv_wc *w = buf->w;
			
				ss->source->addr = source;
				hash_add(source_i->ip_to_ep, ss->source);
				logg(LOG_NOTICE, "SIDR REQ: Private data supplied IP address %s to Endpoint at LID %x\n",
					inet_ntoa(source), w->slid);
			}
		}

		unlock();
	}

	ss->dest = ip_to_ep(dest_i, dest);
	if (!ss->dest) {
		reason = "Cannot forward SIDR REQ since the address is unknown";
		goto err;
	}

	lock();

	if (hash_find(sidrs, &ss->request_id)) {
		logg(LOG_WARNING, "SIDR_REQ: Removed earlier pending request\n");
		hash_del(sidrs, &ss->request_id);
	}

	if (bridging) {

		hash_add(sidrs, ss);
		unlock();

		/* Source QPN is not valid for target network use the QP number of the UD QP */
		ch->src_addr.ip4.sess_qpn = htonl(dest_i->ud->qp->qp_num);
		/* Ensure the SIDR_REP gets back to our QP1 */
		ch->src_addr.ip4.sidr_qpn = ntohl(dest_i->qp1->qp->qp_num);

		send_mad(ss->dest, buf, mad_pos);
		
	} else {
		unlock();

		free(ss);
	}


	return NULL;

err:
	free(ss);
	return reason;
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
static const char * sidr_rep(struct buf *buf, void *mad_pos, struct umad_hdr *umad)
{
	struct sidr_rep *sr = (void *)buf->cur;
	struct sidr_state *ss;
	uint32_t qpn_word = ntohl(sr->qpn);
	uint32_t sr_qpn = qpn_word >> 8;
	uint32_t sr_qkey = ntohl(sr->q_key);

	
	logg(LOG_NOTICE, "SIDR_REP: %s method=%s status=%s attr_id=%s attr_mod=%x ServiceId=%lx ReqId=%x Q_KEY=%x QPN=%d Status=%x\n",
		buf->c->text, umad_method_str(umad->mgmt_class, umad->method),
		umad_common_mad_status_str(umad->status),
		umad_attribute_str(umad->mgmt_class, umad->attr_id), ntohl(umad->attr_mod),
		be64toh(sr->service_id), ntohl(sr->request_id), sr_qkey, sr_qpn, sr->status);

	if (sr->status)
		return "SIDR_REP: Request rejected";

	if (sr_qkey != RDMA_UDP_QKEY)
		logg(LOG_WARNING, "%s: Nonstandard QKEY = %x\n", buf->c->text, sr_qkey);

	lock();

	ss = hash_find(sidrs, &sr->request_id);
	if (!ss) {
		unlock();
		return "SDIR_REP: Cannot find outstanding SIDR_REQ";
	}

	hash_del(sidrs, ss);

	unlock();

	if (ss->dest != buf->source_ep)
		panic("dest not the buf destination\n");

	lock();

	if (find_forward(ss->source, (buf->c->i == i2r + INFINIBAND) ? NULL : ss->dest, ss->source_qp)) {
		unlock();
		return "Ignoring SIDR REQ since one is already pending";
	}

	add_forward(ss->source, ss->source_qp, ss->dest, sr_qpn, sr_qkey);

	if (ss->source_qp)
		/* Add the reverse forward if we have the source_qp number */
		add_forward(ss->dest, sr_qpn, ss->source, ss->source_qp, sr_qkey);

	unlock();

	qpn_word = (ss->source->i->ud->qp->qp_num << 8) | (qpn_word & 0xff);
	sr->qpn = htonl(qpn_word);

	if (bridging)
		send_mad(ss->source, buf, mad_pos);

	free(ss);
	return NULL;
}

static void receive_raw(struct buf *buf)
{
	struct rdma_channel *c = buf->c;
	struct i2r_interface *i = c->i;
	struct ibv_wc *w = buf->w;
	uint16_t lids[2] = { 0, 0 };
	unsigned short dlid = 0;
	void *mad_pos;
	const char *reason;
	int len = w->byte_len;
	struct bth bth = { };
	struct deth deth;	/* BTH subheader */
	char header[200] = "";
	struct udphdr udp;
	struct umad_hdr umad;

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
			reason = "-Unicast Loopback";
			goto discard;
		}

		buf->source_ep = buf_to_ep(buf, ip_none);

		snprintf(header, sizeof(header), "SLID=%x/%s DLID=%x SL=%d LVer=%d",
			w->slid, inet_ntoa(buf->source_ep->addr), dlid, w->sl, ib_get_lver(ih));

		if (ib_get_lnh(ih) < 2) {
			reason = "IP v4/v6 packet";
			goto discard;
		}

		if (ib_get_lnh(ih) == 3) {
			char *xbuf2 = alloca(40);

			PULL(buf, buf->grh);
			buf->grh_valid = true;

			snprintf(header + strlen(header), 100-strlen(header), " SGID=%s DGID=%s",
				inet_ntop(AF_INET6, &buf->grh.sgid, xbuf2, INET6_ADDRSTRLEN),
				inet6_ntoa(&buf->grh.dgid));

			if (buf->source_ep->gid.global.interface_id == 0) /* No GID yet ? */
				memcpy(&buf->source_ep->gid, &buf->grh.sgid, sizeof(union ibv_gid));

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
		struct ether_header e;

		PULL(buf, e);

		ethertype = ntohs(e.ether_type);
		if (ethertype < 0x600) {
			len = ethertype;
			ethertype = ETHERTYPE_IP;
		}

		if (memcmp(i->if_mac, e.ether_shost, ETH_ALEN) == 0) {

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
				return;

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

			if (!valid_addr(i, source)) {
				reason = "-Invalid source IP";
				goto discard;
			}

			buf->source_ep = buf_to_ep(buf, source);

			if (buf->ip.protocol != IPPROTO_UDP) {

				reason = "-Only UDP packets";
				goto discard;

			}

			if (e.ether_dhost[0] & 0x1) {
				reason = "-Multicast on RAW channel";
				goto discard;
			}

			if (!buf->ip_csum_ok)
				logg(LOG_NOTICE, "TCP/UDP CSUM not valid on raw RDMA channel %s\n", c->text);

			PULL(buf, udp);

			if (ntohs(udp.dest) != ROCE_PORT) {

				reason = "Not the ROCE UDP port";
				goto discard;
			}
			break;

		default:
			reason = "-Not IP traffic";
			goto discard;
		}
	}

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
		struct immdt immdt;	/* BTH subheader */

		PULL(buf, immdt);
		buf->imm_valid = true;
		buf->imm = immdt.imm;
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

		return;
	}

	mad_pos = buf->cur;

	/* Start MAD payload */
	PULL(buf, umad);

	logg(LOG_NOTICE, "RAW: QP1 packet %s from %s LID %x LRH_LEN=%u WC_LEN=%u SQP=%x DQP=%x method=%s status=%s attr_id=%s\n", i->text,
		inet_ntoa(buf->source_ep->addr), buf->source_ep->lid, len, w->byte_len,
		 w->src_qp, __bth_qpn(&bth),
 		umad_method_str(umad.mgmt_class, umad.method),
		umad_common_mad_status_str(umad.status),
		umad_attribute_str(umad.mgmt_class, umad.attr_id));

	if (umad.mgmt_class != UMAD_CLASS_CM) {
		reason = "-Only CM Class MADs are supported";
		goto discard;
	}

	if (ntohs(umad.attr_id) == UMAD_CM_ATTR_SIDR_REQ) {
		reason = sidr_req(buf, mad_pos);
		if (reason)
			goto discard;
		return;
	}

	if (ntohs(umad.attr_id) == UMAD_CM_ATTR_SIDR_REP) {
		reason = sidr_rep(buf, mad_pos, &umad);
		if (reason)
			goto discard;
		return;
	}

	reason = "Only SIDR_REQ";

discard:
	if (reason[0] != '-') 
		logg(LOG_INFO, "Discard %s %s: %s Length=%u/prot=%u/pos=%lu\n",
			c->text, reason, header,
			buf->w->byte_len, len, buf->cur - buf->raw);

	st(c, packets_invalid);
}

/* Unicast packet reception */
static void receive_ud(struct buf *buf)
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
		buf->imm = htonl(f->dest->i->ud->qp->qp_num);

	logg(LOG_NOTICE, "receive_ud %s Packet len=%u 0x%x lid=%d forwarded to %s %s:0x%x lid=%d qkey=%x\n", c->text,
			w->byte_len, w->src_qp, e->lid, dest_i->ud->text, inet_ntoa(f->dest->addr), f->dest_qp, f->dest->lid, f->dest_qkey);

	send_ud(dest_i->ud, buf, f->dest->ah, f->dest_qp, f->dest_qkey);
 	return;
 
discard:
	logg(LOG_NOTICE, "receive_ud:Discard %s %s LEN=%ld\n", c->text, reason, buf->end - buf->cur);
	st(c, packets_invalid);
}

/*
 * Receive Channel mostly used to send QP1 traffic.
 * But it can also be used to receive QP1 traffic when redirected to a gateway
 */
static void receive_qp1(struct buf *buf)
{
	const char *reason;
	struct ibv_wc *w = buf->w;
	void *mad_pos;
	struct umad_hdr umad;

	learn_source_address(buf);

	if (!buf->grh_valid)
		/* Even if there is no GRH there is space reserved at the beginning for UD packets */
		buf->cur += 40;

	mad_pos = buf->cur;

	PULL(buf, umad);

	logg(LOG_NOTICE, "QP1 packet %s from %s LID %x WC_LEN=%u SQP=%x method=%s status=%s attr_id=%s\n", buf->c->text,
		inet_ntoa(buf->source_ep->addr), buf->source_ep->lid, w->byte_len,
		w->src_qp, umad_method_str(umad.mgmt_class, umad.method),
		umad_common_mad_status_str(umad.status),
		umad_attribute_str(umad.mgmt_class, umad.attr_id));

	if (umad.mgmt_class != UMAD_CLASS_CM) {
		reason = "-Only CM Class MADs are supported";
		goto discard;
	}

	if (ntohs(umad.attr_id) == UMAD_CM_ATTR_SIDR_REQ) {
		reason = sidr_req(buf, mad_pos);
		if (reason)
			goto discard;
		return;
	}

	if (ntohs(umad.attr_id) == UMAD_CM_ATTR_SIDR_REP) {
		reason = sidr_rep(buf, mad_pos, &umad);
		if (reason)
			goto discard;
		return;
	}

	reason = "Only SIDR_REQ/REP supporte on QP1";

discard:
	if (reason[0] != '-') 
		logg(LOG_INFO, "QP1: Discard %s %s: Length=%u/pos=%lu\n",
			buf->c->text, reason, w->byte_len, buf->cur - buf->raw);

	st(buf->c, packets_invalid);
}

static void reset_flags(struct buf *buf)
{
	memset(&buf->ip_valid, 0, (void *)&buf->ip_csum_ok - (void *)&buf->ip_valid);
}

static void process_cqes(struct rdma_channel *c, struct ibv_wc *wc, unsigned cqs)
{
	unsigned j;

	if (cqs > c->cq_high)
		c->cq_high = cqs;

	for (j = 0; j < cqs; j++) {
		struct ibv_wc *w = wc + j;
		struct buf *buf = (struct buf *)w->wr_id;

		if (w->status == IBV_WC_SUCCESS && w->opcode == IBV_WC_RECV) {

			c->active_receive_buffers--;
			st(c, packets_received);

			if (c != buf->c) {
				logg(LOG_CRIT, "%s: RDMA Channel mismatch CQE is from %s.\n", c->text, buf->c->text);
				st(c, packets_invalid);
				free(buf);
				continue;
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
				if (c->i == i2r + ROCE) {
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
			put_buf(buf);

		} else {
			if (w->status == IBV_WC_SUCCESS && w->opcode == IBV_WC_SEND) {
				c->active_send_buffers--;
				/* Completion entry */
				st(c, packets_sent);
				put_buf(buf);
			} else
				logg(LOG_NOTICE, "Strange CQ Entry %d/%d: Status:%x Opcode:%x Len:%u QP=%x SRC_QP=%x Flags=%x\n",
					j, cqs, w->status, w->opcode, w->byte_len, w->qp_num, w->src_qp, w->wc_flags);

		}
	}

	/* Since we freed some buffers up we may be able to post more of them */
	post_receive(c);
}

static void handle_comp_event(void *private)
{
	struct ibv_comp_channel *events = private;
	struct rdma_channel *c;
	struct ibv_cq *cq;
	int cqs;
	struct ibv_wc wc[10];

	if (ibv_get_cq_event(events, &cq, (void **)&c)) {
		logg(LOG_ERR, "ibv_get_cq_event failed with %s\n", errname());
		return;
	}

	ibv_ack_cq_events(cq, 1);
	if (ibv_req_notify_cq(cq, 0))
		panic("ibv_req_notify_cq: Failed\n");

	if (!c || c->cq != cq)
       		panic("Invalid channel in handle_comp_event() %p\n", c);

	/* Retrieve completion events and process incoming data */
	cqs = ibv_poll_cq(cq, 10, wc);
	if (cqs < 0) {
		logg(LOG_WARNING, "CQ polling failed with: %s on %s\n",
			errname(), c->text);
		return;
	}

	if (cqs)
		process_cqes(c, wc, cqs);
}

/* Special handling using raw socket */
static void handle_receive_packet(void *private)
{
	struct rdma_channel *c = private;
	struct ibv_wc w = {};
	unsigned ethertype;
	ssize_t len;
	struct buf *buf = alloc_buffer(c);
	struct ether_header e;

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
	PULL(buf, e);

	ethertype = ntohs(e.ether_type);
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
	put_buf(buf);
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

	n += sprintf(b + n, "\nChannel %s(%s):\n", interface, type);

	for(j =0; j < nr_stats; j++)
		if (c->stats[j]) {
			n += sprintf(b + n, "%s=%u\n", stats_text[j], c->stats[j]);
	}
	return n;
}

static unsigned show_interfaces(char *b)
{
	struct i2r_interface *i;
	int n = 0;


	for(i = i2r; i < i2r + NR_INTERFACES; i++) {

		if (i->multicast)
			n += channel_stats(b + n, i->multicast, i->text, "Multicast");
		if (i->ud)
			n += channel_stats(b + n, i->ud, i->text, "UD");
		if (i->raw)
			n += channel_stats(b + n, i->raw, i->text, "Raw");

	}
	return n;
}

static unsigned show_multicast(char *b)
{
	int n = 0;
	int free = 0;
	struct buf *buf;
	struct mc *m;

	for(buf = buffers; buf < buffers + nr_buffers; buf++)
		if (buf->free)
		       free++;

	n+= sprintf(b + n, "Multicast: Active=%u NR=%u Max=%u\nBuffers: Active=%u Total=%u\n\n",
		active_mc, nr_mc, MAX_MC, nr_buffers-free , nr_buffers);

	for(m = mcs; m < mcs + nr_mc; m++)

		n += sprintf(n + b, "%s INFINIBAND: %s %s%s P%d ROCE: %s %s P%d\n",
			inet_ntoa(m->addr),
			mc_text[m->interface[INFINIBAND].status],
			m->interface[INFINIBAND].sendonly ? "Sendonly " : "",
			m->mgid_mode->id,
			m->interface[INFINIBAND].pending,
			mc_text[m->interface[ROCE].status],
			m->interface[ROCE].sendonly ? "Sendonly" : "",
			m->interface[ROCE].pending);
	return n;
}

static unsigned show_endpoints(char *b)
{
	struct i2r_interface *i;
	int n = 0;
	struct buf *buf;

	for(i = i2r; i < i2r + NR_INTERFACES; i++)
		if (i->context && i->ep) {
		struct endpoint *e[20];
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
						inet6_ntoa(&ep->gid));

				for (f = ep->forwards; f; f = f->next) {
					n += snprintf(b + n, sizeof(buf) - n, " Q%d->%sQ%d",
					      f->source_qp, inet_ntoa(f->dest->addr), f->dest_qp);
				}
			}
			offset += 20;
		}
	}
	return n;
}

static void status_write(void *private)
{
	static char b[10000];
	int n = 0;
	int fd = status_fd;

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

	n+= show_multicast(n + b);
	n+= show_interfaces(n + b);
	n+= show_endpoints(n+b);
	
	n += sprintf(n + b, "\n\n\n\n\n\n\n\n");
	if (write(fd, b, n) < 0)
		logg(LOG_ERR, "Status write failed with %s\n", errname());

	if (update_requested) {
		close(fd);
		update_requested = false;
	}
	add_event(timestamp() + seconds(60), status_write, NULL,  "Status File Write");
}

#define BEACON_MCS 500

struct beacon_mc {
	struct in_addr addr;
	uint16_t port;
};

/*
 * Beacon processing
 */
struct beacon_info {
	unsigned long signature;
	char version[10];
	bool infiniband;
	uint16_t beacon_port;
	struct in_addr beacon_mc;
	uint64_t t;
	unsigned gateway_qp;
	struct in_addr bridge_addr;		/* Where is the local bridge */
	struct in_addr to_addr;			/* To which address is it bridging */
	unsigned nr_mc;				/* Active Multicast */
	unsigned nr_tsi;			/* Active TSIs */
	struct beacon_mc mc[500];
};

struct mc *beacon_mc;		/* == NULL if unicast */
struct sockaddr_in *beacon_sin;

static void prep_beacon_struct(struct i2r_interface *i, struct beacon_info *b)
{
	enum interfaces in = i - i2r;
	struct mc *m;

	b->signature = BEACON_SIGNATURE;
	memcpy(b->version, VERSION, 10);
	b->infiniband = in == INFINIBAND;
	b->beacon_port = beacon_sin->sin_port;
	b->beacon_mc = beacon_sin->sin_addr;
	b->bridge_addr = i2r[in].if_addr.sin_addr;
	b->to_addr = i2r[in^1].if_addr.sin_addr;
	b->nr_mc = nr_mc;
	b->nr_tsi = i2r[INFINIBAND].nr_tsi;
	if (b->nr_tsi < i2r[ROCE].nr_tsi)
		b->nr_tsi = i2r[ROCE].nr_tsi;

	for(m = mcs; m < mcs + nr_mc; m++) {
		b->mc[m - mcs].addr = m->addr;
		b->mc[m - mcs].port = m->port;
	}
}

static void beacon_received(struct buf *buf)
{
	struct beacon_info *b = (struct beacon_info *)buf->cur;
	char bridge[40];
	uint64_t diff;

	if (b->signature != BEACON_SIGNATURE) {
		logg(LOG_ERR, "Received non beacon traffic on beacon MC group %s\n", beacon_mc->text);
		return;
	}

	now = timestamp();
	strcpy(bridge, inet_ntoa(b->bridge_addr));
	diff = b->t - now;

	logg(LOG_NOTICE, "Received Beacon on %s Version %s Bridge=%s(%s), BridgeTo=%s MC groups=%u, TSIs=%d. Latency %ld ns GatewayQP=%u\n",
		beacon_mc->text, b->version, bridge, b->infiniband ? "Infiniband" : "ROCE",
		inet_ntoa(b->to_addr), b->nr_mc, b->nr_tsi, diff, b->gateway_qp);
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

static void beacon_send(void *private)
{
	struct beacon_info b;
	struct buf *buf;

	if (beacon_mc) {
		int in;

		for(in = 0; in < NR_INTERFACES; in++) {
			struct i2r_interface *i = i2r + in;
			prep_beacon_struct(i, &b);
			b.t = now = timestamp();


			if (i->context && beacon_mc->interface[in].status == MC_JOINED) {
				if (sizeof(b) > MAX_INLINE_DATA) {
					buf = alloc_buffer(i->multicast);
					memcpy(buf->raw, &b, sizeof(b));
					send_to(i->multicast, buf, sizeof(b), &beacon_mc->interface[in].ai, false, 0, buf);
				} else
					send_inline(i->multicast, &b, sizeof(b), &beacon_mc->interface[in].ai, false, 0);
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
		prep_beacon_struct(i, &b);
		memcpy(buf->raw, &b, sizeof(b));

		reset_flags(buf);
		buf->cur = buf->raw;
		buf->end = buf->cur + sizeof(b);

		send_buf_to(i, buf, beacon_sin);

	}
	add_event(timestamp() + seconds(10), beacon_send, NULL, "Send Beacon");
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
	add_event(timestamp() + ONE_SECOND, beacon_send, NULL, "Send Beacon");
}

/* Events are timed according to nanoseconds in the current epoch */
struct timed_event {
	uint64_t time;		/* When should it occur */
	event_callback *callback;	/* function to run */
	void *private;
	struct timed_event *next;	/* The following event */
	const char *text;
};

/* Event queues for each of the threads */
thread_local static struct timed_event *next_event;

static void add_event(uint64_t time, event_callback *callback, void *private, const char *text)
{
	struct timed_event *t;
	struct timed_event *prior = NULL;
	struct timed_event *new_event;

	new_event = calloc(1, sizeof(struct timed_event));
	new_event->time = time;
	new_event->callback = callback;
	new_event->private = private;
	new_event->text = text;

	for(t = next_event; t && time > t->time; t = t->next)
		prior = t;

	new_event->next = t;

	if (prior)
		prior->next = new_event;
	else
		next_event = new_event;
}

static int64_t time_to_next_event(void)
{
	if (next_event)
		return (long)next_event->time - (long)timestamp();
	else
		return 0;
}

/*
 * Run the next event if availabe and return the time till the next event
 * or 0 if there is none
 */
static uint64_t run_events(void)
{
	now = timestamp();
	while (next_event) {
		struct timed_event *te = next_event;
		uint64_t old_now;

		if (te->time > now + ONE_MICROSECOND)
			return te->time - now;
	
		/* Time is up for an event */
		next_event = te->next;
		te->callback(te->private);
	
		if (latency) {
			old_now = now;
			now = timestamp();
			if (now - old_now > ONE_MILLISECOND)
				logg(LOG_ERR, "Callback %s took %ld nanoseconds which is longer than a millisecond\n",
					te->text, now-old_now);
		}

		free(te);
	}
	return 0;
}


static void check_joins(void *private)
{
	struct i2r_interface *i;

	/* Maintenance tasks */
	if (nr_mc > active_mc) {
		join_processing();
		add_event(timestamp() + ONE_SECOND, check_joins, NULL, "Check Multicast Joins");
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

static void calculate_pps_channel(struct rdma_channel *c)
{
	if (c->last_snapshot) {
		uint64_t tdiff = now - c->last_snapshot;

		c->pps_in = seconds(c->stats[packets_received] - c->last_received) / tdiff;
		c->pps_out = seconds(c->stats[packets_sent] - c->last_sent) / tdiff;

		if (c->pps_in > c->max_pps_in)
			c->max_pps_in = c->pps_in;

		if (c->pps_out > c->max_pps_out)
			c->max_pps_out = c->pps_out;

	}
	c->last_received = c->stats[packets_received];
	c->last_sent = c->stats[packets_sent];
	c->last_snapshot = now;
}

static void calculate_pps(void *private)
{
	for(struct i2r_interface *i = i2r; i < i2r + NR_INTERFACES; i++)
	if (i->context)
	{
		if (i->multicast)
			calculate_pps_channel(i->multicast);

		if (i->ud)
			calculate_pps_channel(i->ud);
	}
	add_event(now + seconds(stat_interval), calculate_pps, NULL, "pps calculation");
}

static void brief_status(void)
{
	char buf[100];
	char buf2[150];
	char counts[200];

	unsigned n = 0;
	const char *events;

	for(struct timed_event *z = next_event; z; z = z->next)
		n += sprintf(buf + n, "%ldms,", (z->time - timestamp()) / ONE_MILLISECOND);

	if (n > 0)
		buf[n -1] = 0;
	else
		buf[0] = 0;

	if (n == 0) {
		events = "No upcoming events";
	} else {
		snprintf(buf2, sizeof(buf2), "Events in %s", buf);
		events = buf2;
	}

	n = 0;
	for(struct i2r_interface *i = i2r; i < i2r + NR_INTERFACES;i++)
      	   if (i->context)	{
		n+= sprintf(counts + n, "%s(MC %d/%d",
			i->text,
			i->multicast->stats[packets_received],
			i->multicast->stats[packets_sent]);

		if (i->mc_rate_limited)
			n+= sprintf(counts + n, " R%d", i->mc_rate_limited);

		if (pgm_mode != pgm_none && (i->multicast->stats[pgm_spm] || i->multicast->stats[pgm_odata]))
			n+= sprintf(counts + n, " [TSI=%d SPM=%u,ODATA=%u,RDATA=%u,NAK=%u]",
				i->nr_tsi,
				i->multicast->stats[pgm_spm],
				i->multicast->stats[pgm_odata],
				i->multicast->stats[pgm_rdata],
				i->multicast->stats[pgm_nak]);

		if (i->ud && i->ud->stats[packets_received])
			n+= sprintf(counts + n, ", UD %d/%d",
				i->ud->stats[packets_received],
				i->ud->stats[packets_sent]);
		if (i->raw && i->raw->stats[packets_received])
			n+= sprintf(counts + n, ", RAW %d", i->raw->stats[packets_received]);

		n+= sprintf(counts + n, ") ");
	}

	logg(LOG_NOTICE, "%s. Groups=%d/%d. Packets=%s\n", events, active_mc, nr_mc, counts);

	list_endpoints(i2r + INFINIBAND);
	list_endpoints(i2r + ROCE);

}

static void logging(void *private)
{
	brief_status();
	add_event(timestamp() + seconds(10), logging, NULL, "Brief Status");
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
		panic("Max poll items reached\n");

	poll_callback[poll_items] = callback;
	pfd[poll_items] = e;
	poll_private[poll_items] = private;
	poll_items++;
}

static void setup_timed_events(void)
{
	now = timestamp();

	if (background) {
		add_event(now + seconds(30), status_write, NULL, "Write Status File");
		logging(NULL);
	}

	add_event(now + milliseconds(100), check_joins, NULL, "Check Multicast Joins");

	calculate_pps(NULL);
}

static void arm_channels(struct core_info *core)
{
	struct i2r_interface *i;

	for(i = i2r; i < i2r + NR_INTERFACES; i++)
	   if (i->context) {

		/* And request notifications if something happens */
		if (i->multicast && core == i->multicast->core) {
			ibv_req_notify_cq(i->multicast->cq, 0);
		}

		if (i->raw && core == i->raw->core &&
			       (i->raw->type == channel_raw || i->raw->type == channel_ibraw)) {
			start_channel(i->raw);
			ibv_req_notify_cq(i->raw->cq, 0);

			setup_flow(i->raw);
		}

		if (i->ud && core == i->ud->core) {
			start_channel(i->ud);
			ibv_req_notify_cq(i->ud->cq, 0);
		}

		if (i->qp1 && core == i->qp1->core) {
			start_channel(i->qp1);
			ibv_req_notify_cq(i->qp1->cq, 0);
		}
	}

}


static int event_loop(void)
{
	int64_t timeout;
	int events = 0;
	unsigned long t;
 
	arm_channels(NULL);
	setup_timed_events();

loop:
	if (terminated)
		goto out;

	timeout = time_to_next_event();
	if (timeout) {
		/*
		 * If we come from processing poll events then
		 * give priority to more poll event processing
		 */
		if ((timeout <= 0 && events == 0) ||
			       timeout < -(long)milliseconds(10))

			timeout = run_events();

	}
	
	if (timeout <= 0 || timeout > (long)seconds(10))
		timeout = seconds(10);
 
 	events = poll(pfd, poll_items, (timeout + ONE_MILLISECOND/2) / ONE_MILLISECOND);

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
		printf("/var/lib/ib2roce must exist and be writeable for daemon mode.\n");
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

	if (pid_fd < 0)
		panic("Cannot open pidfile. Error %s\n", errname());

	if (fcntl(pid_fd, F_SETLK, &fl) < 0)
       		panic("ib2roce already running.\n");

	if (ftruncate(pid_fd, 0) < 0)
       		panic("Cannot truncate pidfile. Error %s\n", errname());

	n = snprintf(buf, sizeof(buf), "%ld", (long) getpid());

	if (write(pid_fd, buf, n) != n)
       		panic("Cannot write pidfile. Error %s\n", errname());
}

static void pid_close(void)
{
	unlink("ib2roce.pid");
	close(pid_fd);
}

/* Table of options that can be set via -e option[=value] */
struct enable_option {
	const char *id;
	bool runtime;		/* Is it changeable at runtime? */
	bool *bool_flag;
	int *int_flag;
	const char *on_value;
	const char *off_value;
	void (*callback)(void);
	const char *description;
} enable_table[] = {
{ "buffers", false,		NULL, &nr_buffers,	"1000000", "10000", NULL,	"Number of 8k buffers allocated for packet processing" },
{ "bridging", false,		&bridging, NULL,	"on", "off",	NULL, 		"Forwarding of packets between interfaces" },
{ "drop", true,	NULL,		&drop_packets,		"100", "0",	NULL,		"Drop multicast packets. The value is the number of multicast packets to send before dropping" },
{ "flow", false,		&flow_steering, NULL,	"on", "off",	NULL,		"Enable flow steering to limit the traffic on the RAW sockets [Experimental, Broken]" },
{ "huge", false,		&huge, NULL,		"on", "off",	NULL,		"Enable the use of Huge memory for the packet pool" }, 
{ "loopbackprev", false,	&loopback_blocking, NULL, "on", "off",	NULL,		"Multicast loopback prevention of the NIC" },
{ "packetsocket", false,	&packet_socket, NULL,	"on", "off",	NULL,		"Use a packet socket instead of a RAW QP to capure IB/ROCE traffic" },
{ "pgm", true,			NULL, (int *)&pgm_mode, "on", "off",	NULL,		"PGM processing mode (0=None, 1= Passtrough, 2=DLR, 3=Resend with new TSI" },
{ "hwrate", true,		NULL, &rate,		"6", "0",	NULL,		"Set the speed in the RDMA NIC to limit the output speed 2 =2.5GBPS 5 = 5GBPS 3 = 10GBPS ...(see enum ibv_rate)" },
{ "irate", true,		NULL, &irate,		"1000", "0",	set_rates,	"Infiniband: Limit the packets per second to be sent to an endpoint (0=off)" },
{ "rrate", true,		NULL, &rrate,		"1000", "0",	set_rates,	"ROCE: Limit the packets per second to be sent to an endpoint (0=off)" },
{ "latency", true,		&latency, NULL,		"on", "off",	NULL,		"Monitor latency of busyloop and event processing and provide stats" },
{ "loglevel", true,		NULL, &loglevel,	"5","3",	NULL,		"Log output to console (0=EMERG, 1=ALERT, 2=CRIT, 3=ERR, 4=WARN, 5=NOTICE, 6=INFO, 7=DEBUG)" },
{ "iburst", true,		NULL, &max_iburst,	"100", "0",	set_rates,	"Infiniband: Exempt the first N packets from swrate (0=off)" },
{ "rburst", true,		NULL, &max_rburst,	"100", "0",	set_rates,	"ROCE: Exempt the first N packets from swrate (0=off)" },
{ "raw", false,			&raw, NULL,		"on", "off",	NULL,		"Use of RAW sockets to capture SIDR Requests. Avoids having to use a patched kernel" },
{ "statint", true,		NULL, &stat_interval,	"60", "1",	NULL,		"Sampling interval to calculate pps values" },
{ "unicast", false,		&unicast, NULL,		"on", "off",	NULL,		"Processing of unicast packets with QP1 handling of SIDR REQ/REP" },
{ NULL, false, NULL, NULL, NULL, NULL, NULL, NULL }
};

static void enable(char *option, bool enable)
{
	char *name;
	const char *value = NULL;
	char *r;
	int i;
	struct enable_option *eo;

	if (!option || !option[0]) {
		printf("List of available options that can be enabled\n");
		printf("Setting\t\tType\tActive\tDescription\n");
		printf("----------------------------------------------------------------\n");
		for(i = 0; enable_table[i].id; i++) {
			char state[10];

			eo = enable_table + i;

			if (eo->bool_flag) {
				if (*eo->bool_flag)
					strcpy(state, "on");
				else
					strcpy(state, "off");
			} else
				snprintf(state, 10, "%d", *eo->int_flag);

			printf("%-14s\t%s\t%s\t%s\n", eo->id, eo->bool_flag ? "bool" : "int", state, eo->description);
		}
		return;
	}

	r = index(option, '=');
	if (!r)
		r = index(option, ' ');

	if (!r) {
		name = option; 
	} else {
		*r = 0;
		name = option;
		value = r + 1;
	}

	for(i = 0; enable_table[i].id; i++) {
		if (strncasecmp(name, enable_table[i].id, strlen(name)) == 0)
			goto got_it;
	}
	printf("Unknown option %s\n", name);
	return;

got_it:
	eo = enable_table + i;
	if (!eo->runtime && (i2r[ROCE].context || i2r[INFINIBAND].context)) {
		printf("Cannot change option \"%s\" at runtime\n", option);
		return;
	}
	if (!value) {
		if (enable) 
			value = eo->on_value;
		else
			value = eo->off_value;
	}

	if (eo->bool_flag) {
		if (strcasecmp(value, "on") == 0 ||
			strcasecmp(value, "enable") == 0 ||
			strcasecmp(value, "1") == 0)
				*eo->bool_flag = true;
		else
		if (strcasecmp(value, "off") == 0 ||
			strcasecmp(value, "disable") == 0 ||
			strcasecmp(value, "0") == 0)
				*eo->bool_flag = false;
		else {
			fprintf(stderr, "Unknown bool value %s for option %s\n", value, name);
			return;
		}
	} else
	if (eo->int_flag)
		*eo->int_flag = atoi(value);
	else
		panic("object type unknown\n");

	if (eo->callback)
		eo->callback();
}

struct option opts[] = {
	{ "device", required_argument, NULL, 'd' },
	{ "roce", required_argument, NULL, 'r' },
	{ "multicast", required_argument, NULL, 'm' },
	{ "inbound", required_argument, NULL, 'i' },
	{ "mgid", optional_argument, NULL, 'l' },
	{ "beacon", optional_argument, NULL, 'b' },
	{ "debug", no_argument, NULL, 'x' },
	{ "port", required_argument, NULL, 'p' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "test", no_argument, NULL, 't' },
	{ "config", required_argument, NULL, 'c' },
	{ "cores", required_argument, NULL, 'k' },
	{ "enable", optional_argument, NULL, 'e' },
	{ "disable", required_argument, NULL, 'y' },
	{ "help", no_argument, NULL, 'h' },
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
		case 'b':
			beacon = true;
			beacon_arg = optarg;
			break;

		case 'c':
			readconfig(optarg);
			break;

		case 'd':
			ib_name = optarg;
			break;

		case 'e' : enable(optarg, true);
			break;

		case 'i':
			ret = new_mc_addr(optarg, false, true);
			if (ret)
				exit(1);
			break;

		case 'k':
			cores = atoi(optarg);
			if (cores > 8)
				panic("More than 8 cores\n");
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

		case 'm':
			ret = new_mc_addr(optarg, false, false);
			if (ret)
				exit(1);
			break;

		case 'o':
			ret =  new_mc_addr(optarg, true, false);
			if (ret)
				exit(1);
			break;

		case 'p':
			default_port = atoi(optarg);
			break;

		case 'r':
			roce_name = optarg;
			break;

		case 't':
			ring_test();
			fifo_test();
			hash_test();
			testing = true;
			break;

		case 'v':
			loglevel++;
			break;

		case 'x':
			debug = true;
			break;

		case 'y':
			enable(optarg, false);
			break;

		default:
			printf("ib2roce " VERSION " May 12,2022 Christoph Lameter <cl@linux.com>\n");
			printf("Usage: ib2roce [<option>] ...\n");
			printf("-b|--beacon <multicast address>		Send beacon every second. Off by default\n");
			printf("-c|--config <file>			Read config from file\n");
                       	printf("-d|--device <if[:portnumber][/<netdev>]	Infiniband device. Uses the first available if not specified\n");
			printf("-e|--enable <option>[=<value>]		Set up additional options and features.\n");
			printf("-e|--enable				List additional options with a description\n");
			printf("-h|--help				Show these instructions\n");
			printf("-i|--inbound <multicast address>	Incoming multicast only (ib traffic in, roce traffic out)\n");
			printf("-k|--cores <nr>				Spin on the given # of cores\n");
			printf("-l|--mgid				List availabe MGID formats for Infiniband\n");
			printf("-l|--mgid <format>			Set default MGID format\n");
			printf("-m|--multicast <multicast address>[:port][/mgidformat] Enable multicast forwarding\n");
			printf("-o|--outbound <multicast address>	Outgoing multicast only / sendonly /(ib trafic out, roce traffic in)\n");
			printf("-p|--port <number>			Set default port number to use if none is specified\n");
			printf("-r|--roce <if[:portnumber]>		ROCE device. Uses the first available if not specified.\n");
			printf("-v|--log-packets			Show more detailed logs. Can be specified multiple times\n");
			printf("-x|--debug				Do not daemonize, enter command line mode\n");
			printf("-y|--disable <option>			Disable feature\n");
			exit(1);
	}
}

static void help(char *parameters);

static void exitcmd(char *parameters)
{
	terminate(0);
}

static const char * gid_text[] = { "GID_TYPE_IB", "GID_TYPE_ROCE_V1", "GID_TYPE_ROCE_V2" };
static const char *port_state_text[] = { "PORT_NOP","PORT_DOWN","PORT_INIT","PORT_ARMED","PORT_ACTIVE","PORT_ACTIVE_DEFER" };
static const char *mtu_text[] = { "NONE", "256", "512", "1024", "2048", "4096" };
static const char *link_layer_text[] = { "UNSPECIFIED", "INFINIBAND", "ETHERNET" };

static void interfaces_cmd(char *parameters)
{
	int n;
	char b[5000];

	if (parameters) {
		for(struct i2r_interface *i = i2r; i < i2r + NR_INTERFACES; i++)
			if (i->context && strncasecmp(i->text, parameters, strlen(parameters)) == 0) {
				printf("Interface %s\n", i->text);
				printf("-------------------------------------\n");
				printf("RDMA device=%s Port=%d MTU=%d\n", i->rdma_name, i->port, i->mtu);
				printf("NET device=%s IFindex=%d IP=%s ", i->if_name, i->ifindex, inet_ntoa(i->if_addr.sin_addr));
				printf("Netmask=%s MacLen=%d MAC=%s\n", inet_ntoa(i->if_netmask.sin_addr), i->maclen, hexbytes(i->if_mac, i->maclen, '-'));
				printf("GID %s GIDIndex=%d GIDtablesize=%d\n", inet6_ntoa(&i->gid), i->gid_index, i->iges);
				for(struct ibv_gid_entry *g = i->ige; g < i->ige + i->iges; g++) {
					printf(" gid=%s gid_index=%d port_num=%d gid_type=%s ndev_ifindex=%d\n",
							inet6_ntoa(&g->gid), g->gid_index, g->port_num, gid_text[g->gid_type], g->ndev_ifindex);

				}

				printf("Device Attributes\n");
				printf(" Firmware=%s, NodeGUID=%lx Sys_Image_GUID=%lx\n",
					       i->device_attr.fw_ver,
					       be64toh(i->device_attr.node_guid),
					       be64toh(i->device_attr.sys_image_guid));
				printf(" max_mr_size=%ld page_size_cap=%lx vendor_id=%x vendor_part_id=%x hw_ver=%x",
					       i->device_attr.max_mr_size,
					       i->device_attr.page_size_cap,
					       i->device_attr.vendor_id,
					       i->device_attr.vendor_part_id,
					       i->device_attr.hw_ver);
				printf(" max_qp=%d max_qp_wr=%d device_cap_flags=%x\n",
					       i->device_attr.max_qp,
					       i->device_attr.max_qp_wr,
					       i->device_attr.device_cap_flags);
				printf(" max_sge=%d max_sge_rd=%d max_cq=%d max_cqe=%d max_mr=%d max_pd=%d max_qp_rd_atom=%d max_ee_rd_atom=%d\n",
					       i->device_attr.max_sge,
					       i->device_attr.max_sge_rd,
					       i->device_attr.max_cq,
					       i->device_attr.max_cqe,
					       i->device_attr.max_mr,
					       i->device_attr.max_pd,
					       i->device_attr.max_qp_rd_atom,
					       i->device_attr.max_ee_rd_atom);
				printf(" max_res_rd_atom=%d atomic_cap=%x max_ee=%d max_rdd=%d max_mw=%d\n",
					       i->device_attr.max_res_rd_atom,
					       i->device_attr.atomic_cap,
					       i->device_attr.max_ee,
					       i->device_attr.max_rdd,
					       i->device_attr.max_mw);
				printf(" max_raw_ipv6_qp=%d max_raw_ethy_qp=%d\n",
					       i->device_attr.max_raw_ipv6_qp,
					       i->device_attr.max_raw_ethy_qp);
				printf(" max_mcast_grp=%d max_mcast_qp_attach=%d max_total_mcast_qp_attach=%d\n",
					       i->device_attr.max_mcast_grp,
					       i->device_attr.max_mcast_qp_attach,
					       i->device_attr.max_total_mcast_qp_attach);
				printf(" max_ah=%d max_fmr=%d max_map_per_fmr=%d max_srq=%d max_srq_wr=%d max_srq_sge=%d\n",
						i->device_attr.max_ah,
						i->device_attr.max_fmr,
					       i->device_attr.max_map_per_fmr,
					       i->device_attr.max_srq,
					       i->device_attr.max_srq_wr,
					       i->device_attr.max_srq_sge);
				printf(" max_pkeys=%d local_ca_ack_delay=%d phys_port_cnt=%d\n",
					       i->device_attr.max_pkeys,
					       i->device_attr.local_ca_ack_delay,
					       i->device_attr.phys_port_cnt);

				printf("Port Attributes\n");
				printf(" state=%s MTU=%s Active MTU=%s git_dbl_len=%d port_cap_flags=%x max_msg_sz=%d\n",
					port_state_text[i->port_attr.state],
					mtu_text[i->port_attr.max_mtu],
					mtu_text[i->port_attr.active_mtu],
					i->port_attr.gid_tbl_len,
					i->port_attr.port_cap_flags,
					i->port_attr.max_msg_sz);
				printf(" bad_pkey_cntr=%d qkey_viol_cntr=%d pkey_tbl_len=%d\n",
					i->port_attr.bad_pkey_cntr,
					i->port_attr.qkey_viol_cntr,
					i->port_attr.pkey_tbl_len);
				printf(" lid=%d sm_lid=%d lmc=%d max_vl_num=%d sm_sl=%d\n",
					i->port_attr.lid,
					i->port_attr.sm_lid,
					i->port_attr.lmc,
					i->port_attr.max_vl_num,
					i->port_attr.sm_sl);
				printf(" subnet_timeout=%d init_type_reply=%d active_width=%d active_speed=%d\n",
					i->port_attr.subnet_timeout,
					i->port_attr.init_type_reply,
					i->port_attr.active_width,
					i->port_attr.active_speed);
				printf(" phys_state=%d link_layer=%s flags=%x port_cap_flags2=%x\n",
					i->port_attr.phys_state,
					link_layer_text[i->port_attr.link_layer],
					i->port_attr.flags,
					i->port_attr.port_cap_flags2);
				return;
			}

		printf("Unknown interface \"%s\".\n", parameters);
		return;
	}

	n = show_interfaces(b);
	b[n] = 0;
	puts(b);
}

static void endpoints_cmd(char *parameters)
{
	int n;
	char b[5000];

	n = show_endpoints(b);
	b[n] = 0;
	puts(b);
}

static void buffers_cmd(char *parameters)
{
	struct buf *buf;
	int free = 0;

	for(buf = buffers; buf < buffers + nr_buffers; buf++)
		if (buf->free)
		       free++;

	printf("Buffers: Active=%u Total=%u\n", nr_buffers-free , nr_buffers);
	/* Sometime show more details */
}

static void multicast_cmd(char *parameters)
{
	struct mc *m;

	now = timestamp();

	printf("Multicast: Active=%u NR=%u Max=%u\n", active_mc, nr_mc, MAX_MC);

	for(m = mcs; m < mcs + nr_mc; m++) {

		for(enum interfaces in = INFINIBAND; in <= ROCE; in++) {
			printf("%s %s %s %s %s packet_time=%dns, max_burst=%d packets, delayed=%ld packets, last_sent=%ldms ago, last_delayed=%ldms ago, pending=%u packets, burst=%d\n",
				interfaces_text[in], m->text,
			mc_text[m->interface[in].status],
			m->interface[in].sendonly ? "Sendonly " : "",
			in == INFINIBAND ? m->mgid_mode->id : "",
			m->interface[in].packet_time,
			m->interface[in].max_burst,
			m->interface[in].delayed,
			m->interface[in].last_sent ? (now - m->interface[in].last_sent) / ONE_MILLISECOND : -999,
			m->interface[in].last_delayed ? (now - m->interface[in].last_delayed) / ONE_MILLISECOND : -999,
			m->interface[INFINIBAND].pending,
			m->interface[in].burst);
		}
	}
}

static void statuscmd(char *parameters) {
	brief_status();
}

static void enablecmd(char *parameters) {
	enable(parameters, true);
}

static void disablecmd(char *parameters) {
	enable(parameters, false);
}

static void channel_stat(struct rdma_channel *c)
{
	printf(" Channel %s: ActiveRecvBuffers=%u/%u ActiveSendBuffers=%u/%u CQ_high=%u SendQ=%u\n", c->text,
		c->active_receive_buffers, c->nr_receive, c->active_send_buffers, c->nr_send, c->cq_high, fifo_items(&c->send_queue));

	if (c->last_snapshot && (c->max_pps_in || c->max_pps_out))
		printf(" pps_in=%d pps_out=%d max_pps_in=%d max_pps_out=%d\n", 
				c->pps_in, c->pps_out, c->max_pps_in, c->max_pps_out);

	for(int k = 0; k < nr_stats; k++)
		if (c->stats[k])
			printf(" %s=%u", stats_text[k], c->stats[k]);

	printf("\n");
}


static void channels_cmd(char *parameters)
{
	for(struct i2r_interface *i = i2r; i <i2r + NR_INTERFACES; i++) if (i->context) {
		if (i->multicast)
			channel_stat(i->multicast);
		if (i->ud)
			channel_stat(i->ud);
		if (i->raw)
			channel_stat(i->raw);
		if (i->qp1)
			channel_stat(i->qp1);
	}
}

static void channel_zap(struct rdma_channel *c)
{
	c->last_snapshot = 0;
	c->max_pps_in = 0;
	c->max_pps_out = 0;
	c->cq_high = 0;

	for(int k = 0; k < nr_stats; k++)
		c->stats[k] = 0;

	if (cores) {
		for(unsigned i = 0; i < cores; i++) {
			struct core_info *ci = core_infos + i;

			if (latency) {
				ci->samples = 0;
				ci->max_latency = 0;
				ci->min_latency = 0;
				ci->sum_latency = 0;
			}

		}
	}
}


static void zap_cmd(char *parameters)
{
	for(struct i2r_interface *i = i2r; i <i2r + NR_INTERFACES; i++) if (i->context) {
		if (i->multicast)
			channel_zap(i->multicast);
		if (i->ud)
			channel_zap(i->ud);
		if (i->raw)
			channel_zap(i->raw);
		if (i->qp1)
			channel_zap(i->qp1);
	}
	printf("Ok\n");
}

static void core_cmd(char *parameters) {
	if (!parameters) {
		if (cores) {
			unsigned i;

			for(i = 0; i < cores; i++) {
				unsigned j;
				struct core_info *ci = core_infos + i;

				printf("Core %d: NUMA=%d", i, ci->numa_node);
				if (latency)
					printf(" Loops over 5usecs=%u Average=%luns, Max=%uns, Min=%uns\n",
						ci->samples, ci->samples ? ci->sum_latency / ci->samples : 0,
						ci->max_latency, ci->min_latency);

				for (j = 0; j < ci->nr_channels; j++)
					channel_stat(ci->channel + j);
			}
		} else
			printf("No cores active. ib2roce operates in single threaded mode.\n");
	} else
		printf("Dynamic reseetting of the core config not supported.\n");
}

static void tsi_cmd(char *parameters)
{
	for(struct i2r_interface *i = i2r; i < i2r + NR_INTERFACES; i++) {
		printf("%s: TSIs=%d\n", i->text, i->nr_tsi);
		/* Retrieve TSI streams */
		struct pgm_stream *t[10];
		unsigned nr;
		unsigned offset = 0;

		while ((nr = hash_get_objects(i->pgm_tsi_hash, offset, 10, (void **)t))) {
			for(int j = 0; j < nr; j++) {
				struct pgm_stream *ps = t[j];
				char buf[60];

				format_tsi(buf, &ps->tsi);

				printf("%s: lead=%d trail=%d last=%d lastRepairData=%d oldest=%d\n",
					buf, ps->lead, ps->trail, ps->last, ps->rlast, ps->oldest);

			}
			offset += nr;
		}
	}
}

static void event_cmd(char *parameters)
{
	printf("Scheduled events on the high latency thread\n");
	printf("-------------------------------------------\n");

	for(struct timed_event *z = next_event; z; z = z->next) {
		printf("%ldms %s\n", (z->time - timestamp()) / ONE_MILLISECOND, z->text);
	}
}

static int log_interval;

static void continous(void *private)
{
	printf("\n");
	brief_status();

	if (log_interval)
		add_event(timestamp() + seconds(log_interval),
				continous, NULL, "Continous Logging");
}

static void continous_cmd(char *parameters)
{
	int old_interval = log_interval;

	if (!parameters) {
		printf("Continuous logging interval is %d seconds.\n", log_interval);
		return;
	}

	log_interval = atoi(parameters);

	if (!old_interval && log_interval)
		continous(NULL);
}

static struct concom {
	const char *name;
	bool prompt;
	int parameters;
	const char *description;
	void (*callback)(char *parameters);
} concoms[] = {
{ "buffers",	true,	0,	"Print Information about buffer use",		buffers_cmd },
{ "channels",	true,	0,	"Print information about communication channels", channels_cmd },
{ "continuous",	false,	1,	"Print continous status in specified interval",	continous_cmd },
{ "cores",	true,	1,	"Setup and list core configuration",		core_cmd },
{ "disable",	true,	1,	"Disable optional features",			disablecmd },
{ "enable",	true,	1,	"Setup optional features and list them",	enablecmd },
{ "events",	true,	0,	"Show scheduler event queue",			event_cmd },
{ "help",	true,	0,	"Print a list of commands",			help },
{ "interfaces",	true,	1,	"List statisitcs about Interfaces",		interfaces_cmd },
{ "endpoints",	true,	0,	"List Endpoints",				endpoints_cmd },
{ "multicast",	true,	0,	"List Multicast groups and their status",	multicast_cmd },
{ "quit",	false,	0,	"Terminate ib2roce",				exitcmd },
{ "status",	true,	0,	"Print a brief status",				statuscmd },
{ "tsi",	true,	0,	"Show PGM info",				tsi_cmd },
{ "zap",	true,	0,	"Clear counters",				zap_cmd },
{ NULL,		false,	0,	NULL,						NULL }
};


static void help(char *parameters)
{
	struct concom * cc;

	printf("List of ib2roce console commands:\n");
	printf("Command		Description\n");
	printf("----------------------------------------\n");

	for(cc = concoms; cc->name; cc++) {
		printf("%-16s%s\n", cc->name, cc->description);
	}
}

static void prompt(void *private)
{
	printf("ib2roce-$ ");
	fflush(stdout);
}

static void console_input(void *private)
{
	struct concom * cc;
	char in[80];
	int ret;
	char *p;
	unsigned len;

	ret = read(STDIN_FILENO, in, sizeof(in));

	if (ret == 0) {
		printf("\n");
		terminated = true;
		return;
	}

	if (ret < 0) {
		printf("Console Input Error: %s\n", errname());
		goto out;
	}

	if (ret < 1 || in[0] == '#' || in[0] == '\n' || in[0] <= ' ')
		goto out;

	if (in[ret - 1] == '\n')
		in[ret - 1] = 0;

	for (p = in; *p; p++)
	{
		if (*p < ' ') {
			printf("\nControl Character %d at position %ld\n", *p, p - in);
			goto out;
		}
	}

	p = index(in, ' ');
	if (p)
		*p++ = 0;

	len = strlen(in);

	for(cc = concoms; cc->name; cc++) {
		if (strncasecmp(in, cc->name, len) == 0) {

			if (p && !cc->parameters) {
				printf("Command does not allow parameters\n");
				goto out;
			}
	
			cc->callback(p);

			if (!cc->prompt)
				return;

			goto out;
		}
	};
	printf("Command \"%s\" not found. Try \"help\".\n", in);
out:
	prompt(NULL);
}


int main(int argc, char **argv)
{
	int op, ret = 0;

	mc_hash = hash_create(offsetof(struct mc, addr), sizeof(struct in_addr));

	sidr_state_init();

	while ((op = getopt_long(argc, argv, "b::c:d:e::hi:k:l::m:o:p:i:tvxz:",
					opts, NULL)) != -1) {
		if (!optarg && argv[optind] && argv[optind][0] != '-') {
			optarg = argv[optind];
			optind++;
		}
		exec_opt(op, optarg);
	}


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

	logg (LOG_NOTICE, "%s device = %s:%d, %s device = %s:%d. Multicast Groups=%d MGIDs=%s Buffers=%u\n",
			interfaces_text[INFINIBAND], i2r[INFINIBAND].rdma_name, i2r[INFINIBAND].port,
			interfaces_text[ROCE], i2r[ROCE].rdma_name, i2r[ROCE].port,
			nr_mc, mgid_mode->id, nr_buffers);

	init_buf();	/* Setup interface registers memmory */
	init_pgm_streams();

	setup_interface(INFINIBAND);
	setup_interface(ROCE);

	if (!i2r[INFINIBAND].context && !i2r[ROCE].context) {
		logg(LOG_CRIT, "No working RDMA devices present.\n");
		exit(2);
	}

	if (cores)
		show_core_config();

	if (background)
		status_fd = open("ib2roce-status", O_CREAT | O_RDWR | O_TRUNC,  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	else {
		register_callback(console_input, STDIN_FILENO, NULL);
		add_event(timestamp() + seconds(2), prompt, NULL, "Console Prompt");
	}

	if (beacon)
		beacon_setup(beacon_arg);


	post_receive_buffers();

	send_queue_monitor(NULL);

	start_cores();

	event_loop();

	stop_cores();

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
