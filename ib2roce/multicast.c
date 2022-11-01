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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <rdma/rdma_cma.h>
#include <infiniband/ib.h>
#include <infiniband/verbs.h>
#include <poll.h>
#include <sys/mman.h>

#include <infiniband/mad.h>
#include <infiniband/umad_cm.h>
#include <infiniband/umad_str.h>
#include <execinfo.h>
#include "packet.h"
#include "errno.h"
#include "fifo.h"
#include "ring.h"
#include "hash.h"
#include "sched.h"
#include "logging.h"
#include "locking.h"
#include "buffers.h"
#include "interfaces.h"
#include "multicast.h"
#include "cli.h"
#include "beacon.h"

unsigned default_mc_port = 4711;	/* Port for MC groups that do not have a port (if a port is required) */
uint8_t tos_mode = 0;

/*
 * Multicast Handling (follows the limit per QP as stated in device_attr for ConnectX6)
 */
unsigned nr_mc;
unsigned active_mc;	/* MC groups actively briding */

const char *mc_text[NR_MC_STATUS] = { "Inactive", "Joining", "Joined", "Error" };

struct mc mcs[MAX_MC];

struct hash *mc_hash;

struct mc *hash_lookup_mc(struct in_addr addr)
{
	unsigned a = ntohl(addr.s_addr) | 0xe0000000; /* Infiniband may strip top 4 bits so provide them */
	struct in_addr x = {
		.s_addr = htonl(a)
	};

	return hash_find(mc_hash, &x);
}

int hash_add_mc(struct mc *m)
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

/*
 * Handling of special Multicast Group MGID encodings on Infiniband
 */
#define nr_mgid_signatures 5

static struct mgid_signature {		/* Manage different MGID formats used */
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

static uint8_t mgid_mode = 4;		/* CLLM is the default */

static uint8_t __find_mgid_mode(char *p)
{
	int i;

	for(i = 0; i < nr_mgid_signatures; i++)
		if (strcasecmp(p, mgid_signatures[i].id) == 0)
			return i + 1;

	return 0;
}

static bool find_mgid_mode(char *p)
{
	uint8_t g = __find_mgid_mode(p);

	if (!g) {
		fprintf(stderr, "Not a valid mgid mode %s\n", p);
		return false;
	}
	mgid_mode = g;
	return true;
}

/* Setup the addreses for ROCE and INFINIBAND based on a ipaddr:port spec */
void setup_mc_addrs(struct mc *m, struct sockaddr_in *si)
{
	m->interface[ROCE].sa = (struct sockaddr  *)si;
	m->port = ntohs(si->sin_port);
	m->interface[INFINIBAND].sa = m->interface[ROCE].sa;

	if (mgid_signatures[m->mgid_mode - 1].signature) {
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
		struct mgid_signature *mg = mgid_signatures + m->mgid_mode - 1;

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

/*
 * Parse an address with port number [:xxx] and/or mgid format [/YYYY]
 */
struct sockaddr_in *parse_addr(const char *arg, int port,
		uint8_t *p_mgid_mode, uint8_t *p_tos_mode, bool mc_only)
{
	struct addrinfo *res;
	char *service;
	const struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP
	};
	struct sockaddr_in *si;
	char *p, *q;
	int ret;
	uint8_t mgid;
	struct in_addr addr;
	uint8_t tos;
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

	q = strchr(p, '/');
	if (q) {
		*q++ = 0;
		mgid = __find_mgid_mode(q);

		if (!mgid) {
			fprintf(stderr, "MGID mode not found %s\n", p);
			return NULL;
		}
		p = q;
	} else
		mgid = mgid_mode;

	q = strchr(p, '#');
	if (q) {
		*q++ = 0;
		tos = atoi(q);
		if (!tos) {
			fprintf(stderr, "TOS value invalid : %p\n", p);
			return NULL;
		}
	} else
		tos = tos_mode;

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
	*p_tos_mode = tos;
	return si;
}

const char * mgid_text(struct mc *m)
{
	int g;

	if (m)
		g = m->mgid_mode;
	else
		g = mgid_mode;

	if (!g)
		abort();

	return mgid_signatures[g -1].id;
}

void mgids_out(void)
{
	int n;

	printf("List of supported MGID formats via -l<id>\n");
	printf("=================================\n");
	printf(" ID    | Signature | Port in MGID\n");
	printf("-------+-----------+-------------\n");
	for (n = 0; n < nr_mgid_signatures; n++) {
		struct mgid_signature *m = mgid_signatures + n;

		printf("%7s|    0x%04x | %s\n",
				m->id, m->signature, m->port ? "true" : "false");
	}
}

bool mgid_check(struct mc *m, unsigned short signature)
{
	struct mgid_signature *g= mgid_signatures + m->mgid_mode - 1;

	if (g->signature) {
		if (signature != g->signature)
			return false;
	}
	return true;
}

/* Multicast group specifications on the command line */
int new_mc_addr(char *arg,
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

	si = parse_addr(arg, default_mc_port, &m->mgid_mode, &m->tos_mode, true);
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
	m->enabled = true;
	ret = 0;

out:
	return ret;
}



static int _join_mc(struct in_addr addr, struct sockaddr *sa,
		unsigned port, uint8_t tos, struct rdma_channel *c, bool sendonly, struct mc *m)
{
	int ret;
	int i;
	struct rdma_cm_join_mc_attr_ex mc_attr = {
		.comp_mask = RDMA_CM_JOIN_MC_ATTR_ADDRESS | RDMA_CM_JOIN_MC_ATTR_JOIN_FLAGS,
		.join_flags = sendonly ? RDMA_MC_JOIN_FLAG_SENDONLY_FULLMEMBER
			: RDMA_MC_JOIN_FLAG_FULLMEMBER,
		.addr = sa
	};

	/* Find first free slot */
	for(i = 0; i < c->i->mc_per_qp; i++)
		if (!c->mc[i])
			break;

	if (i == c->i->mc_per_qp) {
		logg(LOG_CRIT, "Can only join %u multicast groups on rdma_channel %s\n", c->i->mc_per_qp, c->text);
		return 1;
	}

	ret = rdma_join_multicast_ex(c->id, &mc_attr, m);

	if (ret) {
		logg(LOG_CRIT, "Failed to create join request %s:%d on %s. Error %s\n",
			inet_ntoa(addr), port,
			c->i->text,
			errname());
		return 1;
	}
	logg(LOG_DEBUG, "Join Request %sMC group %s:%d on %s.\n",
		sendonly ? "Sendonly " : "",
		inet_ntoa(addr), port,
		c->i->text);
	st(c, join_requests);

	c->mc[i] = m;
	c->nr_mcs++;
	return 0;
}

static int _leave_mc(struct in_addr addr,struct sockaddr *si, struct rdma_channel *c, struct mc *m)
{
	int ret;
	int i;

	for(i = 0; i < c->i->mc_per_qp; i++) {
		if (c->mc[i] == m) {
			break;
		}
	}
	if (i == c->i->mc_per_qp)
		panic("Multicast structure not found in _leave_mc");

	ret = rdma_leave_multicast(c->id, si);
	if (ret) {
		logg(LOG_ERR, "Failure rdma_leave_multicast on %s:%s %s\n", c->i->text, inet_ntoa(addr), errname());
		return 1;
	}
	logg(LOG_DEBUG, "Leaving MC group %s on %s .\n",
		inet_ntoa(addr),
		c->i->text);

	st(c, leave_requests);
	c->mc[i] = NULL;
	c->nr_mcs--;
	return 0;
}

int leave_mc(enum interfaces i, struct rdma_channel *c)
{
	int j;
	int ret;

	for (j = 0; j < nr_mc; j++) {
		struct mc *m = mcs + j;
		struct mc_interface *mi = m->interface + i;

		if (mi->channel != c)
			continue;

		m->enabled = false;
		if (mi->channel) {
			ret = _leave_mc(m->addr, mi->sa, c, m);
			if (ret)
				return 1;
		}

		mi->channel = NULL;
	}
	return 0;
}

/*
 * List the two rdma channels for bridging MC traffic on which joins are currently processed
 */
static struct global_join_state {
	struct channel_list *channels[NR_INTERFACES];
} gjs;

/*
 * Join MC groups. This is called from the event loop every second
 * as long as there are unjoined groups
 */
static void send_joins(void)
{
	int i;
	enum interfaces in;

	for (i = 0; i < nr_mc; i++) {
		struct mc *m = mcs + i;
		unsigned port = m->port;

		if (!m->enabled)
			continue;

		if (m->interface[ROCE].status == MC_JOINED && m->interface[INFINIBAND].status == MC_JOINED)
			continue;

		for(in = 0; in < NR_INTERFACES; in++) {
			struct mc_interface *mi = m->interface + in;
			uint8_t tos = in == ROCE ? m->tos_mode : 0;

			if (mi->channel && !is_a_channel_of(mi->channel, gjs.channels[in])) {
				logg(LOG_INFO, "Not joining multicast group %s which is not on rdma channel %s but on %s\n",
						m->text, gjs.channels[in]->c[0]->text, mi->channel->text);
				continue;
			}

			if (i2r[in].context) {
				switch(mi->status) {

					case MC_OFF:
						/* Find rdma channel with available multicast slots  */
						channel_foreach(c, gjs.channels[in]) {
							if (c->type == channel_rdmacm && c->nr_mcs < c->i->mc_per_qp) {
								if (_join_mc(m->addr, mi->sa, port, tos, c, mi->sendonly, m) == 0) {
									mi->status = MC_JOINING;
									mi->channel = c;
									goto next;
								} else
									/* Error during join... Lets retry this in awhile */
									return;
							}
						}
						panic("Not enough rdma channels for multicast channels\n");
						break;

					case MC_ERROR:

						_leave_mc(m->addr, mi->sa, mi->channel, m);
						mi->status = MC_OFF;
						mi->channel = NULL;
						logg(LOG_WARNING, "Left Multicast group %s on %s due to MC_ERROR\n",
								m->text, interfaces_text[in]);
						break;

					case MC_JOINED:
						break;

					case MC_JOINING:
						/* Join is still being processed */
						break;

					default:
						logg(LOG_ERR, "Bad MC status %d MC %s on %s\n",
								mi->status, m->text, interfaces_text[in]);
						break;
				}
				next: ;
			}
		}
	}
}

/*
 * RDMA handler event occurred that completed the next join
 * for a couple of multicast groups
 */
void next_join_complete(struct mc *m)
{
	struct i2r_interface *i;

	if (m->interface[ROCE].channel->core == m->interface[INFINIBAND].channel->core)
		m->same_core = true;
	else
		logg(LOG_WARNING, "MC %s in and out channel not on the same core\n", inet_ntoa(m->addr));

	active_mc++;
	if (active_mc < nr_mc)
		return;

	/*
	 * All active so start listening. This means we no longer
	 * are able to subscribe to Multicast groups
	 */

	for(i = i2r; i < i2r + NR_INTERFACES; i++)
		if (i->context)	{
			channel_foreach(c, gjs.channels[i - i2r]) {
				if (c->type != channel_rdmacm)
					continue;

				if (c->listening)
					continue;

				if (rdma_listen(c->id, 50))
					logg(LOG_ERR, "rdma_listen on %s error %s\n", c->text, errname());

				c->listening = true;
			}
		}
}

static void __check_joins(void *private)
{
	if (nr_mc > active_mc) {

		/* Still subscribing to multicast groups. Send the joins and check back after 50 milliseconds  */
		send_joins();
		add_event(timestamp() + milliseconds(50), __check_joins, private, "Check Multicast Joins");

	}
}

void check_joins(struct channel_list *infiniband,
		struct channel_list *roce)
{
	gjs.channels[INFINIBAND] = infiniband;
	gjs.channels[ROCE] = roce;
	 __check_joins(NULL);
}

static void multicast_cmd(FILE *out, char *parameters)
{
	struct mc *m;

	now = timestamp();

	fprintf(out, "Multicast: Active=%u NR=%u Max=%u\n", active_mc, nr_mc, MAX_MC);

	for(m = mcs; m < mcs + nr_mc; m++) {

		for(enum interfaces in = INFINIBAND; in <= ROCE; in++) {
			struct mc_interface *mi = m->interface + in;

			fprintf(out, "%s %s %s %s %s ", mi->channel ? mi->channel->text : interfaces_text[in], m->text,
				mc_text[mi->status],
				mi->sendonly ? "Sendonly" : "",
				in == INFINIBAND ? mgid_text(m) : "");

			if (!m->enabled)
				fprintf(out, " disabled");

			if (m->admin)
				fprintf(out, " admin");

			if (!is_a_channel_of(mi->channel, &i2r[in].channels))
				fprintf(out, " remote");

			if (!mi->packet_time) {
				fprintf(out, " No rate limitations\n");
				continue;
			}

			fprintf(out, " packet_time=%dns max_burst=%d",
				mi->packet_time,
				mi->max_burst);

			if (mi->last_sent)
			   fprintf(out, " last_sent=%ldms ago, pending=%u packets",
				(now - mi->last_sent) / ONE_MILLISECOND,
				mi->pending);

			if (mi->last_delayed)
			   fprintf(out, " delayed=%ld packets last_delayed=%ldms ago",
				mi->delayed, (now - mi->last_delayed) / ONE_MILLISECOND);

			fprintf(out, "\n");
		}
	}
}

static void mgid_set(char *optarg)
{
	if (optarg) {
		if (find_mgid_mode(optarg))
			return;
	} else
		mgids_out();
	exit(1);
}

static void tos_set(char *optarg)
{
	tos_mode = atoi(optarg);
}

static void multicast_set(char *optarg)
{
	int ret;

	ret = new_mc_addr(optarg, false, false);
	if (ret)
		exit(1);
}

static void inbound_set(char *optarg)
{
	int ret;

	ret = new_mc_addr(optarg, false, true);
	if (ret)
		exit(1);
}

static void outbound_set(char *optarg)
{
	int ret;

	ret = new_mc_addr(optarg, true, false);
	if (ret)
		exit(1);
}

__attribute__((constructor))
static void multicast_init(void)
{
	register_concom("multicast", true, 0, "List Multicast groups and their status", multicast_cmd);
	register_option("mgid", optional_argument, 'l', mgid_set,
			"<format>","Set default MGID format/List formats");
	register_option("tos", required_argument, 't', tos_set,
		       "<value>", "Set TOS default for the following multicast defs");

	register_option("multicast", required_argument, 'm', multicast_set,
			"<multicast address>[:port][/mgidformat]","Enable multicast forwarding");
	register_option("inbound", required_argument, 'i', inbound_set,
		       "<multicast address>", "Incoming multicast only (ib traffic in, roce traffic out)");
	register_option("outbound", required_argument, 'o', outbound_set,
			"<multicast address>", "Outgoing multicast only / sendonly /(ib trafic out, roce traffic in)");

	mc_hash = hash_create(offsetof(struct mc, addr), sizeof(struct in_addr));
}

