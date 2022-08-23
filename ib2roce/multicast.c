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

static struct mgid_signature *mgid_mode = mgid_signatures + 3;		/* CLLM is the default */


static struct mgid_signature *__find_mgid_mode(char *p)
{
	struct mgid_signature *g;

	for(g = mgid_signatures; g < mgid_signatures + nr_mgid_signatures; g++)
		if (strcasecmp(p, g->id) == 0)
			return g;

	return NULL;
}

static bool find_mgid_mode(char *p)
{
	struct mgid_signature *g = __find_mgid_mode(p);

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

/*
 * Parse an address with port number [:xxx] and/or mgid format [/YYYY]
 */
struct sockaddr_in *parse_addr(const char *arg, int port,
	struct mgid_signature **p_mgid_mode, uint8_t *p_tos_mode, bool mc_only)
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
	struct mgid_signature *mgid;
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
	if (m)
		return m->mgid_mode->id;
	else
		return mgid_mode->id;
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
	if (m->mgid_mode->signature) {
		if (signature != m->mgid_mode->signature)
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
	ret = 0;

out:
	return ret;
}

int _join_mc(struct in_addr addr, struct sockaddr *sa,
	unsigned port, uint8_t tos, enum interfaces i, bool sendonly, void *private)
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

int _leave_mc(struct in_addr addr,struct sockaddr *si, enum interfaces i)
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

int leave_mc(enum interfaces i)
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
			uint8_t tos = i == ROCE ? m->tos_mode : 0;

			if (i2r[in].context) {
				switch(mi->status) {

				case MC_OFF:
					if (_join_mc(m->addr, mi->sa, port, tos, in, mi->sendonly, m) == 0)
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


void check_joins(void *private)
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
			in == INFINIBAND ? mgid_text(m) : "",
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

