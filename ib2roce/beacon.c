/*
 * IB2ROCE beacon support code
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
#include "multicast.h"
#include "cli.h"

#include <unistd.h>

#include "beacon.h"

#define BEACON_SIGNATURE 0xD3ADB33F
#define BEACON_MC_ADDR "239.1.2.3"
#define BEACON_PORT	1109

#define MAX_REMOTE_MCS 100

/*
 * Multicast state in the beacon packet
 */
struct beacon_multicast {
	struct in_addr group;
	bool sendonly[2];
	uint8_t tos_mode;
	uint8_t mgid_mode;
	uint16_t port;
};

/*
 * Beacon info
 */
struct beacon_info {
	unsigned long signature;
	char version[10];
	char name[40];			/* The Hostname of the remote bridge */
	unsigned sessionid;		/* Unique session id created on startup */
	unsigned hold_time;		/* Validity of the Beacon Info */
	unsigned sqn;
	uint64_t timestamp;
	bool infiniband;
	struct in_addr addr[2];		/* Addresses of the bridge */
	unsigned nr_mc;			/* Active Multicast */
	unsigned nr_tsi;		/* Active TSIs */
	struct beacon_multicast mc[MAX_REMOTE_MCS];	/* nr_mc beacon_jp_multicast instances follow */
};

/*
 * Remote bridge states: This is controlled by the beacons that will refresh
 * the expiration time. If the expiration occurs then the bridge will take subscribe
 * to all the multicast groups of that bridge.
 * If a new beacon is encoutered from that bridge then there will be an unsubscribe.
 */
struct bridge_state {
	unsigned long expiration;
	bool active;
	struct in_addr origin[2];
	unsigned beacons_missed;
	unsigned beacons_received;
	long  distance[3];
	struct rdma_channel *channel[NR_INTERFACES];
	struct beacon_info last;
};

static bool beacon = false;
static int beacon_interval = 1000;	/* Default Hello interval in Milliseconds */

static struct sockaddr_in *beacon_sin;

static unsigned beacon_seq = 1;
static unsigned sessionid;		/* Random Number for this session */


static char hostname[40];

#define BEACON_MCS 500

#define MAX_BRIDGES 10
static struct bridge_state remote_bridge[MAX_BRIDGES];

static unsigned int nr_bridges;


void run_bridge_channels(void (*func)(struct rdma_channel *))
{
	int i;

	for(i = 0; i < nr_bridges; i++) {
		struct bridge_state *br = remote_bridge + i;

		func(br->channel[INFINIBAND]);
		func(br->channel[ROCE]);
	}
}

static struct mc *beacon_mc;		/* == NULL if unicast */

static void enable_bridge(struct bridge_state *b)
{
	struct beacon_multicast *bm;
	enum interfaces i;

	logg(LOG_INFO, "Takeover for bridge %s. %d multicast groups\n", b->last.name, b->last.nr_mc);

	/* Create new MC channels */
	for (i = 0; i < NR_INTERFACES; i++) {
		b->channel[i] = new_rdma_channel(i2r + i, channel_rdmacm);
	}


	/* Subscribe to all MC groups of the specified group */
	for(bm = b->last.mc; bm < b->last.mc + b->last.nr_mc; bm++) {
		struct mc *m;
		struct sockaddr_in sin = {
			.sin_family = AF_INET,
			.sin_addr = bm->group,
			.sin_port = htons(bm->port)
		};
		int ret;

		m = hash_lookup_mc(bm->group);
		if (!m) {

			if (nr_mc == MAX_MC) {
				logg(LOG_ERR, "Too many multicast groups when enabling bridge %s\n", b->last.name);
				break;
			}
			m = mcs + nr_mc;
			nr_mc++;

			ret = hash_add_mc(m);
			if (ret) {
				logg(LOG_ERR, "Duplicate multicast address when enabling bridge %s\n", b->last.name);
				break;
			}

		}
		m->addr = bm->group;
		m->interface[INFINIBAND].sendonly = bm->sendonly[INFINIBAND];
		m->interface[ROCE].sendonly = bm->sendonly[ROCE];
		m->text = strdup(inet_ntoa(sin.sin_addr));
		m->tos_mode = bm->tos_mode;
		m->mgid_mode = bm->mgid_mode;
		m->port = bm->port;
		setup_mc_addrs(m, &sin);

		m->enabled = true;
	}
	post_receive(b->channel[INFINIBAND]);
	post_receive(b->channel[ROCE]);
	arm_channel(b->channel[INFINIBAND]);
	arm_channel(b->channel[ROCE]);
	check_joins(b->channel[INFINIBAND], b->channel[ROCE]);
	b->active = true;
}

static void disable_bridge(struct bridge_state *b)
{
	logg(LOG_INFO, "Disabling forwarding for %s\n", b->last.name);
	b->active = false;

/*
 * If there are errors: Do not worry. Destroying the
 * QP is also an implied leave
 */
	leave_mc(INFINIBAND, b->channel[INFINIBAND]);
	leave_mc(ROCE, b->channel[ROCE]);

	channel_destroy(b->channel[INFINIBAND]);
	channel_destroy(b->channel[ROCE]);
}

static void check_remote_bridges(void)
{
	struct bridge_state *b;

	now = timestamp();

	for(b = remote_bridge; b < remote_bridge + nr_bridges; b++)
		if (!b->active && b->expiration && now > b->expiration)
		{
			enable_bridge(b);
		}
}

static void prep_beacon_struct(struct i2r_interface *i, struct buf *buf)
{
	struct beacon_info *b = (void *)buf->raw;
	enum interfaces in = i - i2r;
	struct mc *m;
	unsigned groups = 0;


	b->signature = BEACON_SIGNATURE;
	memcpy(b->version, VERSION, 10);
	memcpy(b->name, hostname, sizeof(hostname));
	b->infiniband = in == INFINIBAND;
	b->sessionid = sessionid;
	b->addr[INFINIBAND] = i2r[INFINIBAND].if_addr.sin_addr;
	b->addr[ROCE] = i2r[ROCE].if_addr.sin_addr;
	b->hold_time = beacon_interval * 3 + beacon_interval / 2;
	b->nr_tsi = i2r[INFINIBAND].nr_tsi;
	if (b->nr_tsi < i2r[ROCE].nr_tsi)
		b->nr_tsi = i2r[ROCE].nr_tsi;

	buf->cur = buf->raw + sizeof(struct beacon_info);
	for(m = mcs; m < mcs + nr_mc; m++) {
		struct beacon_multicast *bm = b->mc + groups;

		if (m->admin || !m->enabled || m->interface[i - i2r].channel != i->multicast)
			continue;

		bm->group = m->addr;
		bm->tos_mode = m->tos_mode;
		bm->port = m->port;
		bm->sendonly[INFINIBAND] = m->interface[INFINIBAND].sendonly;
		bm->sendonly[ROCE] = m->interface[ROCE].sendonly;
		bm->mgid_mode = m->mgid_mode;
		groups++;
	}

	b->nr_mc = groups;

	/* Max MTU is 4096 bytes */
	if (buf->cur > buf->raw + 4096)
		abort();


	b->timestamp = now = timestamp();
	b->sqn = beacon_seq;
	beacon_seq++;
	buf->end = (uint8_t *)(b->mc + groups);
}

static void beacon_received(struct mc *m, enum interfaces in, struct buf *buf)
{
	struct beacon_info *b = (struct beacon_info *)buf->cur;
	struct bridge_state *r;
	long diff;

	if (b->signature != BEACON_SIGNATURE) {
		logg(LOG_ERR, "Received non beacon traffic on beacon MC group %s\n", beacon_mc->text);
		return;
	}

	now = timestamp();
	diff = now - b->timestamp;
	if (diff <= 0)
		diff = 0;


	/* See if we already have that bridge */
	for(r = remote_bridge; r < remote_bridge + nr_bridges; r++)
		if (r->origin[0].s_addr == b->addr[0].s_addr && r->origin[1].s_addr == b->addr[1].s_addr)
			break;

	if (r == remote_bridge + nr_bridges) {
		if (nr_bridges < MAX_BRIDGES) {
			/* New bridge */
			nr_bridges++;
			r->active = false;
			r->origin[0] = b->addr[0];
			r->origin[1] = b->addr[1];

			logg(LOG_INFO, "New Bridge %s Version %s Name=%s MC groups=%u, TSIs=%d. Latency %ld ns\n",
				beacon_mc->text, b->version, b->name, b->nr_mc, b->nr_tsi, diff);

		} else {
			logg(LOG_ERR, "Too many bridges. Max is %d\n", MAX_BRIDGES);
			return;
		}
	}

	if (r->last.sessionid != b->sessionid)	/* New session zap the info */
		memset(&r->last, 0, sizeof(r->last));

	r->beacons_received++;
	if (!r->last.sqn || b->sqn > r->last.sqn) {
		if (r->last.sqn && r->last.sqn + 1!= b->sqn) {
			int missed = (b->sqn - r->last.sqn)  - 1;

			r->beacons_missed++;
			logg(LOG_NOTICE, "%d beacons missed on %s. Last SQN %u, now %u\n", missed, buf->c->i->text, r->last.sqn, b->sqn);
		}

		if (!b->hold_time) {	/* Remote request to forget all information */

			r->expiration = 0;	/* That means it is exempt from expiration scans */

			if (r->active) {
				disable_bridge(r);
			}

			return;
		}
		if (r->active) {
			disable_bridge(r);
		}

		memcpy(&r->last, b, sizeof(struct beacon_info) + b->nr_mc * sizeof(struct beacon_multicast));
		r->expiration = now + milliseconds(b->hold_time);
	} else
		logg(LOG_INFO, "Discarded outdated beacon from %s. Last SQN %u > %u\n", b->name, r->last.sqn, b->sqn);

	r->distance[r->last.sqn % 3] = diff / 1000;
}

static enum interfaces last_interface;

static void beacon_send(void *private)
{
	struct buf *buf;

	if (beacon) {
		if (last_interface == INFINIBAND)
			last_interface = ROCE;
		else
			last_interface = INFINIBAND;

		if (beacon_mc) {
			enum interfaces in = last_interface;
			struct i2r_interface *i = i2r + in;

			if (i->context && beacon_mc->interface[in].status == MC_JOINED) {

				buf = alloc_buffer(i->multicast);
				prep_beacon_struct(i, buf);
				send_to(i->multicast, buf->raw, buf->end - buf->raw, &beacon_mc->interface[in].ai, false, 0, buf);
			}

		} else { /* Unicast */
			struct i2r_interface *i = find_interface(beacon_sin);

			if (!i) {
				logg(LOG_ERR, "Beacon IP %s unreachable\n", inet_ntoa(beacon_sin->sin_addr));
				beacon = false;
				return;
			}
			buf = alloc_buffer(i->multicast);
			prep_beacon_struct(i, buf);

			reset_flags(buf);
			buf->cur = buf->raw;
			send_buf_to(i, buf, beacon_sin);

		}
		check_remote_bridges();
	}
	if (beacon_interval)
		add_event(timestamp() + milliseconds(beacon_interval), beacon_send, NULL, "Send Beacon");
}

void beacon_shutdown(void)
{
	if (beacon) {
		/* Send a beacon with a 0 hold time to expire all information at the other bridges */
		beacon_interval = 0;
		beacon_send(NULL);		/* Argh... Race condition */
	}
}

void beacon_setup(void)
{
	struct in_addr addr;

	if (!beacon)
		return;

	beacon_mc = NULL;
//	beacon_sin = parse_addr(beacon_arg, default_mc_port, &mgid, &tos, false);
	addr = beacon_sin->sin_addr;
	if (IN_MULTICAST(ntohl(addr.s_addr))) {
		struct mc *m = mcs + nr_mc++;

		memset(m, 0, sizeof(*m));
		m->text = strdup(inet_ntoa(beacon_sin->sin_addr));
		m->mgid_mode = 1;
		m->tos_mode = 0;
		m->addr = addr;
		m->admin = true;

		setup_mc_addrs(m, beacon_sin);

		if (hash_add_mc(m)) {
			logg(LOG_ERR, "Beacon MC already in use.\n");
			beacon = false;
			free(beacon_sin);
			beacon_sin = NULL;
		} else
			beacon_mc = m;

		m->callback = beacon_received;
		m->enabled = true;
	}

	/*
	 * First hello should have a random interval offset for each bridge if multiple
	 * are starting up simultaneously.
	 *
	 * Also the first hello is delayed to ensure the bridges are all up and running
	 * and have stabilized.
	 */
	add_event(timestamp() + seconds(5) + milliseconds(rand() % beacon_interval),
			beacon_send, NULL, "Send Beacon");
}

static void beacon_option(char *optarg)
{
	struct addrinfo *res;
	char *service;
	const struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP
        };
	char *p, *q;
	int ret;
	char *a;

	beacon = true;

	if (!optarg)
		a = strdupa("239.1.2.3");
	else
   	    	a = strdupa(optarg);

	/*
	 * Parse argument
	 * <IP-Addr?>[/interval][:port]
	 *
	 * Default 239.1.2.3/100:<default_mc_port>
	 */

	service = strchr(a, ':');
	if (service) {
		*service++ = 0;
		p = service;
	} else {
		char *s = alloca(10);
		unsigned port = default_port ? default_port : 4711;

		snprintf(s, 10, "%d", port);
		service = s;
		p = a;
	}

	q = strchr(p, '/');
	if (q) {
		*q++ = 0;
		beacon_interval = atoi(q);
		p = q;
	}

	ret = getaddrinfo(a, service, &hints, &res);
	if (ret) {
		fprintf(stderr, "getaddrinfo() failed (%s) - invalid IP address.\n", gai_strerror(ret));
                exit(1);
        }

	beacon_sin = malloc(sizeof(struct sockaddr_in));
        memcpy(beacon_sin, res->ai_addr, sizeof(struct sockaddr_in));
        freeaddrinfo(res);
}

/* Print the bridge states */
static void beacon_cmd(char *parameters)
{
	struct bridge_state *b;

	printf("Nr|Origin           |SessID  |Time to Expire|Stat|Rec. |Miss|MC |TSI| Latencies\n");
	printf("--+-----------------+--------+--------------+----+-----+----+---+---|--------------\n");
	printf("%2lu|%-17s|%8x|%s|%s|%5u|%4u|%3u|%3u| Sent=%d\n",
				0L,
				hostname,
				sessionid,
				"    LOCAL     ",
				"    ",
				0,
				0,
				nr_mc,
				i2r[INFINIBAND].nr_tsi + i2r[ROCE].nr_tsi,
		     		beacon_seq);

	if (!nr_bridges) {
		printf("No remote bridges detected\n");
		return;
	}

	for(b = remote_bridge; b < remote_bridge + nr_bridges; b++) {
		char ex[30];
		char origin_roce[INET_ADDRSTRLEN];

		if (b->expiration && b->expiration > now)
			sprintf(ex, "%11ld ms", ((b->expiration - now) / ONE_MILLISECOND));
		else
			strcpy(ex, "Expired       ");

		inet_ntop(AF_INET, &b->origin[ROCE], origin_roce, INET_ADDRSTRLEN);

		printf("%2lu|%-17s|%8x|%s|%s|%5u|%4u|%3u|%3u|%ld us %ld us %ld us\n",
				(b - remote_bridge) + 1,
				b->last.name,
				b->last.sessionid,
				ex,
				b->active ? "Dead" : "OK  ",
				b->beacons_received,
				b->beacons_missed,
				b->last.nr_mc,
				b->last.nr_tsi,
		     		b->distance[0], b->distance[1], b->distance[2]);
	}
}

__attribute__((constructor))
static void beacon_init(void)
{
	srand(time(NULL));
	sessionid = rand();
	if (gethostname(hostname, sizeof(hostname)) < 0)
			logg(LOG_CRIT, "Cannot determine hostname: %s\n", errname());

	register_option("beacon", optional_argument, 'b', beacon_option,
			"<addr>[:port][/interval]", "Send beacon in given milliseconds. 1 second by default");
	register_concom("beacons", true, 0, "Show Beacon info", beacon_cmd);
	register_enable("binterval", true, NULL, &beacon_interval, "1000", "100", NULL, "Beacon Interval");
	register_enable("beacon", true, &beacon, NULL, "On", "Off", NULL, "Switch beacon off");

}

