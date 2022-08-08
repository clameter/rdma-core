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

#include "beacon.h"

#define BEACON_SIGNATURE 0xD3ADB33F

static bool beacon = false;		/* Announce our presence (and possibly coordinate between multiple instances in the future */

const char *beacon_arg = NULL;

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

static struct mc *beacon_mc;		/* == NULL if unicast */
static struct sockaddr_in *beacon_sin;

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

static void beacon_received(struct mc *m, enum interfaces in, struct buf *buf)
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

	}
#ifdef UNICAST
	else {
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
#endif
	add_event(timestamp() + seconds(10), beacon_send, NULL, "Send Beacon");
}

void beacon_setup(void)
{
	struct mgid_signature *mgid;
	struct in_addr addr;
	uint8_t tos;

	if (!beacon)
		return;

	if (!beacon_arg)
		beacon_arg = "239.1.2.3";

	beacon_mc = NULL;
	beacon_sin = parse_addr(beacon_arg, default_mc_port, &mgid, &tos, false);
	addr = beacon_sin->sin_addr;
	if (IN_MULTICAST(ntohl(addr.s_addr))) {
		struct mc *m = mcs + nr_mc++;

		memset(m, 0, sizeof(*m));
		m->text = strdup(beacon_arg);
		m->mgid_mode = mgid;
		m->tos_mode = tos;
		m->addr = addr;

		setup_mc_addrs(m, beacon_sin);

		if (hash_add_mc(m)) {
			logg(LOG_ERR, "Beacon MC already in use.\n");
			beacon = false;
			free(beacon_sin);
			beacon_sin = NULL;
		} else
			beacon_mc = m;
		m->callback = beacon_received;
	}
	add_event(timestamp() + ONE_SECOND, beacon_send, NULL, "Send Beacon");
}

static void beacon_option(char *optarg)
{
	beacon = true;

	beacon_arg = optarg;
}

__attribute__((constructor))
static void beacon_init(void) {
	register_option("beacon", optional_argument, 'b', beacon_option,
			"<multicast address>/<unicast address>", "Send beacon every second. Off by default");
}

