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
#include <stdatomic.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <getopt.h>
#include <rdma/rdma_cma.h>
#include <poll.h>
#include <sys/mman.h>
#include <numa.h>
#include <infiniband/mad.h>
#include <linux/if_arp.h>


#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <infiniband/umad_cm.h>
#include <infiniband/umad_str.h>
#include <execinfo.h>
#include "errno.h"
#include "bth_hdr.h"
#include "ib_hdrs.h"
#include "fifo.h"
#include "ring.h"
#include "hash.h"
#include "sched.h"
#include "logging.h"
#include "locking.h"
#include "buffers.h"
#include "multicast.h"
#include "interfaces.h"
#include "beacon.h"
#include "cli.h"
#include "pgm.h"
#include "endpoint.h"

#include "ibraw.h"
#include "cma-hdr.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

/* Globals */

static bool debug = false;		/* Stay in foreground, print more details */
static bool update_requested = false;	/* Received SIGUSR1. Dump all MC data details */
static bool testing = false;		/* Run some tests on startup */
static int drop_packets = 0;		/* Packet dropper */


/*
 * Basic RDMA interface management
 */

#define MAX_INLINE_DATA 64

#ifdef UNICAST
static setup_callback setup_channel, setup_raw, setup_packet, setup_incoming;
#endif

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

#ifdef HAVE_MSTFLINT
static void shutdown_sniffer(int arg) {
	struct i2r_interface *i = i2r + INFINIBAND;

	if (clear_ib_sniffer(i->port, i->raw->qp))
		logg(LOG_ERR, "Failed to switch off sniffer mode on %s\n", i->raw->text);
	else
		logg(LOG_NOTICE, "ABORT handler cleared the sniffer mode on Infiniband\n");
}
#endif

static void unicast_packet(struct rdma_channel *c, struct buf *buf, struct in_addr dest_addr)
{
	unsigned long l;

	memcpy(&l, buf->cur, sizeof(long));
//	if (l == BEACON_SIGNATURE) {
//		beacon_received(buf);
//		return;
//	}

	dump_buf_grh(buf);
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
void receive_multicast(struct buf *buf)
{
	struct mc *m;
	struct rdma_channel *c = buf->c;
	enum interfaces in = c->i - i2r;
	struct ib_addr *dgid = (struct ib_addr *)&buf->grh.dgid.raw;
	struct in_addr dest_addr;
	int ret;
	const char *reason = NULL;

	learn_source_address(buf);

	if (!buf->grh_valid) {
		logg(LOG_WARNING, "No GRH on %s. Packet discarded: %s\n",
			c->text, payload_dump(buf->cur));
		goto invalid_packet;
	}

	if (buf->ip_valid) {

		if (!IN_MULTICAST(ntohl(buf->ip.daddr))) {
			reason = "Unicast Packet";
			goto discardit;
		}

		if (buf->ip.saddr == c->i->if_addr.sin_addr.s_addr) {
			reason = "Loopback Packet";
			goto discardit;
		}

		
		if (!__valid_addr(c->i, buf->ip.saddr)) {
			reason = "Packet not originating on source interface";
			goto discardit;
		}

	} else /* ! buf->ip_valid */ {

		if (buf->grh.dgid.raw[0] !=  0xff) {
			reason = "Unicast Packet";
			goto discardit;
		}

		if (memcmp(&buf->grh.sgid, &c->i->gid, sizeof(union ibv_gid)) == 0) {

			logg(LOG_DEBUG, "Loopback Packet");
			goto discardit;
		}

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

		if (!mgid_check(m, signature)) {
			logg(LOG_INFO, "Discard Packet: MGID multicast signature(%x)  mismatch. MGID=%s\n",
					signature, inet6_ntoa(mgid));
			goto invalid_packet;
		}

	}

	if (m->callback) {
		m->callback(m, in, buf);
		return;
	}

	if (!m->enabled)
		return;

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
	struct rdma_channel *ch_out = mi->channel;

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

discardit:    
	logg(LOG_WARNING, "%s on multicast channel %s: GRH=%s %s\n", reason, c->text, grh_str(&buf->grh), payload_dump(buf->cur));

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
void receive_main(struct buf *buf)
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

void receive_raw(struct buf *buf)
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
void receive_ud(struct buf *buf)
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
void receive_qp1(struct buf *buf)
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

static int status_fd;

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
			mgid_text(m),
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

static void brief_status(void)
{
	char buf[4000];
	char buf2[4200];
	char counts[200];

	unsigned n = 0;
	const char *events;

	n = get_timer_list(buf, ',');

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
#ifdef UNICAST
		if (i->ud && i->ud->stats[packets_received])
			n+= sprintf(counts + n, ", UD %d/%d",
				i->ud->stats[packets_received],
				i->ud->stats[packets_sent]);
		if (i->raw && i->raw->stats[packets_received])
			n+= sprintf(counts + n, ", RAW %d", i->raw->stats[packets_received]);
#endif
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

static void setup_timed_events(void)
{
	now = timestamp();

	if (background) {
		add_event(now + seconds(30), status_write, NULL, "Write Status File");
		logging(NULL);
	}

	calculate_pps(NULL);

	check_joins(i2r[INFINIBAND].multicast, i2r[ROCE].multicast);
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

static char pid_name[40];

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

	if (default_port)
		snprintf(pid_name, sizeof(pid_name), "ib2roce-%d.pid", default_port);
	else
		strcpy(pid_name, "ib2roce.pid");

	pid_fd = open(pid_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

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
	unlink(pid_name);
	close(pid_fd);
}

static void debug_set(char *optarg)
{
	debug = true;
}

static void test_set(char *optarg)
{
	ring_test();
	fifo_test();
	hash_test();
	testing = true;
}

static void setup_options(void)
{
	register_option("debug", no_argument, 'x', debug_set,
		       	NULL, "Do not daemonize, enter command line mode");
	register_option("test", no_argument, 'q', test_set, NULL, "Run selftest");
}

static void setup_enable(void)
{
	register_enable("bridging", false, &bridging, NULL, "on", "off", NULL,
		"Forwarding of packets between interfaces");
	register_enable("drop", true, NULL, &drop_packets, "100", "0", NULL,
		"Drop multicast packets. The value is the number of multicast packets to send before dropping");
	register_enable("pgm", true,NULL, (int *)&pgm_mode, "on", "off", NULL,
		"PGM processing mode (0=None, 1= Passtrough, 2=DLR, 3=Resend with new TSI");
	register_enable("hwrate", true, NULL, &rate, "6", "0", NULL,
		"Set the speed in the RDMA NIC to limit the output speed 2 =2.5GBPS 5 = 5GBPS 3 = 10GBPS ...(see enum ibv_rate)");
	register_enable("irate", true,NULL, &irate, "1000", "0", set_rates,
		"Infiniband: Limit the packets per second to be sent to an endpoint (0=off)");
	register_enable("rrate", true,NULL, &rrate, "1000", "0", set_rates,
		"ROCE: Limit the packets per second to be sent to an endpoint (0=off)");
	register_enable("iburst", true,	NULL, &max_iburst, "100", "0", set_rates,
		"Infiniband: Exempt the first N packets from swrate (0=off)");
	register_enable("rburst", true,	NULL, &max_rburst, "100", "0", set_rates,
		"ROCE: Exempt the first N packets from swrate (0=off)");
}

__attribute__((constructor))
static void options_init(void)
{
	setup_options();
	setup_enable();
}


int main(int argc, char **argv)
{
	int ret = 0;

	sidr_state_init();

	parse_options(argc, argv);

	if (debug || !bridging) {
		openlog("ib2roce", LOG_PERROR, LOG_USER);
		concom_init();
	} else {
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
			nr_mc, mgid_text(NULL), nr_buffers);

	numa_run_on_node(i2r[INFINIBAND].context ? i2r[INFINIBAND].numa_node : i2r[ROCE].numa_node);
	init_buf();	/* Setup interface registers memmory */
	numa_run_on_node(-1);

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

	beacon_setup();


	post_receive_buffers();

	send_queue_monitor(NULL);

	start_cores();
	arm_channels(NULL);
	setup_timed_events();

	if (event_loop() <0)
		logg(LOG_ERR, "Event Loop failed with %s\n", errname());

	beacon_shutdown();
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
