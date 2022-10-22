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
#include "multicast.h"
#include "interfaces.h"
#include "beacon.h"
#include "cli.h"
#include "pgm.h"
#include "endpoint.h"
#include "unicast.h"

#include "ibraw.h"
#include "cma-hdr.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

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

__attribute__((constructor))
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
	struct rdma_channel *qp1 = find_channel(e->i, channel_qp1);

	buf->cur = mad_pos;
	buf->end = mad_pos + 256;

	send_ud(qp1, buf, e->ah, 1, IB_DEFAULT_QP1_QKEY);
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
		struct rdma_channel *qp1 = find_channel(dest_i, channel_qp1);
		struct rdma_channel *ud = find_channel(dest_i, channel_ud);

		hash_add(sidrs, ss);
		unlock();

		/* Source QPN is not valid for target network use the QP number of the UD QP */
		ch->src_addr.ip4.sess_qpn = htonl(ud->qp->qp_num);
		/* Ensure the SIDR_REP gets back to our QP1 */
		ch->src_addr.ip4.sidr_qpn = ntohl(qp1->qp->qp_num);

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

	qpn_word = (find_channel(ss->source->i, channel_ud)->qp->qp_num << 8) | (qpn_word & 0xff);
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
		buf->imm = htonl(find_channel(f->dest->i, channel_ud)->qp->qp_num);

	logg(LOG_NOTICE, "receive_ud %s Packet len=%u 0x%x lid=%d forwarded to %s %s:0x%x lid=%d qkey=%x\n", c->text,
			w->byte_len, w->src_qp, e->lid, find_channel(dest_i, channel_ud)->text,
				inet_ntoa(f->dest->addr), f->dest_qp, f->dest->lid, f->dest_qkey);

	send_ud(find_channel(dest_i, channel_ud), buf, f->dest->ah, f->dest_qp, f->dest_qkey);
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


