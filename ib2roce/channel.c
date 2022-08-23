/*
 * RDMA channel implementation
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

#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <infiniband/mad.h>


#include "fifo.h"
#include "interfaces.h"
#include "channel.h"
#include "cli.h"
#include "beacon.h"

const char *interfaces_text[NR_INTERFACES] = { "Infiniband", "ROCE" };

const char *stats_text[nr_stats] = {
	"PacketsReceived", "PacketsSent", "PacketsBridged", "PacketsInvalid", "PacketsQueued",
	"JoinRequests", "JoinFailures", "JoinSuccess", "LeaveRequests",
	"pgmdup", "pgm_odata", "pgm_rdata", "pgm_spm", "pgm_nak"
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

void show_core_config(void)
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

struct rdma_channel *new_rdma_channel(struct i2r_interface *i, enum channel_type type)
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

static bool loopback_blocking = true;	/* Ask for loopback blocking on Multicast QPs */

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

unsigned default_port = 0;	/* Port to use to bind to devices  */

static void port_set(char *optarg)
{
	default_port = atoi(optarg);
}

static bool setup_multicast(struct rdma_channel *c)
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

static bool setup_incoming(struct rdma_channel *c)
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

struct channel_info channel_infos[nr_channel_types] = {
	{ "multicast",	0, 0,	10000,	1000,	0,		IBV_QPT_UD,		setup_multicast, receive_multicast, channel_err },
	{ "ud",		1, 1,	500,	200,	RDMA_UDP_QKEY,	IBV_QPT_UD,		setup_channel,	receive_ud,	channel_err },
	{ "qp1",	2, 1,	10,	5,	IB_DEFAULT_QP1_QKEY, IBV_QPT_UD,	setup_channel,	receive_qp1,	channel_err },
	{ "raw",	3, 1,	1000, 	5,	0x12345,	IBV_QPT_RAW_PACKET,	setup_raw,	receive_raw,	channel_packet },
	{ "ibraw",	3, 1,	1000,	5,	0x12345,	IBV_QPT_UD,		setup_raw,	receive_raw,	channel_packet },
	{ "packet",	-1, -1,	0,	0,	0,		0,			setup_packet,	receive_raw,	channel_err },
	{ "incoming",	-1, -1,	100,	50,	0,		0,			setup_incoming,	receive_main,	channel_err },
	{ "error",	-1, -1,	0,	0,	0,		0,			NULL,		NULL,		channel_err },
};

static bool flow_steering = false;	/* Use flow steering to filter packets */

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


void channel_destroy(struct rdma_channel *c)
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

void start_channel(struct rdma_channel *c)
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

void stop_channel(struct rdma_channel *c)
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


void arm_channel(struct rdma_channel *c)
{
	ibv_req_notify_cq(c->cq, 0);
}

void arm_channels(struct core_info *core)
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

static int stat_interval = 10;		/* Interval for statistics */

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

void calculate_pps(void *private)
{
	for(struct i2r_interface *i = i2r; i < i2r + NR_INTERFACES; i++)
	if (i->context)
	{
		if (i->multicast)
			calculate_pps_channel(i->multicast);

		if (i->ud)
			calculate_pps_channel(i->ud);

	}

	run_bridge_channels(calculate_pps_channel);
	add_event(now + seconds(stat_interval), calculate_pps, NULL, "pps calculation");
}

int channel_stats(char *b, struct rdma_channel *c, const char *interface, const char *type)
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

void channel_stat(struct rdma_channel *c)
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
#ifdef UNICAST
		if (i->ud)
			channel_stat(i->ud);
		if (i->raw)
			channel_stat(i->raw);
		if (i->qp1)
			channel_stat(i->qp1);
#endif
	}
}

__attribute__((constructor))
static void channel_init(void)
{
	register_concom("channels", true, 0, "Print information about communication channels", channels_cmd);

	register_enable("flow", false, &flow_steering, NULL, "on", "off", NULL,
		"Enable flow steering to limit the traffic on the RAW sockets [Experimental, Broken]");

	register_enable("loopbackprev", false, &loopback_blocking, NULL, "on", "off", NULL,
		"Multicast loopback prevention of the NIC");

	register_option("port", required_argument, 'p', port_set,
		       "<number>", "Set default port number to use if none is specified");

	register_enable("statint", true, NULL, &stat_interval, "60", "1", NULL,
		"Sampling interval to calculate pps values");
}
