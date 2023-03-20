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
#include "pgm.h"
#include "unicast.h"

const char *interfaces_text[NR_INTERFACES] = { "Infiniband", "ROCE" };

const char *stats_text[nr_stats] = {
	"PacketsReceived", "PacketsSent", "PacketsBridged", "PacketsInvalid", "PacketsQueued",
	"JoinRequests", "JoinFailures", "JoinSuccess", "LeaveRequests"
};

bool latency = false;

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
static short core_lookup(struct i2r_interface *i,  enum channel_type type, int instance)
{
	short core = channel_infos[type].core;

	if (!cores)
		goto nocore;

	if (instance) {
		core += (instance - 1);
		core %= cores;
	}

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
				n += sprintf(b + n, "%s ", ci->channel[j]->text);
			}
		} else {
			n += sprintf(b + n, "<not used>");
		}

		n += sprintf(b +n,"\n");
		logg(LOG_NOTICE, "Core %d: NUMA=%d %s", i, ci->numa_node, b);

	}
}

struct rdma_channel *new_rdma_channel(struct i2r_interface *i, enum channel_type type, unsigned instance)
{
	struct rdma_channel *c;
	struct channel_info *ci;
	struct core_info *coi = NULL;
	char *p;
	short core;
	int channel_nr;
	unsigned rdma_channel_size = sizeof(struct rdma_channel) + i->mc_per_qp * sizeof(struct mc *);

retry:
	ci = channel_infos + type;
	channel_nr = -1;
	c = calloc(1, rdma_channel_size);

	core = core_lookup(i, type, instance);
	if (core != NO_CORE) {
		coi = core_infos + core;

		channel_nr = coi->nr_channels;
		coi->channel[channel_nr] = c;
		coi->nr_channels++;
		if (coi->nr_channels > MAX_CQS_PER_CORE)
			panic("Too many RDMA channels per core. Max = %d\n", MAX_CQS_PER_CORE);

		c->core = coi;

	}

	if (type == channel_err)
		goto err;

	c->i = i;
	c->type = type;
	c->receive = ci->receive;
	c->instance = instance;

	p = malloc(strlen(i->text) + strlen(ci->suffix) + 2 + 4);

	if (instance)
		sprintf(p, "%s-%s(%d)", i->text, ci->suffix, instance);
	else
		sprintf(p, "%s-%s", i->text, ci->suffix);

	c->text = p;

	c->nr_cq = ci->nr_cq;
	c->nr_send = ci->nr_send;
	c->nr_receive = ci->nr_cq - ci->nr_send;
	c->max_backlog = 10000;
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

int allocate_rdmacm_qp(struct rdma_channel *c, bool multicast)
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

	/* XXX This is not going to work for multi channel RDMA */
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
			IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_QKEY);

	if (ret) {
		logg(LOG_CRIT, "ibv_modify_qp: Error when moving %s to Init state. %s\n", c->text, errname());
		ibv_destroy_qp(c->qp);
		ibv_destroy_cq(c->cq);
		c->qp = NULL;
		return false;
	}
	return true;
}

struct channel_info channel_infos[nr_channel_types] = {
	{ "multicast",	0, 0,	10000,	1000,	0,		IBV_QPT_UD,		setup_multicast, receive_multicast, channel_err },
	{ "ud",		1, 1,	500,	200,	RDMA_UDP_QKEY,	IBV_QPT_UD,		setup_channel,	receive_ud,	channel_err },
	{ "incoming",	-1, -1,	100,	50,	0,		0,			setup_incoming,	NULL,		channel_err },
	{ "error",	-1, -1,	0,	0,	0,		0,			NULL,		NULL,		channel_err },
};

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
	} else {
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

	c->attr.qp_state = IBV_QPS_RTS;
	ret = ibv_modify_qp(c->qp, &c->attr, IBV_QP_STATE | IBV_QP_SQ_PSN);

	if (ret)
		logg(LOG_CRIT, "ibv_modify_qp: Error when moving %s to RTS state. %s\n", c->text, errname());

	logg(LOG_NOTICE, "QP %s moved to state RTS/RTR: QPN=%d\n",
		 c->text, c->qp->qp_num);
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

void all_channels(FILE *out, void (*func)(FILE *out, struct rdma_channel *))
{
 	interface_foreach(i)
		channel_foreach(c, &i->channels)
				func(out, c);
}

bool is_a_channel_of(struct rdma_channel *c, struct channel_list *cl)
{
	channel_foreach(c2, cl)
		if (c2 == c)
			return true;
	return false;
}

void arm_channel(struct rdma_channel *c)
{
	ibv_req_notify_cq(c->cq, 0);
}

void arm_channels(struct core_info *core)
{
	interface_foreach(i)
		channel_foreach(c, &i->channels) {

			switch (c->type) {
		   		case  channel_rdmacm:
		  			if (core == c->core) {
						ibv_req_notify_cq(c->cq, 0);
					}
					break;

				case channel_ud:
 					if (core == c->core) {
						start_channel(c);
						ibv_req_notify_cq(c->cq, 0);
					}
					break;

				default:
					break;
			}
 		}
}

static int stat_interval = 10;		/* Interval for statistics */
static uint64_t stat_start;		/* Starting the next calculation */

static void calculate_pps_channel(FILE *out, struct rdma_channel *c)
{
	if (c->last_snapshot) {
		uint64_t tdiff = now - c->last_snapshot;

		c->pps_in = (seconds(c->stats[packets_received] - c->last_received) + tdiff/2) / tdiff;
		c->pps_out = (seconds(c->stats[packets_sent] - c->last_sent) + tdiff/2) / tdiff;

		if (c->pps_in > c->max_pps_in)
			c->max_pps_in = c->pps_in;

		if (c->pps_out > c->max_pps_out)
			c->max_pps_out = c->pps_out;

	}
	c->last_received = c->stats[packets_received];
	c->last_sent = c->stats[packets_sent];
	c->last_snapshot = now;
}

static bool pps_display;

static void calculate_pps(void *private)
{
	all_channels(NULL, calculate_pps_channel);
	stat_start += seconds(stat_interval);
	add_event(stat_start, calculate_pps, NULL, "pps calculation");

	if (pps_display) {
		int n = 0;
		char buf[4000];

 		interface_foreach(i) {
			unsigned pps_in = 0;
			unsigned pps_out = 0;

			channel_foreach(c, &i->channels) {
				pps_in += c->pps_in;
				pps_out += c->pps_out;
			}
			if (pps_in || pps_out) {
				n += sprintf(buf + n, "%s ", i->text);
				if (pps_in)
					n += sprintf(buf + n, "%s in ", print_count(pps_in));
				if (pps_out)
					n += sprintf(buf + n, "%s out ", print_count(pps_out));
			}
	
			if (pgm_mode)
				n += pgm_brief_stats(buf + n, i);
		}
		if (n)
			logg(LOG_INFO,"pps: %s\n", buf);
	}
}

void start_calculate_pps(void)
{
	stat_start = now;
	calculate_pps(NULL);
}

static void channel_zap(FILE *out, struct rdma_channel *c)
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
	c->bytes_received = 0;
	c->bytes_sent = 0;
	c->min_packet_size = 0;
	c->max_packet_size = 0;
}


static void zap_cmd(FILE *out, char *parameters)
{
	all_channels(NULL, channel_zap);
	fprintf(out, "Ok\n");
}

int channel_stats(char *b, struct rdma_channel *c, const char *interface, const char *type)
{
	int n = 0;
	int j;

	n += sprintf(b + n, "\nChannel %s:\n", type);

	for(j =0; j < nr_stats; j++)
		if (c->stats[j]) {
			n += sprintf(b + n, "%s=%u\n", stats_text[j], c->stats[j]);
	}
	if (c->bytes_sent)
		n += sprintf(b +n, "bytes sent=%lu\n", c->bytes_sent);

	if (c->bytes_received)
		n += sprintf(b +n, "bytes received=%lu\n", c->bytes_received);

	if (c->min_packet_size)
		n += sprintf(b + n, "MinPSize=%u\n", c->min_packet_size);

	if (c->max_packet_size)
		n += sprintf(b + n, "MaxPSize=%u\n", c->max_packet_size);

	if (c->stats[packets_received]) {
		n += sprintf(b +n, "AvgPsize=%lu\n", c->bytes_received / c->stats[packets_received]);
	}

	return n;
}

void channel_stat(int indent, FILE *out, struct rdma_channel *c)
{
	char indent_str[10];

	if (indent > sizeof(indent_str) - 1)
		panic("indent too high");

	memset(indent_str, ' ', indent);
	indent_str[indent] = 0;

	fprintf(out, "%sChannel %s: ActRecvBuf=%u/%u ActSendBuf=%u/%u CQ_high=%u BackLog=%u BacklogDrops=%u Port=%d QPN=%d nr_multicast=%u",
		indent_str, c->text, c->active_receive_buffers, c->nr_receive,
		c->active_send_buffers, c->nr_send, c->cq_high,
		fifo_items(&c->send_queue), c->backlog_drop,
		ntohs(((struct sockaddr_in *)c->bindaddr)->sin_port), c->qp->qp_num, c->nr_mcs);

		if (c->last_snapshot) {
			if (c->pps_in)
			 	fprintf(out, " pps_in=%u", c->max_pps_in);
			if (c->pps_out)
			 	fprintf(out, " pps_out=%u", c->max_pps_out);
			if (c->max_pps_in)
			 	fprintf(out, " max_pps_in=%u", c->max_pps_in);
			if (c->max_pps_out)
			 	fprintf(out, " max_pps_out=%u", c->max_pps_out);
	}

	for(int k = 0; k < nr_stats; k++)
		if (c->stats[k])
			fprintf(out, " %s=%u", stats_text[k], c->stats[k]);

	fprintf(out, "\n");
}

static void channel_stat_indent_0(FILE *f, struct rdma_channel *c)
{
	channel_stat(0, f, c);
}

static void channels_cmd(FILE *out, char *parameters)
{
	all_channels(out, channel_stat_indent_0);
}

__attribute__((constructor))
static void channel_init(void)
{
	register_concom("zap", true, 0, "Clear counters", zap_cmd );
	register_concom("channels", true, 0, "Print information about communication channels", channels_cmd);

	register_enable("loopbackprev", false, &loopback_blocking, NULL, "on", "off", NULL,
		"Multicast loopback prevention of the NIC");

	register_enable("ppsdisplay", true, &pps_display, NULL, "on", "off", NULL,
		"Display pps in and out of interfaces");

	register_option("port", required_argument, 'p', port_set,
		       "<number>", "Set default port number to use if none is specified");

	register_enable("statint", true, NULL, &stat_interval, "60", "1", NULL,
		"Sampling interval to calculate pps values");
	register_enable("latency", true, &latency, NULL, "on", "off", NULL,
		"Collect latency statistics for cores busy polling");
}
