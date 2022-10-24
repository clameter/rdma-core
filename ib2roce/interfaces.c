/*
 * RDMA Interfaces
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
#include <rdma/rdma_cma.h>
#include <infiniband/ib.h>
#include <infiniband/verbs.h>
#include <sys/ioctl.h>
#include <numa.h>

#include "packet.h"
#include "errno.h"
#include "fifo.h"
#include "ring.h"
#include "hash.h"
#include "sched.h"
#include "logging.h"
#include "locking.h"
#include "buffers.h"
#include "multicast.h"
#include "interfaces.h"
#include "cli.h"
#include "endpoint.h"

char *ib_name, *roce_name;

int rate = IBV_RATE_10_GBPS;	/* Limit sending rate */
int rrate = 0;			/* Software delay per message for ROCE */
int irate = 0;			/* Software delay per message for Infiniband */
int max_rburst = 10;		/* Dont delay until # of packets for ROCE */
int max_iburst = 10;		/* Dont delay until # of packets for Infiniband */

bool bridging = true;		/* Allow briding */
bool unicast = false;		/* Bridge unicast packets */
static bool raw = false;		/* Use raw channels */
static bool packet_socket = false;	/* Do not use RAW QPs, use packet socket instead */


struct i2r_interface i2r[NR_INTERFACES];

const char *inet6_ntoa(void *x)
{
	char buf[INET6_ADDRSTRLEN];

	return inet_ntop(AF_INET6, x, buf, INET6_ADDRSTRLEN);
}

void set_rate(struct mc *m)
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

void set_rates(void)
{
	int j;

	for (j = 0; j < nr_mc; j++) {
		struct mc *m = mcs + j;

		set_rate(m);
		set_rate(m);
	}
}

/* Check the RDMA device if it fits what was specified on the command line and store it if it matches */
int check_rdma_device(enum interfaces i, int port, char *name,
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
int find_rdma_devices(void)
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

static void qp_destroy(struct i2r_interface *i)
{
#ifdef HAVE_MSTFLINT
	if (i == i2r + INFINIBAND && i->raw && i->raw->type == channel_ibraw) {
		if (clear_ib_sniffer(i->port, i->raw->qp))
			logg(LOG_ERR, "Failed to switch off sniffer mode on %s\n", i->raw->text);
	}
#endif

	channelp_foreach(c, &i->channels) {
		if (*c) {
			channel_destroy(*c);
			*c = NULL;
		}
	}
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

/* Check overrun counter */
void check_out_of_buffer(void *private)
{
	struct i2r_interface *i = private;
	int fh;
	char buffer[100];
	unsigned long out_of_buffer;

	snprintf(buffer, sizeof(buffer), "/sys/class/infiniband/%s/ports/%d/hw_counters/out_of_buffer", i->rdma_name, i->port);
	fh = open(buffer, O_RDONLY);
	if (read(fh, buffer, sizeof(buffer)) < 0) {
		logg(LOG_CRIT, "Cannot read out_of_buffer counter from sysfs. %s\n", errname());
		close(fh);
		return;
	}
	close(fh);

	out_of_buffer = atol(buffer);
	if (i->out_of_buffer != out_of_buffer) {
		if (i->out_of_buffer)
			logg(LOG_ERR, "Out of Buffer on %s. %ld packets dropped (was %ld, now %ld)\n",
					i->text, out_of_buffer - i->out_of_buffer, i->out_of_buffer, out_of_buffer);

		i->out_of_buffer = out_of_buffer;
	}
	add_event(now + ONE_SECOND, check_out_of_buffer, i, "Check out of buffers");
}

/* Find an RDMA channel by type */
struct rdma_channel *find_channel(struct i2r_interface *i, enum channel_type type)
{
	channel_foreach(c, &i->channels) {

		if (c->type == type)
			return c;
	}

	panic("Cannot find channel type %u on interface %s\n", type, i->text);
	return NULL;
}

void setup_interface(enum interfaces in)
{
	struct i2r_interface *i = i2r + in;
	struct ibv_gid_entry *e;
	struct rdma_channel *multicast= NULL;
	struct rdma_channel *qp1 = NULL;
	struct rdma_channel *raw_channel = NULL;
	struct rdma_channel *ud = NULL;
	unsigned channels;

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

	/* Calculate number of required RDMA channels for multicast */
	channels = 1 + nr_mc / i->device_attr.max_mcast_grp;

	for (int j = 0; j < channels; j++) {
		char buf[5];

		snprintf(buf, sizeof(buf), "%d", j);
		i->channels.c[j] = multicast = new_rdma_channel(i, channel_rdmacm, buf);

		if (!multicast)
			panic("Cannot create %d rdma channels required for multicast\n", channels);

	}

	if (unicast) {

		i->channels.c[channels++] = ud = new_rdma_channel(i, channel_ud, NULL);
		i->channels.c[channels++] = qp1 = new_rdma_channel(i, channel_qp1, NULL);

 		if (raw) {
 			if (i == i2r + INFINIBAND) {
				i->channels.c[channels++] = raw_channel = new_rdma_channel(i, channel_ibraw, NULL);
 				/* Sadly fallback is not working here */
 			} else {
 				if (packet_socket)
					i->channels.c[channels++] = new_rdma_channel(i, channel_packet, NULL);
 				else
					i->channels.c[channels++] = new_rdma_channel(i, channel_raw, NULL);
 			}
 		}
 	}

	if (channels > MAX_CHANNELS_PER_INTERFACE)
		panic("Too many channels for interface %s\n", i->text);

 	check_out_of_buffer(i);
 	numa_run_on_node(-1);

	logg(LOG_NOTICE, "%s interface %s/%s(%d) port %d GID=%s/%d IPv4=%s:%d CQs=%u"
		"/%u/%u"
			" MTU=%u NUMA=%d.\n",
		i->text,
		i->rdma_name,
		i->if_name, i->ifindex,
		i->port,
		inet6_ntoa(e->gid.raw), i->gid_index,
		inet_ntoa(i->if_addr.sin_addr), default_port,
		multicast ? multicast->nr_cq: 0,
		ud ? ud->nr_cq : 0,
		raw_channel ? raw_channel->nr_cq : 0,
		i->mtu,
		i->numa_node
	);
}

void shutdown_ib(void)
{
	if (!i2r[INFINIBAND].context)
		return;

	channel_foreach(c, &i2r[INFINIBAND].channels) {
		if (c->type == channel_rdmacm)
			leave_mc(INFINIBAND, c);
	}

	/* Shutdown Interface */
	qp_destroy(i2r + INFINIBAND);
}

void shutdown_roce(void)
{
	if (!i2r[ROCE].context)
		return;

	channel_foreach(c, &i2r[ROCE].channels) {
		if (c->type == channel_rdmacm)
			leave_mc(ROCE, c);
	}

	/* Shutdown Interface */
	qp_destroy(i2r + ROCE);
}

void handle_rdma_event(void *private)
{
	struct i2r_interface *i = private;
	struct rdma_cm_event *event;
	int ret;
	enum interfaces in = i - i2r;
#ifdef UNICAST
	struct rdma_unicast *ru = fifo_first(&i->resolve_queue);
#endif

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
				struct rdma_channel *c = m->interface[in].channel;

				a->remote_qpn = param->qp_num;
				a->remote_qkey = param->qkey;

				if (rate)
					param->ah_attr.static_rate = rate;

				if (m->tos_mode)
					param->ah_attr.grh.traffic_class = m->tos_mode;

				/* This is set as a marker so that another ib2roce can
				 * discern that a message loop exists and avoid
				 * forwarding the packet.
				 * By default the hop_limit is 0!!!
				 */
				param->ah_attr.grh.hop_limit = 1;

				a->ah = ibv_create_ah(c->pd, &param->ah_attr);
				if (!a->ah) {
					logg(LOG_ERR, "Failed to create AH for Multicast group %s on %s \n",
						m->text, i->text);
					m->interface[in].status = MC_ERROR;
					break;
				}
				m->interface[in].status = MC_JOINED;

				logg(LOG_NOTICE, "Joined %s MLID 0x%x tos %u sl %u on %s\n",
					inet6_ntoa(param->ah_attr.grh.dgid.raw),
					param->ah_attr.dlid,
					m->tos_mode,
					param->ah_attr.sl,
					c->text);
				st(c, join_success);
				set_rate(m);

				/* Things actually work if both multicast groups are joined */
				if (!bridging || m->interface[in^1].status == MC_JOINED)
			       		next_join_complete();

			}
			break;

		case RDMA_CM_EVENT_MULTICAST_ERROR:
			{
				struct rdma_ud_param *param = &event->param.ud;
				struct mc *m = (struct mc *)param->private_data;
				struct rdma_channel *c = m->interface[in].channel;

				logg(LOG_ERR, "Multicast Error. Group %s on %s\n",
					m->text, i->text);

				/* If already joined then the bridging may no longer work */
				if (!bridging || (m->interface[in].status == MC_JOINED && m->interface[in^1].status == MC_JOINED))
				       active_mc--;

				m->interface[in].status = MC_ERROR;
				st(c, join_failure);
			}
			break;

#ifdef UNICAST
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
#endif

		default:
			logg(LOG_NOTICE, "RDMA Event handler:%s status: %d\n",
				rdma_event_str(event->event), event->status);
			break;
	}

	rdma_ack_cm_event(event);
	return;

#ifdef UNICAST
err:
	rdma_ack_cm_event(event);
	ru->state = UC_ERROR;
	resolve_end(ru);
#endif
}

void handle_async_event(void *private)
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

	terminate(0);

        ibv_ack_async_event(&event);
}

/*
 * Handling of RDMA work requests
 */
void post_receive(struct rdma_channel *c)
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

void post_receive_buffers(void)
{
	interface_foreach(i)
		channel_foreach(c, &i->channels)
			post_receive(c);
}

void reset_flags(struct buf *buf)
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

/*
 * Polling function for each core enabling low latency operations.
 * This currently does not support NUMA affinities. It may need
 * to benefit from manually setting affinities but -- aside from the
 * obvious need to run on the NIC numa node that it serves --
 * the Linux scheduler should take care of most of what is needed.
 *
 * NOHZ should be enabled though to avoid hiccups from timer interrupts
 */
void scan_cqs(void *private)
{
	struct core_info *core = private;
	int i;
	int cqs;
	struct rdma_channel *c;
	struct ibv_wc wc[10];

	for(i = 0; i < core->nr_channels; i++) {
		cqs = ibv_poll_cq(core->channel[i]->cq, 10, wc);
		if (cqs) {
			c = core->channel[i];

			if (cqs > 0)
				process_cqes(c, wc, cqs);
			else {
				logg(LOG_WARNING, "Busyloop: CQ polling failed with: %s on %s\n",
						errname(), c->text);
				core->state = core_err;
				continue;
			}
		}
	}
}

void handle_comp_event(void *private)
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
void handle_receive_packet(void *private)
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

/* A mini router follows */
struct i2r_interface *find_interface(struct sockaddr_in *sin)
{
	interface_foreach(i) {
		unsigned netmask = i->if_netmask.sin_addr.s_addr;

		if ((sin->sin_addr.s_addr & netmask) ==  (i->if_addr.sin_addr.s_addr & netmask))
			return i;
	}

	return NULL;
}

unsigned show_interfaces(char *b)
{
	int n = 0;

	interface_foreach(i)
		channel_foreach(c, &i->channels)
			n += channel_stats(b + n, c, i->text, c->type == channel_rdmacm ? "Multicast" : c->text);

	return n;
}

static const char * gid_text[] = { "GID_TYPE_IB", "GID_TYPE_ROCE_V1", "GID_TYPE_ROCE_V2" };
static const char *port_state_text[] = { "PORT_NOP","PORT_DOWN","PORT_INIT","PORT_ARMED","PORT_ACTIVE","PORT_ACTIVE_DEFER" };
static const char *mtu_text[] = { "NONE", "256", "512", "1024", "2048", "4096" };
static const char *link_layer_text[] = { "UNSPECIFIED", "INFINIBAND", "ETHERNET" };

static void interfaces_cmd(FILE *out,char *parameters)
{
	int n;
	char b[5000];

	if (parameters) {
		interface_foreach(i)
			if (strncasecmp(i->text, parameters, strlen(parameters)) == 0) {
				fprintf(out, "Interface %s\n", i->text);
				fprintf(out, "-------------------------------------\n");
				fprintf(out, "RDMA device=%s Port=%d MTU=%d\n", i->rdma_name, i->port, i->mtu);
				fprintf(out, "NET device=%s IFindex=%d IP=%s ", i->if_name, i->ifindex, inet_ntoa(i->if_addr.sin_addr));
				fprintf(out, "Netmask=%s MacLen=%d MAC=%s\n", inet_ntoa(i->if_netmask.sin_addr), i->maclen, hexbytes(i->if_mac, i->maclen, '-'));
				fprintf(out, "GID %s GIDIndex=%d GIDtablesize=%d\n", inet6_ntoa(&i->gid), i->gid_index, i->iges);
				for(struct ibv_gid_entry *g = i->ige; g < i->ige + i->iges; g++) {
					fprintf(out, " gid=%s gid_index=%d port_num=%d gid_type=%s ndev_ifindex=%d\n",
							inet6_ntoa(&g->gid), g->gid_index, g->port_num, gid_text[g->gid_type], g->ndev_ifindex);

				}

				fprintf(out, "Device Attributes\n");
				fprintf(out, " Firmware=%s, NodeGUID=%lx Sys_Image_GUID=%lx\n",
					       i->device_attr.fw_ver,
					       be64toh(i->device_attr.node_guid),
					       be64toh(i->device_attr.sys_image_guid));
				fprintf(out, " max_mr_size=%ld page_size_cap=%lx vendor_id=%x vendor_part_id=%x hw_ver=%x",
					       i->device_attr.max_mr_size,
					       i->device_attr.page_size_cap,
					       i->device_attr.vendor_id,
					       i->device_attr.vendor_part_id,
					       i->device_attr.hw_ver);
				fprintf(out, " max_qp=%d max_qp_wr=%d device_cap_flags=%x\n",
					       i->device_attr.max_qp,
					       i->device_attr.max_qp_wr,
					       i->device_attr.device_cap_flags);
				fprintf(out, " max_sge=%d max_sge_rd=%d max_cq=%d max_cqe=%d max_mr=%d max_pd=%d max_qp_rd_atom=%d max_ee_rd_atom=%d\n",
					       i->device_attr.max_sge,
					       i->device_attr.max_sge_rd,
					       i->device_attr.max_cq,
					       i->device_attr.max_cqe,
					       i->device_attr.max_mr,
					       i->device_attr.max_pd,
					       i->device_attr.max_qp_rd_atom,
					       i->device_attr.max_ee_rd_atom);
				fprintf(out, " max_res_rd_atom=%d atomic_cap=%x max_ee=%d max_rdd=%d max_mw=%d\n",
					       i->device_attr.max_res_rd_atom,
					       i->device_attr.atomic_cap,
					       i->device_attr.max_ee,
					       i->device_attr.max_rdd,
					       i->device_attr.max_mw);
				fprintf(out, " max_raw_ipv6_qp=%d max_raw_ethy_qp=%d\n",
					       i->device_attr.max_raw_ipv6_qp,
					       i->device_attr.max_raw_ethy_qp);
				fprintf(out, " max_mcast_grp=%d max_mcast_qp_attach=%d max_total_mcast_qp_attach=%d\n",
					       i->device_attr.max_mcast_grp,
					       i->device_attr.max_mcast_qp_attach,
					       i->device_attr.max_total_mcast_qp_attach);
				fprintf(out, " max_ah=%d max_fmr=%d max_map_per_fmr=%d max_srq=%d max_srq_wr=%d max_srq_sge=%d\n",
						i->device_attr.max_ah,
						i->device_attr.max_fmr,
					       i->device_attr.max_map_per_fmr,
					       i->device_attr.max_srq,
					       i->device_attr.max_srq_wr,
					       i->device_attr.max_srq_sge);
				fprintf(out, " max_pkeys=%d local_ca_ack_delay=%d phys_port_cnt=%d\n",
					       i->device_attr.max_pkeys,
					       i->device_attr.local_ca_ack_delay,
					       i->device_attr.phys_port_cnt);

				fprintf(out, "Port Attributes\n");
				fprintf(out, " state=%s MTU=%s Active MTU=%s git_dbl_len=%d port_cap_flags=%x max_msg_sz=%d\n",
					port_state_text[i->port_attr.state],
					mtu_text[i->port_attr.max_mtu],
					mtu_text[i->port_attr.active_mtu],
					i->port_attr.gid_tbl_len,
					i->port_attr.port_cap_flags,
					i->port_attr.max_msg_sz);
				fprintf(out, " bad_pkey_cntr=%d qkey_viol_cntr=%d pkey_tbl_len=%d\n",
					i->port_attr.bad_pkey_cntr,
					i->port_attr.qkey_viol_cntr,
					i->port_attr.pkey_tbl_len);
				fprintf(out, " lid=%d sm_lid=%d lmc=%d max_vl_num=%d sm_sl=%d\n",
					i->port_attr.lid,
					i->port_attr.sm_lid,
					i->port_attr.lmc,
					i->port_attr.max_vl_num,
					i->port_attr.sm_sl);
				fprintf(out, " subnet_timeout=%d init_type_reply=%d active_width=%d active_speed=%d\n",
					i->port_attr.subnet_timeout,
					i->port_attr.init_type_reply,
					i->port_attr.active_width,
					i->port_attr.active_speed);
				fprintf(out, " phys_state=%d link_layer=%s flags=%x port_cap_flags2=%x\n",
					i->port_attr.phys_state,
					link_layer_text[i->port_attr.link_layer],
					i->port_attr.flags,
					i->port_attr.port_cap_flags2);
				return;
			}

		fprintf(out, "Unknown interface \"%s\".\n", parameters);
		return;
	}

	n = show_interfaces(b);
	b[n] = 0;
	fputs(b, out);
}

static void device_set(char *optarg)
{
	ib_name = optarg;
}

static void roce_set(char *optarg)
{
	roce_name = optarg;
}

__attribute__ ((constructor))
static void interfaces_init(void)
{
	register_concom("interfaces", true, 1, "List statistics about Interfaces", interfaces_cmd);
	register_option("device", required_argument, 'd', device_set,
		"<if[:portnumber][/<netdev>]", "Infiniband device. Uses the first available if not specified");
	register_option("roce", required_argument, 'r', roce_set,
	       "<if[:portnumber]>","ROCE device. Uses the first available if not specified.");

	register_enable("packetsocket", false, &packet_socket, NULL, "on", "off", NULL,
		"Use a packet socket instead of a RAW QP to capure IB/ROCE traffic");
	register_enable("raw", false, &raw, NULL, "on", "off",	NULL,
		"Use of RAW sockets to capture SIDR Requests. Avoids having to use a patched kernel");
	register_enable("unicast", false, &unicast, NULL, "on", "off",	NULL,
		"Processing of unicast packets with QP1 handling of SIDR REQ/REP");
}

