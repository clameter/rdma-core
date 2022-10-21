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
#include "unicast.h"
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

			reason = "Loopback Packet";
			goto discardit;
		}

		/*
		 * ib2roce sets the hop limit to 1. By default is it
		 * 0. So if hop_limit is set then another ib2roce already
		 * processed the packet. Discard it.
		 */
		if (buf->grh.hop_limit) {
			reason = "Hop Limit !=0 discard packet.\n";
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

static int status_fd;

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

static void logging(void *private)
{
	brief_status(stdout);
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
	for (x = sysconf(_SC_OPEN_MAX); x>2; x--)
		close(x);
	close(0);

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

	parse_options(argc, argv);

	if (debug || !bridging) {

		openlog("ib2roce", LOG_PERROR, LOG_USER);

	} else {
		background = true;
		daemonize();
		pid_open();
	}
	concom_init();

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
