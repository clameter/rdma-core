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
#include <fcntl.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <numa.h>
#include <systemd/sd-daemon.h>

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
#include "sender.h"

#ifdef UNICAST
#include "endpoint.h"
#include "unicast.h"
#include "ibraw.h"
#endif

/* Globals */

static bool debug = false;		/* Stay in foreground, print more details */
static bool testing = false;		/* Run some tests on startup */
static uint64_t watchdog_nsec;
static int drop_packets = 0;		/* Packet dropper */

static char *payload_dump(uint8_t *p)
{
	return _hexbytes(p, 48);
}

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

#ifdef HAVE_MSTFLINT
static void shutdown_sniffer(int arg) {
	struct i2r_interface *i = i2r + INFINIBAND;

	if (clear_ib_sniffer(i->port, i->raw->qp))
		logg(LOG_ERR, "Failed to switch off sniffer mode on %s\n", i->raw->text);
	else
		logg(LOG_NOTICE, "ABORT handler cleared the sniffer mode on Infiniband\n");
}
#endif

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

#ifdef UNICAST
	learn_source_address(buf);
#endif

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

		if (buf->ip.saddr == c->i->if_addr.sin_addr.s_addr && buf->w->qp_num == buf->w->src_qp) {
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

		if (memcmp(&buf->grh.sgid, &c->i->gid, sizeof(union ibv_gid)) == 0 && buf->w->qp_num == buf->w->src_qp) {

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

	if (pgm_mode) {
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

	if (!m->same_core) {
		/* Ok we need to queue on another core */
		fifo_put(&ch_out->send_queue, buf);
		goto success;
	}

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

success:
	st(c, packets_bridged);
	return;

discardit:    
	logg(LOG_DEBUG, "%s on multicast channel %s: GRH=%s %s\n", reason, c->text, grh_str(&buf->grh), payload_dump(buf->cur));

invalid_packet:
	st(c, packets_invalid);
}

static void run_watchdog(void *private)
{
	sd_notify(0, "WATCHDOG=1");
	add_event(timestamp() + watchdog_nsec, run_watchdog, NULL, "Watchdog");
}

static void setup_timed_events(void)
{
	uint64_t x;
	int ret;

	now = timestamp();

	start_calculate_pps();

	check_joins(&i2r[INFINIBAND].channels, &i2r[ROCE].channels);

	ret = sd_watchdog_enabled(0, &x);
	if (ret < 0)
		panic("Watchdog check failed. errname())\n");

	if (!ret)
		return;

	if (x < 100000)
		panic("Watchdog timer less than 100 milliseconds not supported\n");

	if (!systemd)
		panic("Watchdog only supported in --systemd mode\n");

	/* Systemd recommends to send watchdog notifications in half the requested time interval */
	watchdog_nsec = x * ONE_MICROSECOND /2;
	run_watchdog(NULL);
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

	/* Init the scheduler */
	now = timestamp();
	parse_options(argc, argv);

	if (debug || !bridging) {

		openlog("ib2roce", LOG_PERROR, LOG_USER);

	} else {
		background = true;
		if (!systemd) {
			daemonize();
			pid_open();
		}
	}
	concom_init();

	setup_termination_signals();

	ret = find_rdma_devices();
	if (ret && !testing)
		return ret;

	if (mode == mode_bridge)
		logg (LOG_NOTICE, "%s device = %s:%d, %s device = %s:%d. Multicast Groups=%d MGIDs=%s Buffers=%u\n",
			interfaces_text[INFINIBAND], i2r[INFINIBAND].rdma_name, i2r[INFINIBAND].port,
			interfaces_text[ROCE], i2r[ROCE].rdma_name, i2r[ROCE].port,
			nr_mc, mgid_text(NULL), nr_buffers);
	else {
		logg (LOG_NOTICE, "%s device = %s:%d. Multicast Groups=%d MGIDs=%s Buffers=%u\n",
			interfaces_text[default_interface], i2r[default_interface].rdma_name, i2r[default_interface].port,
			nr_mc, mgid_text(NULL), nr_buffers);
	}

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

	beacon_setup();

	if (mode == mode_sender)
		sender_setup();

	post_receive_buffers();

	start_cores();
	arm_channels(NULL);
	setup_timed_events();

	if (systemd)
		sd_notify(0, "READY=1");

	if (event_loop() < 0)
		logg(LOG_ERR, "Event Loop failed with %s\n", errname());

	if (systemd)
		sd_notify(0, "STOPPING=1");

	beacon_shutdown();

	if (mode == mode_sender)
		sender_shutdown();

	stop_cores();

	shutdown_roce();
	shutdown_ib();

	if (background)
		pid_close();

	syslog (LOG_NOTICE, "Shutdown complete.\n");
	closelog();

	return EXIT_SUCCESS;
}
