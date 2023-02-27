/*
 * IB2ROCE Sender support
 *
 * (C) 2022 Christoph Lameter <cl@linux.com>
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

#include <unistd.h>

#include "interfaces.h"
#include "sender.h"
#include "cli.h"
#include "pgm.h"

static unsigned sendrate = 5;
static unsigned sendbatch = 1;
static unsigned sendlen = 32;

static uint64_t sender_interval;
static uint64_t sender_time;
static unsigned sender_seq;

static unsigned sessionid;
static char hostname[40];

#define MAX_SENDRATE 1000

struct sender_info {
	unsigned signature;
	unsigned sessionid;
	uint64_t timestamp;
	char name[40];
};

#define SENDER_SIGNATURE 0xD3ADB33F


/* Return pointer to spm_type specific data */
static void *pgm_packet_start(struct i2r_interface *i, struct buf *buf, struct mc *m, enum pgm_type_e ptype)
{
	struct pgm_header *h;
	struct pgm_opt_length *ol;
	void *type_data;

	buf->end = buf->raw;


	/* Max MTU is 4096 bytes */
	if (sendlen > 4096)
		abort();

	memset(buf->raw, 0, sendlen);

	/* Create the pgm header */
	VPUSH(buf, h);

	h->pgm_sport = htons(i->port);
	h->pgm_dport = htons(m->port);
	h->pgm_type = ptype;
	h->pgm_options = PGM_OPT_PRESENT;
	h->pgm_checksum = 0;
	memcpy(h->pgm_gsi, &i->if_addr.sin_addr, sizeof(i->if_addr.sin_addr));
	memcpy(h->pgm_gsi + 4, &i->if_addr.sin_port, sizeof(i->if_addr.sin_port));

	type_data = buf->end;
	/* Space for the type specific struct */
	buf->end += pgm_type2size(ptype);

	VPUSH(buf, ol);

	/* Options follow opt_length is needed */
	ol->opt_type = PGM_OPT_LENGTH;
	ol->opt_length = sizeof(struct pgm_opt_length);

	buf->option_length = ol;
	buf->lastopt = (struct pgm_opt_header *)ol;
	return type_data;
}


/* Returns pointer to where the option data has to be placed */
static void *pgm_option(struct buf *buf, uint8_t opt_type, unsigned len)
{
	struct pgm_opt_header *poh;
	void *option_data;

	buf->lastopt = (void *)buf->end;

	VPUSH(buf, poh);
	poh->opt_type = opt_type;
	poh->opt_reserved = 0;

	option_data = buf->end;
	buf->end += len;
	poh->opt_length = buf->end - (uint8_t *)poh;

	return option_data;

}

static void pgm_end_options(struct buf *buf)
{
	buf->lastopt->opt_type |= PGM_OPT_END;
	buf->option_length->opt_total_length = htons(buf->end - (uint8_t *)buf->option_length);

}

/*
 * After all data has been written to the buffer finish it up
 * setting maximum length etc.
 */
static void pgm_packet_end(struct buf *buf)
{
	struct pgm_header *h = (void *)buf->raw;

	/* RFC3208 8. Packet formats */
	h->pgm_tsdu_length = htons(buf->end - buf->raw - sizeof(struct pgm_header));

	/* Stuff it if sendlen is defined so that we send packets of a fixed size */
	if (buf->end < buf->raw + sendlen) {
		buf->end = buf->raw +sendlen;
	}
}

static void prep_spm(struct i2r_interface *i, struct buf *buf, struct mc *m, uint8_t ptype)
{
	struct pgm_spm *ps = pgm_packet_start(i, buf, m, PGM_SPM);

	ps->spm_sqn = 1;
	ps->spm_trail = 1;
	ps->spm_lead = 1;
	ps->spm_nla_afi = 4;
	ps->spm_nla = i->if_addr.sin_addr;

	if (ptype)
		pgm_option(buf, ptype, 0);

	pgm_end_options(buf);
	pgm_packet_end(buf);
}

static void prep_sender_struct(struct i2r_interface *i, struct buf *buf, struct mc *m)
{
	struct sender_info *s;
	struct pgm_data *d;

	/* Max MTU is 4096 bytes */
	if (sendlen > 4096)
		abort();

	buf->end = buf->raw;
	memset(buf->raw, 0, sendlen);

	d = pgm_packet_start(i, buf, m, PGM_ODATA);
	d->data_sqn = htonl(sender_seq);
	d->data_trail = htonl(sender_seq);

	if (sender_seq  <= 1) {
		struct pgm_opt_syn *pos = pgm_option(buf, PGM_OPT_SYN, sizeof(struct pgm_opt_syn));

		pos->opt_reserved = 0;
		logg(LOG_INFO, "%s: Initiating stream with OPT_SYN set on ODATA\n", m->text);
	}

	pgm_end_options(buf);

	VPUSH(buf, s);
	s->signature = SENDER_SIGNATURE;
	memcpy(s->name, hostname, sizeof(hostname));
	s->sessionid = sessionid;

	s->timestamp = now;

	pgm_packet_end(buf);
}

static void sender_send(void *private)
{
	struct buf *buf;
	struct i2r_interface *i = i2r + default_interface;
	struct rdma_channel *blacklisted = NULL;
	bool successful = true;

	if (!sender_interval || !i->context)
		return;

	if (sender_time + sender_interval < now) {
		static bool falling_behind_warning;

		if (!falling_behind_warning) {
			logg(LOG_WARNING, "Falling behind while sending to %s. Skipping intervals\n", print_time(now - sender_time - sender_interval));
			falling_behind_warning = true;
		}

		sender_time = now;
		goto out;
	}

	for(int j = 0; j < sendbatch; j++) {

		now = timestamp();

		/* scan through all multicast groups and send */
		mc_foreach(m) {
			struct rdma_channel *c = m->interface[default_interface].channel;

			if (blacklisted == c)
				continue;

			if (m->interface[default_interface].status != MC_JOINED)
				continue;

			if (sendqueue_full(c)) {
				if (!c->reduced_rate_warning) {
					logg(LOG_WARNING, "%s: Sendbuffer overflow. Skipping intervals\n", c->text);
					c->reduced_rate_warning = true;
				}
				blacklisted = c;
				successful = false;
				continue;
			}
			buf = alloc_buffer(c);
			prep_sender_struct(i, buf, m);
			__send_to(c, buf->raw, buf->end - buf->raw, &m->interface[default_interface].ai, false, 0, buf);
		}
		if (successful)
			sender_seq++;
	}

out:
	sender_time += sender_interval;
	add_event(sender_time, sender_send, NULL, "Sender Send");
}

void sender_shutdown(void)
{
	struct i2r_interface *i = i2r + default_interface;
	char buffer[10000];
	unsigned n = 0;

	if (!sender_interval)
		return;

	sender_interval = 0;
	sender_send(NULL);		/* Argh... Race condition */

	/* scan through all multicast groups and send SPMs */
	mc_foreach(m) {
		struct rdma_channel *c = m->interface[default_interface].channel;
		struct buf *buf;

		if (m->interface[default_interface].status != MC_JOINED)
			continue;

		n += sprintf(buffer + n," %s", m->text);
		buf = alloc_buffer(c);
		prep_spm(i, buf, m, PGM_OPT_FIN);
		__send_to(c, buf->raw, buf->end - buf->raw, &m->interface[default_interface].ai, false, 0, buf);
	}
	sender_seq = 0;
	logg(LOG_INFO, "SPM with OPT_FIN was sent to%s.\n", buffer);
}

static void __sender_setup(void *private)
{
	struct i2r_interface *i = i2r + default_interface;
	unsigned r;

	sender_shutdown();

	if (sendrate < 300) {
		r = sendrate;
 		sendbatch = 1;
	} else if (sendrate < 3000) {
		r = sendrate / 10;
		sendbatch = 10;
	} else if (sendrate  < 30000) {
		r = sendrate / 100;
		sendbatch = 100;
	} else if (sendrate < 300000) {
		r = sendrate / 1000;
		sendbatch = 1000;
	} else {
		r = 1000;
		sendbatch = sendrate / 1000;
	}

	sender_interval = ONE_SECOND / r;

	logg(LOG_INFO, "Rate = %u. Batch=%u Sendrate=%u interval=%s rate*sendbatch=%u\n", sendrate, sendbatch, r, print_time(sender_interval), r * sendbatch);

	sender_seq = 1;

	/* scan through all multicast groups and send SPMs */
	mc_foreach(m) {
		struct rdma_channel *c = m->interface[default_interface].channel;
		struct buf *buf;

		if (m->interface[default_interface].status != MC_JOINED)
			continue;

		buf = alloc_buffer(c);
		prep_spm(i, buf, m, 0);
		__send_to(c, buf->raw, buf->end - buf->raw, &m->interface[default_interface].ai, false, 0, buf);
	}
}

void sender_setup(void)
{
	__sender_setup(NULL);

	if (!sender_interval)
		return;

	sender_time = timestamp() + ONE_SECOND + rand() % sender_interval;

	add_event(sender_time, sender_send, NULL, "Sender Send");
}

__attribute__((constructor))
static void sender_init(void)
{
	srand(time(NULL));
	sessionid = rand();
	if (gethostname(hostname, sizeof(hostname)) < 0)
			logg(LOG_CRIT, "Cannot determine hostname: %s\n", errname());

	register_enable("sendrate", true, NULL, (int *)&sendrate, "2", "off", sender_setup,
		"The rate of sending packets when requested");
	register_enable("sendlen", true, NULL, (int *)&sendlen, "2", "off", NULL,
		"The length of the packets being sent");
}

