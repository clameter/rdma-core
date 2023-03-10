/*
 * IB2ROCE PGM support
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
#include "pgm.h"
#ifdef UNICAST
#include "endpoint.h"
#endif
#include "cli.h"

/*
 * PGM RFC3208 Support
 */
#define PGM_EXT_OPT_LABEL 0x22

bool pgm_mode = true; 	/* Will only analyze PORT streams */

struct nak {
	struct pgm_nak *next;
	unsigned sqn;
	bool nak_sent;
	bool ncf_sent;
	bool nnak_sent;
};

struct pgm_tsi {
	struct in_addr mcgroup;
	uint8_t gsi[6];			/* GSI field from PGM header */
	uint8_t flow[2];		/* source port */
};

const char *pgm_type_text[] = { "SPM", "POLL", "POLR", NULL, "ODATA", "RDATA", NULL, NULL, "NAK", "NNAK", "NCF", NULL, "SPMR", "ACK" };

enum stream_state {
	stream_init,
	stream_sync,
	stream_repair,
	stream_error,
	stream_ignore,
	stream_states
};

const char *stream_state_text[] = {
	"INIT",
	"SYNC",
	"REPAIR",
	"ERROR",
	"IGNORE" };

/* Stream information */
struct pgm_stream {
	struct pgm_tsi tsi;		/* Transport Session Identifier */
	struct i2r_interface *i;	/* Interface of the source */
	unsigned trail;			/* Sender trail */
	unsigned lead;			/* Sender lead */
	unsigned last;			/* last SQN received */
	unsigned odata;			/* ODATA packets received */
        unsigned rdata;			/* RDATA packets received */
	unsigned spm;			/* SPM packets received */
	uint64_t timestamp;		/* Timestamp for last action */
	unsigned ncf;			/* NCF packets received */
	unsigned ack;			/* ACK in NACK format */
	unsigned nak;			/* NAKs */
	unsigned nnak;			/* NNAKs */
	unsigned drop;			/* Packets dropped */
	uint64_t timestamp_error;	/* Timestamp for last problem */
	uint64_t options;		/* Which options were used by the stream */
	unsigned dup;			/* Duplicate ODATA */
	unsigned rlast;			/* Last SQN for repair data */
	unsigned sqn_seq_errs;		/* Sequence Errors */
	unsigned missed_sqns;		/* SQNs missed */
	unsigned last_missed_sqn, last_missed_sqns;
	unsigned first_sqn, last_sqn;
	unsigned oldest;		/* The oldest message available locally */
	unsigned last_seq;		/* Last in sequence */
	struct in_addr repairer;	/* Unicast address for NAKs */
	enum stream_state state;
	bool label;
	char text[60];
};

/* Records (ODATA/RDATA) in a stream */
struct pgm_record {
	struct pgm_tsi tsi;
	uint32_t sqn;			/* Message ID  */
	struct pgm_stream *stream;
	struct buf *buf;		/* Address of buffer */
	void *start;			/* Beginning of ODATA/RDATA record */
	unsigned len;			/* Length of the message */
};

/* Permissions for options indexed by category */
static const uint64_t cat_perm[pgm_cat_max] = {
	/* Invalid */	0,
	/* SPM */	(1UL << PGM_OPT_LENGTH) + (1UL << PGM_OPT_JOIN) + (1UL << PGM_OPT_FIN) + (1UL << PGM_OPT_RST),
	/* DATA */	(1UL << PGM_OPT_LENGTH) + (1UL << PGM_OPT_FRAGMENT) + (1UL << PGM_OPT_JOIN) + (1UL << PGM_OPT_SYN) + (1UL << PGM_OPT_FIN),
	/* NAK */	(1UL << PGM_OPT_LENGTH) + (1UL << PGM_OPT_NAK_LIST)
};

static void init_pgm_streams(void)
{
	struct i2r_interface *i;

	for(i = i2r; i < i2r + NR_INTERFACES; i++) {
		i->pgm_tsi_hash = hash_create(0, sizeof(struct pgm_tsi));
//		i->pgm_record_hash = hash_create(0, sizeof(struct pgm_tsi) + sizeof(uint32_t));
	}
}

static struct in_addr tsi_sender(struct pgm_tsi *tsi)
{
	struct in_addr a;

	memcpy(&a, tsi->gsi, sizeof(struct in_addr));
	return a;
}

static void format_tsi(char *b, struct pgm_tsi *tsi, unsigned char *label, unsigned len)
{
	char *p = b;

	if (len) {
		memcpy(b, label, len);
		p += len;
		*p++=':';
	}

	__hexbytes(p, tsi->gsi, 8, 0);
	p+= 16;

	sprintf(p, "@%s", inet_ntoa(tsi->mcgroup));
}

static bool process_data(struct pgm_stream *s, struct pgm_header *h, uint16_t *opt_offset, uint8_t *a, unsigned len)
{
	struct pgm_data *data = (struct pgm_data *)(h + 1);
//	uint32_t tdsu = ntohs(h->pgm_tsdu_length);
	uint32_t sqn = ntohl(data->data_sqn);
	uint32_t trail = ntohl(data->data_trail);

	logg(LOG_DEBUG, "%s: %s SQN=%d TRAIL=%d SYN=%d len=%u\n", s->text, pgm_type_text[h->pgm_type], sqn, trail, opt_offset[PGM_OPT_SYN], len);

	/* Accept SQN if the stream is new or if the SYN option is set */
	if (s->state == stream_init || opt_offset[PGM_OPT_SYN]) {

		if (opt_offset[PGM_OPT_SYN])
			logg(LOG_INFO, "TSI Start (OPT_SYN on %s) %s\n", pgm_type_text[h->pgm_type], s->text);

		s->state = stream_sync;
		goto accept;
	}

	if (h->pgm_type == PGM_RDATA) {
		s->rdata++;
		s->timestamp_error = now;
		goto finish;
	}
	s->odata++;

	if (sqn <= s->last) {
		s->dup++;
		logg(LOG_NOTICE, "%s: Sender is duplicating traffic last=%u sqn=%u\n", s->text, s->last, sqn);
		s->last = sqn;
		s->timestamp_error = now;
		return false;
	}

	/* Move trail/lead */
	if (trail > s->trail)
		s->trail = trail;

	if (sqn > s->lead)
		s->lead = sqn;

	if (s->last > 1 && sqn != s->last +1 && !opt_offset[PGM_OPT_RST]) {
		logg(LOG_NOTICE, "%s: Sequence error SQN %d->SQN %d diff %d\n", s->text, s->last, sqn, sqn - s->last);
		s->state = stream_repair;
		s->sqn_seq_errs++;
		s->missed_sqns += sqn - s->last;
		s->last_missed_sqn = sqn - 1;
		s->last_missed_sqns = sqn - s->last;
		s->timestamp_error = now;
	} else
		s->timestamp = now;

accept:
	s->last = sqn;

finish:
	if (opt_offset[PGM_OPT_FIN]) {
		/* End of Stream */
		logg(LOG_INFO, "TSI End (OPT_FIN on %s) %s\n", pgm_type_text[h->pgm_type], s->text);
		s->state = stream_init;
	}


	return true;
}

static bool process_spm(struct pgm_stream *s, struct pgm_header *h, uint16_t *opt_offset)
{
	struct pgm_spm *spm = (struct pgm_spm *)(h + 1);

	s->spm++;
	s->trail = ntohl(spm->spm_trail);
	s->lead = ntohl(spm->spm_lead);

	if (opt_offset[PGM_OPT_RST]) {
		logg(LOG_INFO, "TSI Error (OPT_RST on SPM) %s\n", s->text);
		s->state = stream_error;
	} else
		s->state = stream_sync;

	if (opt_offset[PGM_OPT_FIN]) {
		/* End of Stream */
		logg(LOG_INFO, "TSI End (OPT_FIN on SPM) %s\n", s->text);
		s->state = stream_init;
	}

	return true;
}

static bool process_nak(struct pgm_stream *s, struct pgm_header *h, uint16_t *opt_offset)
{
	struct pgm_nak *nak = (struct pgm_nak *)(h + 1);
	uint32_t sqn = ntohl(nak->nak_sqn);
	unsigned count = 1;
	unsigned n;
	char sqns[2000];

	/* First SQN */
	n = sprintf(sqns, "%u", sqn);

	/* More SQNs ? */
	if (opt_offset[PGM_OPT_NAK_LIST]) {

		struct pgm_opt_header *poh = (void *)h + opt_offset[PGM_OPT_NAK_LIST];
		struct pgm_opt_nak_list *ponl = (void *)(&poh->opt_reserved);
		unsigned naks =(poh->opt_length - 3)/sizeof(uint32_t);
		unsigned i;

		count += naks;

		for(i = 0; i < naks; i++)
			n += sprintf(sqns + n, " %u", ntohl(ponl->opt_sqn[i]));
	}

	if (h->pgm_type != PGM_ACK) {

		switch (h->pgm_type) {
			case PGM_NAK: s->nak += count; break;
			case PGM_NCF: s->ncf += count; break;
			case PGM_NNAK: s->nnak += count; break;
		}

		logg(LOG_NOTICE, "%s: %s NLA=%s GRP_NLA=%s SQN=%s\n",
			s->text, pgm_type_text[h->pgm_type], inet_ntoa(nak->nak_src_nla),
			inet_ntoa(nak->nak_grp_nla), sqns);

		s->timestamp_error = now;

	} else {

		s->ack += count;
		logg(LOG_NOTICE, "%s: ACK %s\n", s->text, sqns);

	}
	return true;
}

static struct pgm_stream *create_tsi(struct i2r_interface *i, struct pgm_tsi *tsi)
{
	struct pgm_stream *s;

	lock();
	s = hash_find(i->pgm_tsi_hash, &tsi);
	if (!s) {
		s = calloc(1, sizeof(struct pgm_stream));
		s->tsi = *tsi;
		s->i = i;
		format_tsi(s->text, tsi, NULL, 0);
		hash_add(i->pgm_tsi_hash, s);
		i->nr_tsi++;
	}
	unlock();
	return s;
}

bool pgm_process(struct rdma_channel *c, struct mc *m, struct buf *buf)
{
	struct i2r_interface *i = c->i;
	struct pgm_tsi tsi;
	struct pgm_stream *s;
	uint8_t *a;
	uint16_t opt_offset[MAX_PGM_OPT];
	enum cat_type pgm_category;
	uint8_t *pgm_start = (uint8_t *)(buf->cur);
	struct pgm_header *header = (void *)pgm_start;

	tsi.mcgroup = m->addr;
	memcpy(tsi.gsi, header->pgm_gsi, 6);
	if (header->pgm_type == PGM_NAK || header->pgm_type == PGM_NNAK)
		memcpy(&tsi.flow, &header->pgm_dport, sizeof(uint16_t));
	else
		memcpy(&tsi.flow, &header->pgm_sport, sizeof(uint16_t));

	s = hash_find(i->pgm_tsi_hash, &tsi);
	if (!s) {
		s= create_tsi(i, &tsi);

		if (!valid_addr(c->i, tsi_sender(&tsi))) {
			s->state = stream_ignore;
			logg(LOG_NOTICE, "%s: Invalid TSI %s (IP addr not local)\n", i->text, s->text);
			return false;
		} else
			logg(LOG_DEBUG, "TSI New %s\n", s->text);
	}

	if (s->state == stream_ignore) {
drop:
		s->drop++;
		s->timestamp_error = now;
		return false;
	}

	/* Determine the category of the pgm_type which will allow us to easily check allowed options */
	pgm_category = pgm_type2cat(header->pgm_type);
	if (header->pgm_type >= MAX_PGM_TYPE || pgm_category == cat_invalid) {
		logg(LOG_NOTICE, "%s: Invalid PGM type %u. Packet Skipped.\n", s->text, header->pgm_type);
		goto drop;
	}

	/* move to the beginning of the options. Extracts size for category from cat_sizes */
	a = pgm_start + sizeof(struct pgm_header) + pgm_type2size(header->pgm_type);

	/*
	 * Parse options following the PGM header. This is common for all PGM packet types so do it
	 * now in the most efficient way.
	 */
	memset(opt_offset, 0, sizeof(uint16_t) * MAX_PGM_OPT);

	if (header->pgm_options & PGM_OPT_PRESENT) {

		struct pgm_opt_header *poh;
		uint8_t *opt_start =  a;
		uint16_t *v;
		unsigned option;
		uint64_t opt_bit;

		do {
			poh = (struct pgm_opt_header *)a;
			option = poh->opt_type & PGM_OPT_MASK;
			opt_bit = 1L << option;

			/*
			 * RFC3208 allows ignoring options that are unknown.
			 * We just skip over unknown data
			 */
			if (option <= MAX_PGM_OPT) {

				opt_offset[option] = a - pgm_start;

				if (!(opt_bit & cat_perm[pgm_category]))
					logg(LOG_INFO, "%s: Invalid option %x for PGM record type %x specified.\n",
						s->text, option, header->pgm_type);

			} else
			if (option == PGM_EXT_OPT_LABEL) {

				if (!s->label) {
					s->label = true;
					format_tsi(s->text, &tsi, a +4, poh->opt_length - 4);
				}
			} else
			if (option != PGM_OPT_INVALID) {
				/* Record unknown option encountered */
				s->options |= opt_bit;

				/* What now ? */
				switch (poh->opt_reserved & PGM_OPX_MASK) {

					case PGM_OPX_INVALIDATE:
						/* Modify so downstream does not process this option */
						poh->opt_type = PGM_OPT_INVALID | (poh->opt_type & PGM_OPT_END);
						break;

					case PGM_OPX_DISCARD:
						/* Discard the packet  */
						goto drop;

					case PGM_OPX_IGNORE:
						/* Just leave it as is */
						break;
				}
			}

			a += poh->opt_length;

		} while (!(poh->opt_type & PGM_OPT_END));

		v = (uint16_t *)(opt_offset[PGM_OPT_LENGTH] + pgm_start + 2);
		if (!*v)

			logg(LOG_INFO, "%s: packet without OPT_LENGTH.\n", s->text);

		else {
			unsigned total_opt_length = ntohs(*v);

			if (a - opt_start != total_opt_length) {
				logg(LOG_INFO, "%s: total_opt_length mismatch (is %lu, expected %u). Packet skipped\n",
					s->text, a - opt_start, total_opt_length);
				goto drop;
			}
		}

	} else {

		if (pgm_category != cat_nak)
			logg(LOG_INFO, "%s: No Options ... Type %d\n", s->text, header->pgm_type);

	}

	switch(pgm_category) {
		case cat_spm:
			return process_spm(s, header, opt_offset);

		case cat_data:
		        return process_data(s, header, opt_offset, a, buf->end - a);

		case cat_nak:
			return process_nak(s, header, opt_offset);

		default:
		break;
	}
	return false;
}

static void tsi_cmd(FILE *out, char *parameters)
{
	unsigned status[stream_states] = { 0, };
	unsigned sum_tsi = 0;
	unsigned sum_rdata = 0;
	unsigned sum_odata = 0;
	unsigned sum_spm = 0;
	unsigned sum_ncf = 0;
	unsigned sum_sqnerrs = 0;
	unsigned sum_missed_sqn = 0;
	unsigned data_tsi = 0;
	unsigned active_tsi = 0;
	unsigned tsi_displayed = 0;
	char cmd = tolower(parameters ? parameters[0] : 's');

	interface_foreach(i) {
		/* Retrieve TSI streams */
		struct pgm_stream *t[10];
		unsigned nr;
		unsigned offset = 0;

		while ((nr = hash_get_objects(i->pgm_tsi_hash, offset, 10, (void **)t))) {
			for(int j = 0; j < nr; j++) {
				struct pgm_stream *ps = t[j];

				status[ps->state]++;
				if (ps->last > 1)
					data_tsi++;

				if (ps->timestamp > now - seconds(60))
					active_tsi++;

				switch (cmd) {
					/* Summary */
					case 's' :
						continue;

					/* Streams with data */
					case 'd' :
						/* Default Display: Only active streams */
						if (ps->state != stream_sync || !ps->last)
							continue;
						break;

					/* Streams with errors */
					case 'e' :
						 if (ps->state == stream_init)
							 continue;
						 if (!ps->timestamp_error)
							 continue;
						 break;

					case 'n' :
						 if (ps->state == stream_sync)
							continue;
						 if (!ps->ncf)
							 continue;
						 break;

					default: break;
				}
				now = timestamp();
				sum_odata += ps->odata;
				sum_rdata += ps->rdata;
				sum_spm += ps->spm;
				sum_ncf += ps->ncf;
				sum_sqnerrs += ps->sqn_seq_errs;
				sum_missed_sqn += ps->missed_sqns;

				fprintf(out, "%s: %s", ps->text, stream_state_text[ps->state]);

				if (ps->last)
					fprintf(out, " SQN: last=%d lead=%d trail=%d", ps->last, ps->lead, ps->trail);

				if (ps->odata || ps->spm) {
					fprintf(out, " ODATA=%u SPM=%u", ps->odata, ps->spm);

					if (ps->timestamp)
						fprintf(out, " Active %s", print_time(now - ps->timestamp));

					if (ps->rdata || ps->ncf)
						fprintf(out, " RDATA=%u NCF=%u", ps->rdata, ps->ncf);

					if (ps->timestamp_error)
						fprintf(out, " Error %s", print_time(now - ps->timestamp_error));

				}

				if (ps->drop)
					fprintf(out, " Drop %u", ps->drop);

				if (ps->dup)
					fprintf(out, " dup(OData!)=%u", ps->dup);

				if (ps->ack)
					fprintf(out, " ack=%u", ps->ack);

				if (ps->sqn_seq_errs) {
					fprintf(out, " sqnerrs=%u missed_sqns=%u last_missed_sqn=%u last_missed_sqns=%u",
						ps->sqn_seq_errs, ps->missed_sqns, ps->last_missed_sqn, ps->last_missed_sqns);
				}
				if (ps->options) {
					fprintf(out, " ignored-opt=");

					for(int b = MAX_PGM_OPT; b < 64; b++) {
						if (ps->options & (1L << b)) {
							fprintf(out, "%x ", b);
						}
					}
				}

				fprintf(out, "\n");
				tsi_displayed++;
  			}
			offset += nr;
		}
		if (i->nr_tsi) {
			fprintf(out, "%s: TSIs=%d\n", i->text, i->nr_tsi);
			sum_tsi += i->nr_tsi;
		}
	}
	if (cmd == 's') {

		fprintf(out, "Total TSIs=%u Active=%u Data=%u", sum_tsi, active_tsi, data_tsi);
		for (int i = 0; i < stream_states; i++)
			fprintf(out, " %s=%u", stream_state_text[i], status[i]);

		fprintf(out, "\n");
	} else
		fprintf(out, "--- %u/%u TSIs shown ODATA=%u RDATA=%u SPM=%u NCF=%u SQNERRS=%u Missed SQNs=%u\n",
			tsi_displayed, sum_tsi, sum_odata, sum_rdata, sum_spm, sum_ncf, sum_sqnerrs, sum_missed_sqn);
}

__attribute__((constructor))
static void pgm_init(void)
{
	register_concom("tsi", true, 1, "Show PGM info (parmameters all/data/errors/summary/nak)", tsi_cmd);
	register_enable("pgm", true, &pgm_mode, NULL, "on", "off", NULL,
		"Enable PGM processing and validaton (Sequence numbers etc)");
	init_pgm_streams();
}

#define NSTREAMS 100
/* Summarize TSI stats for an interface */
unsigned pgm_brief_stats(char *b, struct i2r_interface *i)
{

	struct pgm_stream *streams[NSTREAMS];
	unsigned offset = 0;
	unsigned nr;
	unsigned nr_streams = 0;
	unsigned spm = 0;
	unsigned odata = 0;
	unsigned rdata = 0;
	unsigned nak = 0;

	if (!i->context || !i->pgm_tsi_hash)
		return 0;

	while ((nr = hash_get_objects(i->pgm_tsi_hash, offset, NSTREAMS, (void **)streams))) {
		int j;

		for (j = 0; j < nr; j++) {
			struct pgm_stream *s = streams[j];

			spm += s->spm;
			odata += s->odata;
			rdata += s->rdata;
			nak += s->nak;
			nr_streams++;
		}

		offset += nr;
	}

	if (nr_streams && odata) {
		int ret = sprintf(b, " [TSI=%u SPM=%u,ODATA=%u,RDATA=%u,NAK=%u]",
				i->nr_tsi - i->last_tsi, spm - i->last_spm, odata - i->last_odata, rdata - i->last_rdata, nak - i->last_naks);

		i->last_tsi = i->nr_tsi;
		i->last_spm = spm;
		i->last_odata = odata;
		i->last_rdata = rdata;
		i->last_naks = i->last_naks;
		return ret;
	} else
		return 0;
}


