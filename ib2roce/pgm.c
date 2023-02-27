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

bool pgm_mode = true; 	/* Will only analyze CLLM streams */

struct nak {
	struct pgm_nak *next;
	unsigned sqn;
	bool nak_sent;
	bool ncf_sent;
	bool nnak_sent;
};

struct pgm_tsi {
	struct in_addr mcgroup;
	struct in_addr sender;
	uint16_t dport;
	uint16_t sport;
};

enum stream_state {
	stream_init,
	stream_sync,
	stream_repair,
	stream_error,
	stream_ignore,
};
/* Stream information */
struct pgm_stream {
	struct pgm_tsi tsi;
	struct i2r_interface *i;	/* Interface of the source */
	unsigned trail;			/* Sender trail */
	unsigned lead;			/* Sender lead */

	unsigned last;			/* Highest SQN received */
	unsigned rlast;			/* Last Repair data */
	unsigned last_seq;		/* Last in sequence */
	unsigned oldest;		/* The oldest message available locally */
	unsigned dup, odata, rdata, spm, ack, nak;
	unsigned rdup;
	unsigned first_sqn, last_sqn;
	unsigned sqn_seq_errs;
	unsigned drop;
	unsigned last_missed_sqn, last_missed_sqns;
	struct in_addr repairer;
	enum stream_state state;
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
		i->pgm_record_hash = hash_create(0, sizeof(struct pgm_tsi) + sizeof(uint32_t));
	}
}

static void format_tsi(char *b, struct pgm_tsi *tsi)
{
	static char c[30];

	strcpy(c, inet_ntoa(tsi->sender));

	snprintf(b, 60, "%s:%d->%s:%d", c, tsi->sport, inet_ntoa(tsi->mcgroup), tsi->dport);
}

static bool process_data(struct pgm_stream *s, struct pgm_header *h, uint16_t *opt_offset, uint8_t *a, unsigned len)
{
	struct pgm_data *data = (struct pgm_data *)(h + 1);
//	uint32_t tdsu = ntohs(h->pgm_tsdu_length);
	uint32_t sqn = ntohl(data->data_sqn);
	uint32_t trail = ntohl(data->data_trail);
	char rtype = h->pgm_type == PGM_RDATA ? 'R' : 'O';

	logg(LOG_DEBUG, "%s: %cDATA SQN=%d TRAIL=%d SYN=%d len=%u\n", s->text, rtype, sqn, trail, opt_offset[PGM_OPT_SYN], len);

	/* Accept SQN if the stream is new or if the SYN option is set */
	if (s->state == stream_init || opt_offset[PGM_OPT_SYN]) {
		logg(LOG_INFO, "TSI Start (OPT_SYN on %cDATA) %s\n", rtype, s->text);
		s->state = stream_sync;
		goto accept;
	}

	if (h->pgm_type == PGM_RDATA) {
		s->rdata++;
		goto finish;
	}
	s->odata++;

	if (sqn <= s->last) {
		s->dup++;
		logg(LOG_NOTICE, "%s: Sender is duplicating traffic last=%u sqn=%u\n", s->text, s->last, sqn);
		s->last = sqn;
		return false;
	}

	/* Move trail/lead */
	if (trail > s->trail)
		s->trail = trail;

	if (sqn > s->lead)
		s->lead = sqn;

	if (sqn != s->last +1 && !opt_offset[PGM_OPT_RST]) {
		logg(LOG_NOTICE, "%s: Sequence error SQN %d->SQN %d diff %d\n", s->text, s->last, sqn, sqn - s->last);
		s->state = stream_repair;
		s->sqn_seq_errs++;
	}

accept:
	s->last = sqn;

finish:
	if (opt_offset[PGM_OPT_FIN]) {
		/* End of Stream */
		logg(LOG_INFO, "TSI End (OPT_FIN on %cDATA) %s\n", rtype, s->text);
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

	if (h->pgm_type != PGM_ACK) {

		s->nak++;
		logg(LOG_NOTICE, "%s: NAK/NCF/NNAK SQN=%u NLA=%s GRP_NLA=%s\n",
			s->text, sqn, inet_ntoa(nak->nak_src_nla),
			inet_ntoa(nak->nak_grp_nla));

	} else {
		s->ack++;
		logg(LOG_NOTICE, "%s: ACK %u\n", s->text, sqn);
	}
	return true;
}

bool pgm_process(struct rdma_channel *c, struct mc *m, struct buf *buf)
{
	struct i2r_interface *i = c->i;
	struct pgm_tsi tsi;
	struct pgm_stream *s;
	uint8_t *a;
	uint16_t opt_offset[MAX_PGM_OPT];
	unsigned pgm_type;
	enum cat_type pgm_category;
	uint8_t *pgm_start = (uint8_t *)(buf->cur);
	struct pgm_header *header = (void *)pgm_start;

	tsi.mcgroup = m->addr;
	memcpy(&tsi.sender, header->pgm_gsi, sizeof(struct in_addr));
	tsi.sport = ntohs(header->pgm_sport);
	tsi.dport = ntohs(header->pgm_dport);

	s = hash_find(i->pgm_tsi_hash, &tsi);
	if (!s) {
		lock();
		s = hash_find(i->pgm_tsi_hash, &tsi);
		if (!s) {
			s = calloc(1, sizeof(struct pgm_stream));
			s->tsi = tsi;
			s->i = i;
			format_tsi(s->text, &tsi);
			hash_add(i->pgm_tsi_hash, s);
			i->nr_tsi++;
			unlock();

			if (!valid_addr(c->i, tsi.sender)) {
				s->state = stream_ignore;
				logg(LOG_NOTICE, "%s: Invalid TSI %s (IP addr not local)\n", i->text, s->text);
				return false;
			} else
				logg(LOG_NOTICE, "TSI New %s\n", s->text);
		} else
			unlock();
	}

	if (s->state == stream_ignore) {
drop:
		s->drop++;
		return false;
	}

	/* Determine the category of the pgm_type which will allow us to easily check allowed options */
 	pgm_type = header->pgm_type & PGM_TYPE_MASK;
	pgm_category = pgm_type2cat(pgm_type);
	if (pgm_type >= MAX_PGM_TYPE || pgm_category == cat_invalid) {
		logg(LOG_NOTICE, "%s: Invalid PGM type %u. Packet Skipped.\n", s->text, pgm_type);
		goto drop;
	}

	/* move to the beginning of the options. Extracts size for category from cat_sizes */
	a = pgm_start + sizeof(struct pgm_header) + pgm_type2size(pgm_type);

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

		do {
			poh = (struct pgm_opt_header *)a;
			option = poh->opt_type & PGM_OPT_MASK;

			/*
			 * RFC3208 allows ignoring options that are unknown.
			 * We just skip over unknown data
			 */
			if (option <= MAX_PGM_OPT) {
				/*
				 * The 2 should be sizeof(pgm_opt_header) but that header includes a reserved
				 * field that is also part of the other struct pgm_opt_xxxes. So hardcode
				 * the size here without the reserved field/
				 */
				opt_offset[option] = a + 2 - pgm_start;

				 if (!((1L << option) & cat_perm[pgm_category]))
					logg(LOG_INFO, "%s: Invalid option %x for PGM record type %x specified.\n", s->text, option, pgm_type);
                        } else
				logg(LOG_INFO, "%s: Option > max\n", s->text);

			a += poh->opt_length;
		} while (!(poh->opt_type & PGM_OPT_END));

		v = (uint16_t *)(opt_offset[PGM_OPT_LENGTH] + pgm_start);
		if (!*v)
			logg(LOG_INFO, "%s: packet without OPT_LENGTH.\n", s->text);
		else {
			unsigned total_opt_length = ntohs(*v);

			if (a - opt_start != total_opt_length) {
				logg(LOG_INFO, "%s: total_opt_length mismatch (is %lu, expected %u). Packet skipped\n", s->text, a - opt_start, total_opt_length);
				goto drop;
			}
		}
	} else
		logg(LOG_INFO, "%s: No Options ...\n", s->text);

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
	interface_foreach(i) {
		fprintf(out, "%s: TSIs=%d\n", i->text, i->nr_tsi);
		/* Retrieve TSI streams */
		struct pgm_stream *t[10];
		unsigned nr;
		unsigned offset = 0;

		while ((nr = hash_get_objects(i->pgm_tsi_hash, offset, 10, (void **)t))) {
			for(int j = 0; j < nr; j++) {
				struct pgm_stream *ps = t[j];
				char buf[60];

				format_tsi(buf, &ps->tsi);

				fprintf(out, "%s: lead=%d trail=%d last=%d lastRepairData=%d oldest=%d",
					buf, ps->lead, ps->trail, ps->last, ps->rlast, ps->oldest);

				if (ps->dup)
					fprintf(out, " dup(OData!)=%u", ps->dup);

				if (ps->rdup)
					fprintf(out, " dup(Rdata!)=%u", ps->rdup);

				if (ps->rdata)
					fprintf(out, " rdata=%u", ps->rdata);

				if (ps->ack)
					fprintf(out, " ack=%u", ps->ack);

				if (ps->nak)
					fprintf(out, " nak=%u", ps->nak);

				if (ps->first_sqn)
					fprintf(out, " firstsqn=%u", ps->first_sqn);

				if (ps->sqn_seq_errs) {
					fprintf(out, " sqnerrs=%u lastmissed=%u nr_missed=%u",
						ps->sqn_seq_errs, ps->last_missed_sqn, ps->last_missed_sqns);
				}
				fprintf(out, "\n");
  			}
			offset += nr;
		}
	}
}

__attribute__((constructor))
static void pgm_init(void)
{
	register_concom("tsi", true, 0, "Show PGM info", tsi_cmd);
	register_enable("pgm", true, &pgm_mode, NULL, "on", "off", NULL,
		"Enable PGM processing and validaton (Sequence numbers etc)");

	init_pgm_streams();
}

/* Summarize TSI stats for an interface */
unsigned pgm_brief_stats(char *b, struct i2r_interface *i)
{

	struct pgm_stream *streams[10];
	unsigned offset = 0;
	unsigned nr;
	unsigned nr_streams = 0;
	unsigned spm = 0;
	unsigned odata = 0;
	unsigned rdata = 0;
	unsigned nak = 0;

	if (!i->context || !i->pgm_tsi_hash)
		return 0;

	while ((nr = hash_get_objects(i->pgm_tsi_hash, offset, 10, (void **)streams))) {
		int j;

		for (j = 0; j < nr; j++) {
			struct pgm_stream *s = streams[j];

			spm += s->spm;
			odata += s->odata;
			rdata += s->rdata;
			nr_streams++;
		}

		offset += 10;
	}

	if (nr_streams && odata)

		return sprintf(b, " [TSI=%d SPM=%u,ODATA=%u,RDATA=%u,NAK=%u]",
				nr_streams, spm, odata, rdata, nak);
	else
		return 0;
}


