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
#include "packet.h"
#ifdef UNICAST
#include "endpoint.h"
#endif
#include "cli.h"

/*
 * PGM RFC3208 Support
 */

enum pgm_mode pgm_mode = pgm_off;

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
	unsigned last_missed_sqn, last_missed_sqns;
//	struct nak *nak;
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

	snprintf(b, 60, "%s:%d->%s:%d", c, ntohs(tsi->sport), inet_ntoa(tsi->mcgroup), ntohs(tsi->dport));
}

static bool add_record(struct buf *buf, struct pgm_tsi *tsi, uint32_t sqn, void *start, unsigned len)
{
	struct i2r_interface *i = buf->c->i;
	struct pgm_record *r = calloc(1, sizeof(struct pgm_record));
	struct pgm_record *q;

	r->tsi = *tsi;
	r->sqn = sqn;
	r->buf = buf;
	r->start = start;
	r->len = len;

	lock();
	if ((q = hash_find(i->pgm_record_hash, &r))) {
		unlock();
		return false;
	} else {
		__get_buf(buf);
		hash_add(i->pgm_record_hash, r);
		unlock();
		return true;
	}
}

static struct pgm_record *find_record(struct i2r_interface *i, struct pgm_tsi *tsi, uint32_t sqn)
{
	struct pgm_record f = { .tsi = *tsi, .sqn = sqn };

	return hash_find(i->pgm_record_hash, &f);
}

/* Forwarded packet if ib2roce behaves like a DLR */
static void forward_packet(struct buf *buf, struct pgm_tsi *tsi, uint32_t sqn)
{
}

/* Packet delivery in sequence */
static void deliver_in_seq(struct buf *buf, struct pgm_tsi *tsi, uint32_t sqn)
{
}

bool pgm_process(struct rdma_channel *c, struct mc *m, struct buf *buf)
{
	struct i2r_interface *i = c->i;
	struct pgm_tsi tsi;
	struct pgm_stream *s;
	uint32_t sqn;
	uint32_t tdsu;
	uint16_t total_opt_length = 0;
	uint8_t *options_start;
	union {
		struct pgm_header pgm;
		struct {
			uint8_t skip[8];
			struct in_addr addr;
			uint16_t port;
		};
	} header;
	char text[60];
	struct pgm_spm spm;
	struct pgm_data data;
	struct pgm_nak nak;
#if 0
	struct pgm_poll poll;
	struct pgm_polr polr;
#endif
	struct pgm_ack ack;
	int ret = true;

	PULL(buf, header);

	/* Verify if pgm message originated from our subnet */
	if (!valid_addr(c->i, header.addr)) {
		logg(LOG_INFO, "Discarded PGM packet originating from %s is from outside our subnet %s\n", inet_ntoa(header.addr), c->i->text);
		return false;
	}

	if (pgm_mode < pgm_passthrough)
		return true;

	tdsu = ntohs(header.pgm.pgm_tsdu_length);

	tsi.mcgroup = m->addr;
	memcpy(&tsi.sender, header.pgm.pgm_gsi, sizeof(struct in_addr));
	tsi.sport = ntohs(header.pgm.pgm_sport);
	tsi.dport = ntohs(header.pgm.pgm_dport);
	format_tsi(text, &tsi);

	s = hash_find(i->pgm_tsi_hash, &tsi);

	switch (header.pgm.pgm_type) {
		case PGM_SPM:		/* Multicast downstream */
			PULL(buf, spm);
			if (!s)
				break;

			s->spm++;

			s->trail = ntohl(spm.spm_trail);
			s->lead = ntohl(spm.spm_lead);
			if (pgm_mode <= pgm_passthrough)
				break;

			if (s->last_seq < s->lead) {
				/* We are missing packets */
			}
			break;

/* 		These may not exist although described in the RFC. There is no definition of the spmr struct available
		case PGM_SPMR:		Unicast upstream
			PULL(buf, spmr);
			break;
*/
		case PGM_ODATA:		/* Multicast downstream */
		case PGM_RDATA:		/* Multicast downstream */
			PULL(buf, data);

			logg(LOG_DEBUG, "%s: %cDATA SQN=%d TRAIL=%d\n", text,
				header.pgm.pgm_type == PGM_RDATA ? 'R' : 'O', ntohl(data.data_sqn), ntohl(data.data_trail));

			sqn = ntohl(data.data_sqn);

			if (!s) {
				lock();
				s = hash_find(i->pgm_tsi_hash, &tsi);
				if (!s) {
					s = calloc(1, sizeof(struct pgm_stream));
					s->tsi = tsi;
					s->i = i;
					strcpy(s->text, text);
					hash_add(i->pgm_tsi_hash, s);

					/* First message on new stream */
					s->last_seq = sqn - 1;
					s->last = s->last_seq;
					s->oldest = sqn;

					i->nr_tsi++;

					logg(LOG_NOTICE, "%s: New Stream TSI %s\n", i->text, s->text);
				}
				unlock();
			}

			if (header.pgm.pgm_type == PGM_RDATA)
				s->rdata++;
			else
				s->odata++;

			if (sqn < s->last_seq) {
				s->dup++;
				ret = false;
				logg(LOG_NOTICE, "%s: Repeated data out of Window\n", s->text);
				break;
			}

			if (sqn == s->last) {
				s->dup++;
				ret = false;
				logg(LOG_NOTICE, "%s: Sender is duplicating traffic %d\n", s->text, sqn);
				break;
			}


			if (sqn < s->last && find_record(i, &tsi, sqn)) {
				s->dup++;
				ret = false;
				logg(LOG_NOTICE, "%s: Repeated data in Window SQN=%d\n", s->text, sqn);
				break;
			}

			/* Move trail/lead */
			if (ntohl(data.data_trail) > s->trail)
				s->trail = ntohl(data.data_trail);

			if (sqn > s->lead)
				s->lead = sqn;

			if (pgm_mode <= pgm_passthrough) {

				if (header.pgm.pgm_type == PGM_ODATA) {
					if (sqn != s->last +1)
						logg(LOG_NOTICE, "%s: Sequence error SQN %d->SQN %d diff %d\n", s->text, s->last, sqn, sqn-s->last);
					s->last = sqn;
				}
				break;
			}

			/* This is either the next data or missing data */

			if (!add_record(buf, &tsi, sqn, buf->cur, tdsu))
				panic("PGM: SQN exists\n");

			if (sqn == s->last_seq + 1) {
				/* The next packet that we need ! */
				s->last_seq = sqn;
				forward_packet(buf, &tsi, sqn);
				deliver_in_seq(buf, &tsi, sqn);

				if (sqn == s->last + 1) {
					/* Stream without pending holes in the sequence */
					s->last = sqn;
				} else {
					/* We just filled up in a missing piece check how long our consistent history goes now */
					while (s->last_seq < s->last) {
						struct pgm_record *r = find_record(i, &tsi, s->last_seq + 1);

						if (r) {
							logg(LOG_NOTICE, "Found earlier record %d\n", s->last_seq + 1);

							deliver_in_seq(r->buf, &tsi, s->last_seq + 1);
							s->last_seq++;
						} else
							break;
					}
					/* If this was RDATA and there still is a hole then send NAK */
				}
			} else {
				logg(LOG_NOTICE, "Out of sequence sqn=%d last_seq=%d s->last=%d\n", sqn, s->last_seq, s->last);
				forward_packet(buf, &tsi, sqn);
				s->last = sqn;
				/* We have opened up some hole between s->last_seq and s->last. Could send NAK */

				/* s->last_seq ... s->last -1 is missing at this point */

				if (s->last_seq < s->trail) {
					logg(LOG_ERR, "Unrecoverable Dataloss !\n");
				} else {
					logg(LOG_NOTICE, "Nak Processing not implemented yet\n");
				}
			}

			break;

		case PGM_NAK:		/* Unicast upstream */
		case PGM_NCF:		/* Multicast downstream */
		case PGM_NNAK:		/* Unicast upstream DLR ->source */
			PULL(buf, nak);
			s->nak++;
			logg(LOG_NOTICE, "%s: NAK/NCF/NNAK SQN=%x NLA=%s GRP_NLA=%s\n",
				text, nak.nak_sqn, inet_ntoa(nak.nak_src_nla),
				inet_ntoa(nak.nak_grp_nla));
			break;

#if 0
		/* Is POLL really used I do not know of a DLR */
		case PGM_POLL:		/* DLR downstream multicast */
			PULL(buf, poll);
			logg(LOG_NOTICE, "%s: POLL\n", s->text);
			break;

		case PGM_POLR:		/* Unicast response upstream to DLR */
			PULL(buf, polr);
			logg(LOG_NOTICE, "%s: POLR\n", s->text);
			break;
#endif
		/* Not RFC compliant but it seems to be used sometimes */
		case PGM_ACK:		/* Unicast upstream */
			PULL(buf, ack);
			s->ack++;
			logg(LOG_NOTICE, "%s: ACK RX_MAX=%x BITMAP=%x\n", text, ntohl(ack.ack_rx_max), ack.ack_bitmap);
			break;

		default:
			logg(LOG_NOTICE, "%s: Invalid PGM type=%x. Packet Skipped.\n", text, header.pgm.pgm_type);
			break;
	}

	options_start = buf->cur;
	if (header.pgm.pgm_options & 0x1) {
		bool last = false;

		do {
			struct pgm_opt_header opt;
			struct pgm_opt_length length;
			struct pgm_opt_fragment fragment;
			struct pgm_opt_nak_list nak_list;
			struct pgm_opt_join join;
			struct pgm_opt_redirect redirect;
			struct pgm_opt_fin fin;
			struct pgm_opt_syn syn;
			struct pgm_opt_rst rst;
			uint8_t *start_option = buf->cur;

			PULL(buf, opt);

			if (opt.opt_length == 0) {
				logg(LOG_NOTICE, "Invalid option length zero\n");
				break;
			}

			last = opt.opt_type & PGM_OPT_END;
			switch (opt.opt_type & PGM_OPT_MASK) {
				case PGM_OPT_LENGTH:
					buf->cur = start_option;
					PULL(buf, length);
					total_opt_length = ntohs(length.opt_total_length);
					break;
				case PGM_OPT_FRAGMENT:
					PULL(buf, fragment);
					logg(LOG_INFO, "%s: OPT Fragment SQN=%x offset=%d len=%d\n", text,
							ntohl(fragment.opt_sqn), ntohl(fragment.opt_frag_off), ntohl(fragment.opt_frag_len));
					break;
				case PGM_OPT_NAK_LIST:
					PULL(buf, nak_list);
					logg(LOG_INFO, "%s: OPT NAK list #%d\n", text, (opt.opt_length - 1) /4 );

					break;
				case PGM_OPT_JOIN:
					PULL(buf, join);
					logg(LOG_INFO, "%s: OPT Join MIN SQN=%d\n",
								text, ntohl(join.opt_join_min));
					break;
				case PGM_OPT_REDIRECT:
					PULL(buf, redirect);

					logg(LOG_INFO, "%s: OPT Redirect NLA=%s\n", text, inet_ntoa(redirect.opt_nla));
					break;

				/* Not sure if these options are in use.  They are mostly not necessary (?) */
				case PGM_OPT_SYN:
					PULL(buf, syn);
					logg(LOG_INFO, "%s: OPT SYN\n", text);
					break;
				case PGM_OPT_FIN:
					PULL(buf, fin);
					logg(LOG_NOTICE, "%s: End of Stream TSI %s\n", i->text, text);
					if (s) {
						/* Remove all records */
						hash_del(i->pgm_tsi_hash, &tsi);
						free(s);
						i->nr_tsi--;
						s = NULL;
					}
					break;
				case PGM_OPT_RST:
					PULL(buf, rst);
					logg(LOG_NOTICE, "%s: OPT RST\n", text);
					break;

				case 0x21:
				case 0x22:
				case 0x23:
				case 0x24:
					break;

				/* NAK Intervals */
				case PGM_OPT_NAK_BO_IVL:
				case PGM_OPT_NAK_BO_RNG:

				/* NLA redirection */
				case PGM_OPT_PATH_NLA:

				/* Broken Multicast ??? */
				case PGM_OPT_NBR_UNREACH:

				case PGM_OPT_INVALID:

				/* Congestion "Control" and avoidance. Traffic load feedback */
				case PGM_OPT_CR:
				case PGM_OPT_CRQST:

				/* Forward Error correction.... How would this work ??? */
				case PGM_OPT_PARITY_PRM:
				case PGM_OPT_PARITY_GRP:
				case PGM_OPT_CURR_TGSIZE:

				/* Extensions by PGMCC */
				case PGM_OPT_PGMCC_DATA:
				case PGM_OPT_PGMCC_FEEDBACK:

				default:
					logg(LOG_NOTICE, "%s: Invalid PGM option=%x Option Skipped. D=%s\n",
						text, opt.opt_type & PGM_OPT_MASK,
						_hexbytes(start_option, opt.opt_length));
					break;
			}
			buf->cur = start_option + opt.opt_length;
		} while (!last);

		if (total_opt_length != buf->cur - options_start)
			logg(LOG_NOTICE, "%s: Option length mismatch. Expected %d but it is %ld\n", s->text, total_opt_length, buf->cur - options_start);
	}

	return ret;
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

				fprintf(out, "%s: lead=%d trail=%d last=%d lastRepairData=%d oldest=%d\n",
					buf, ps->lead, ps->trail, ps->last, ps->rlast, ps->oldest);

				if (ps->dup)
					fprintf(out, "Dup(OData!)=%u", ps->dup);

				if (ps->rdup)
					fprintf(out, "Dup(Rdata!)=%u", ps->rdup);

				if (ps->rdata)
					fprintf(out, "rdata=%u", ps->rdata);

				if (ps->ack)
					fprintf(out, "ack=%u", ps->ack);

				if (ps->nak)
					fprintf(out, "nak=%u", ps->nak);

				if (ps->first_sqn)
					fprintf(out, "firstsqn=%u", ps->first_sqn);

				if (ps->sqn_seq_errs) {
					fprintf(out, "sqnerrs=%u lastmissed=%u nr_missed=%u",
						ps->sqn_seq_errs, ps->last_missed_sqn, ps->last_missed_sqns);
				}
  			}
			offset += nr;
		}
	}
}

__attribute__((constructor))
static void pgm_init(void)
{
	register_concom("tsi", true, 0, "Show PGM info", tsi_cmd);
	register_enable("pgm", true, NULL, (int *)&pgm_mode, "2", "off", NULL,
		"PGM processing mode (0=None, 1= verify source address, 2=Passtrough, 3=DLR, 4=Resend with new TSI");

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


