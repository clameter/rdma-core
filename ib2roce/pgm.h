#ifndef IB2ROCE_PGM
#define IB2ROCE_PGM
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

#include "channel.h"
#include "multicast.h"
#include "buffers.h"
#include "packet.h"

extern bool pgm_mode;

bool pgm_process(struct rdma_channel *c, struct mc *m, struct buf *buf);

unsigned pgm_brief_stats(char *b, struct i2r_interface *i);

#define MAX_PGM_TYPE (PGM_ACK + 1)
#define PGM_OPT_TYPE_MASK (PGM_OPT_VAR_PKTLEN -1)
#define MAX_PGM_OPT (PGM_OPT_RST + 1)

/* There are 3 categories of pgm_data frames and one invalid. Encode them in a 64 bit integer */
#define PGM_CAT_SHIFT 16

enum cat_type { cat_invalid, cat_spm, cat_data, cat_nak, pgm_cat_max };

/* This mapping only works for IPv4 */
static const uint64_t cat_sizes =
	(sizeof(struct pgm_spm) << PGM_CAT_SHIFT) +
	(sizeof(struct pgm_data) << (2 * PGM_CAT_SHIFT)) +
	(sizeof(struct pgm_nak) << (3 * PGM_CAT_SHIFT));

/* Mapping of PGM_TYPES to categories */

/* 2 bits required for each entry in type_to_cat */
#define PGM_TYPE_SHIFT 2

static const uint64_t type_to_cat_uc_mc[2] = {
	/* Unicast */
        (cat_nak << (8 * PGM_TYPE_SHIFT)) +		/* PGM_NAK         = 0x08 */
        (cat_nak << (9 * PGM_TYPE_SHIFT)) +		/* PGM_NNAK        = 0x09 */
        (cat_nak << (13 * PGM_TYPE_SHIFT))		/* PGM_ACK         = 0x0d */,

	/* Multicast */
	cat_spm +					/* PGM_SPM	   = 0x00 */
        (cat_data << (4 * PGM_TYPE_SHIFT)) +		/* PGM_ODATA       = 0x04 */
        (cat_data << (5 * PGM_TYPE_SHIFT)) +		/* PGM_RDATA       = 0x05 */
        (cat_nak << (10 * PGM_TYPE_SHIFT)) +		/* PGM_NCF         = 0x0a */
        (cat_nak << (13 * PGM_TYPE_SHIFT))		/* PGM_ACK         = 0x0d */
};

static const uint64_t type_to_cat = {
	cat_spm +					/* PGM_SPM	   = 0x00 */
        (cat_data << (4 * PGM_TYPE_SHIFT)) +		/* PGM_ODATA       = 0x04 */
        (cat_data << (5 * PGM_TYPE_SHIFT)) +		/* PGM_RDATA       = 0x05 */
        (cat_nak << (8 * PGM_TYPE_SHIFT)) +		/* PGM_NAK         = 0x08 */
        (cat_nak << (9 * PGM_TYPE_SHIFT)) +		/* PGM_NNAK        = 0x09 */
        (cat_nak << (10 * PGM_TYPE_SHIFT)) +		/* PGM_NCF         = 0x0a */
        (cat_nak << (13 * PGM_TYPE_SHIFT))		/* PGM_ACK         = 0x0d */
};


static inline enum cat_type __pgm_type2cat(uint64_t mask, enum pgm_type_e ptype)
{
	return (mask >> (ptype * PGM_TYPE_SHIFT)) & ((1 << PGM_TYPE_SHIFT) -1);
}

static inline enum cat_type pgm_type2cat(enum pgm_type_e ptype, bool multicast)
{
	return __pgm_type2cat(type_to_cat_uc_mc[multicast], ptype);
}

static inline unsigned pgm_type2size(enum pgm_type_e ptype)
{
	return (cat_sizes >> (__pgm_type2cat(type_to_cat, ptype) * PGM_CAT_SHIFT)) & ((1 << PGM_CAT_SHIFT) -1);
}

#define PGM_EXT_OPT_LABEL 0x22

#endif
