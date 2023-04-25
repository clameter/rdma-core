/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, and (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 *
 * Original code by Andy Heffernan (ahh@juniper.net)
 *
 * Modified for rdma-core by Christoph Lameter <cl@linux.com>
 */

/*
 * PGM header (RFC 3208)
 */
struct pgm_header {
    uint16_t	pgm_sport;
    uint16_t	pgm_dport;
    uint8_t	pgm_type;
    uint8_t	pgm_options;
    uint16_t	pgm_sum;
    uint8_t	pgm_gsid[6];
    uint16_t	pgm_length;
};


struct pgm_spm {
    uint32_t	pgms_seq;
    uint32_t	pgms_trailseq;
    uint32_t	pgms_leadseq;
    uint16_t	pgms_nla_afi;
    uint16_t	pgms_reserved;
    /* ... uint8_t	pgms_nla[0]; */
    /* ... options */
};

struct pgm_nak {
    uint32_t	pgmn_seq;
    uint16_t	pgmn_source_afi;
    uint16_t	pgmn_reserved;
    /* ... uint8_t	pgmn_source[0]; */
    /* ... uint16_t	pgmn_group_afi */
    /* ... uint16_t	pgmn_reserved2; */
    /* ... uint8_t	pgmn_group[0]; */
    /* ... options */
};

struct pgm_poll {
    uint32_t	pgmp_seq;
    uint16_t	pgmp_round;
    uint16_t	pgmp_subtype;
    uint16_t	pgmp_nla_afi;
    uint16_t	pgmp_reserved;
    /* ... uint8_t	pgmp_nla[0]; */
    /* ... options */
};

struct pgm_polr {
    uint32_t	pgmp_seq;
    uint16_t	pgmp_round;
    uint16_t	pgmp_reserved;
    /* ... options */
};

struct pgm_data {
    uint32_t	pgmd_seq;
    uint32_t	pgmd_trailseq;
    /* ... options */
};

typedef enum _pgm_type {
    PGM_SPM = 0,		/* source path message */
    PGM_POLL = 1,		/* POLL Request */
    PGM_POLR = 2,		/* POLL Response */
    PGM_ODATA = 4,		/* original data */
    PGM_RDATA = 5,		/* repair data */
    PGM_NAK = 8,		/* NAK */
    PGM_NULLNAK = 9,		/* Null NAK */
    PGM_NCF = 10,		/* NAK Confirmation */
    PGM_ACK = 11,		/* ACK for congestion control */
    PGM_SPMR = 12,		/* SPM request */
    PGM_MAX = 255
} pgm_type;

#define PGM_OPT_BIT_PRESENT	0x01
#define PGM_OPT_BIT_NETWORK	0x02
#define PGM_OPT_BIT_VAR_PKTLEN	0x40
#define PGM_OPT_BIT_PARITY	0x80

#define PGM_OPT_LENGTH		0x00
#define PGM_OPT_FRAGMENT        0x01
#define PGM_OPT_NAK_LIST        0x02
#define PGM_OPT_JOIN            0x03
#define PGM_OPT_NAK_BO_IVL	0x04
#define PGM_OPT_NAK_BO_RNG	0x05

#define PGM_OPT_REDIRECT        0x07
#define PGM_OPT_PARITY_PRM      0x08
#define PGM_OPT_PARITY_GRP      0x09
#define PGM_OPT_CURR_TGSIZE     0x0A
#define PGM_OPT_NBR_UNREACH	0x0B
#define PGM_OPT_PATH_NLA	0x0C

#define PGM_OPT_SYN             0x0D
#define PGM_OPT_FIN             0x0E
#define PGM_OPT_RST             0x0F
#define PGM_OPT_CR		0x10
#define PGM_OPT_CRQST		0x11

#define PGM_OPT_PGMCC_DATA	0x12
#define PGM_OPT_PGMCC_FEEDBACK	0x13

#define PGM_OPT_MASK		0x7f

#define PGM_OPT_END		0x80    /* end of options marker */
#define PGM_OPT_INVALID		0x7f

#define PGM_MIN_OPT_LEN		4

struct pgm_opt_header {
	uint8_t		opt_type;
	uint8_t		opt_length;
	uint8_t		opt_reserved;
};

struct pgm_opt_length {
	uint8_t		opt_type;
	uint8_t		opt_length;
	uint16_t	opt_total_length;
};

struct pgm_opt_syn {
	uint8_t		opt_reserved;
};


#define PGM_OPX_MASK		0x3
#define PGM_OPX_IGNORE		0x0
#define PGM_OPX_INVALIDATE	0x1
#define PGM_OPX_DISCARD		0x2

#define AFI_IP	1


