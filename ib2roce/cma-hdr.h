// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2005 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2002-2005, Network Appliance, Inc. All rights reserved.
 * Copyright (c) 1999-2019, Mellanox Technologies, Inc. All rights reserved.
 * Copyright (c) 2005-2006 Intel Corporation.  All rights reserved.
 * Modified in kernel and copied from the kernel source for use in user space:
 * Copyright (c) 2022 Christoph Lameter <cl@linux.com>
 */

union cma_ip_addr {
	struct in6_addr ip6;
	struct {
		__be32 sess_qpn;		/* QPN of the UD session to be established or 0 for not provided */
		__be32 sess_qkey;		/* QKEY for the UD session to be established or 0 for default */
		__be32 sidr_qpn;		/* QPN that will take the SIDR REP response or 0 for the default (QP1) */
		__be32 addr;			/* Source and destination IP address */
	} ip4;
};

struct cma_hdr {
	uint8_t cma_version;
	uint8_t ip_version;	/* IP version: 7:4 */
	__be16 port;
	union cma_ip_addr src_addr;
	union cma_ip_addr dst_addr;
};

#define CMA_VERSION 0x00

static inline uint8_t cma_get_ip_ver(const struct cma_hdr *hdr)
{
	return hdr->ip_version >> 4;
}

static inline void cma_set_ip_ver(struct cma_hdr *hdr, uint8_t ip_ver)
{
	hdr->ip_version = (ip_ver << 4) | (hdr->ip_version & 0xF);
}


