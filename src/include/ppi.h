/*
 *	
 * Copyright (c) 2016 Cisco Systems, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 * 
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * \file ppi.h
 *
 * \brief per-packet information (ppi) module using the generic
 * programming interface defined in feature.h.
 *
 */
#ifndef PPI_H
#define PPI_H

#include <stdio.h> 
#include "output.h"
#include "feature.h"

#define MAX_NUM_PKT 200

/** usage string */
#define ppi_usage "  ppi=1                      include per-packet info (ppi)\n"

/** ppi filter key */
#define ppi_filter(record) 1

#define TCP_OPT_LEN 24
  
struct pkt_info {
    struct timeval time; 
    unsigned int ack;
    unsigned int seq;
    unsigned short len;  
    unsigned char flags;
    unsigned short opt_len;  
    unsigned char opts[TCP_OPT_LEN];
};

/** ppi structure */
typedef struct ppi {
    unsigned int np;
    struct pkt_info pkt_info[MAX_NUM_PKT];
} ppi_t;

void tcp_flags_to_string(unsigned char flags, char *string);

void tcp_opt_print_json(zfile f,
                        const unsigned char *options,
                        unsigned int total_len);

declare_feature(ppi);

/** initialization function */
void ppi_init(struct ppi **ppi_handle);

/** update ppi */
void ppi_update(struct ppi *ppi, 
		const struct pcap_pkthdr *header,
		const void *data, 
		unsigned int len, 
		unsigned int report_ppi);

/** JSON print ppi */
void ppi_print_json(const struct ppi *w1, 
		     const struct ppi *w2,
		     zfile f);

/** delete ppi */
void ppi_delete(struct ppi **ppi_handle);

/** ppi unit test entry point */
void ppi_unit_test();

#endif /* PPI_H */
