/*
 *	
 * Copyright (c) 2018 Cisco Systems, Inc.
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
 * \file fp_tls.h
 *
 * \brief TLS fingerprinting
 *
 */
#ifndef FP_TLS_H
#define FP_TLS_H

#include <stdio.h> 
#include <pcap.h>
#include "output.h"
#include "feature.h"
#include "extractor.h"

#define MAX_FP_LEN 1500

/** usage string */
#define fp_tls_usage "  fp_tls=1                   include TLS fingerprinting\n"

/** fp_tls filter key */
#define fp_tls_filter(record) (record->app == 443 || (record->key.dp == 443 || record->key.sp == 443))
  
/** fp_tls structure */
typedef struct fp_tls {
    unsigned int fp_len;
    unsigned char fp[MAX_FP_LEN];
} fp_tls_t;

declare_feature(fp_tls);

/** initialization function */
void fp_tls_init(struct fp_tls **fp_tls_handle);

/** update fp_tls */
void fp_tls_update(struct fp_tls *fp_tls, 
		    const struct pcap_pkthdr *header,
		    const void *data, 
		    unsigned int len, 
		    unsigned int report_fp_tls);

/** JSON print fp_tls */
void fp_tls_print_json(const struct fp_tls *w1, 
		    const struct fp_tls *w2,
		    zfile f);

/** delete fp_tls */
void fp_tls_delete(struct fp_tls **fp_tls_handle);

/** fp_tls unit test entry point */
void fp_tls_unit_test();

#endif /* FP_TLS_H */
