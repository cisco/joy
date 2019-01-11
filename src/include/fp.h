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
 * \file fp.h
 *
 * \brief  Fingerprint extraction module
 *
 */
#ifndef FPX_H
#define FPX_H

#include <stdio.h> 
#include <pcap.h>
#include "output.h"
#include "feature.h"
#include "extractor.h"

#define MAX_TCP_FP_LEN 32
#define MAX_FP_LEN 1500

/** usage string */
#define fpx_usage "  fpx=1                      include fingerprint extraction\n"

/** fpx filter key */
#define fpx_filter(record) 1

/** fpx structure */
typedef struct fpx {
    unsigned int tcp_fp_len;
    unsigned char tcp_fp[MAX_TCP_FP_LEN];
    unsigned int fp_len;
    unsigned char fp[MAX_FP_LEN];
} fpx_t;

declare_feature(fpx);

/** initialization function */
void fpx_init(struct fpx **fpx_handle);

/** update fpx */
void fpx_update(struct fpx *fpx, 
		    const struct pcap_pkthdr *header,
		    const void *data, 
		    unsigned int len, 
		    unsigned int report_fpx);

/** JSON print fpx */
void fpx_print_json(const struct fpx *w1, 
		    const struct fpx *w2,
		    zfile f);

/** delete fpx */
void fpx_delete(struct fpx **fpx_handle);

/** fpx unit test entry point */
void fpx_unit_test(void);

#endif /* FPX_H */
