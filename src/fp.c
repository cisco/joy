/*
 *	
 * Copyright (c) 2018-2019 Cisco Systems, Inc.
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
 * \file tls_fp.c
 *
 * \brief Protocol fingerprint extraction feature module that uses the
 * C preprocessor generic programming interface defined in feature.h.
 *
 */

#include <stdio.h>  
#include <stdlib.h>
#include <string.h>    
#include "config.h"
#include "err.h"
#include "fp.h"
#include "extractor.h"

extern FILE *info;


/**
 * \brief Initialize the memory of fpx struct.
 *
 * \param fpx_handle contains fpx structure to init
 *
 * \return none
 */
void fpx_init(struct fpx **fpx_handle) {
    if (*fpx_handle != NULL) {
        fpx_delete(fpx_handle);
    }

    *fpx_handle = calloc(1, sizeof(struct fpx));
    if (*fpx_handle == NULL) {
        /* Allocation failed */
        joy_log_err("malloc failed");
        return;
    }

    /* initialize lengths */
    {
	struct fpx *f = *fpx_handle;
	
	f->fp_len = 0;
	f->tcp_fp_len = 0;
    }
}

/**
 * \fn void fpx_update (struct fpx *fpx,
 *                          const struct pcap_pkthdr *header,
                            const void *data,
                            unsigned int len,
                            unsigned int report_fpx)
 * \param fpx structure to initialize
 * \param header pointer to the pcap packet header
 * \param data data to use for update
 * \param len length of the data
 * \param report_fpx flag to determine if we filter fpx
 * \return none
 */
void fpx_update (struct fpx *fpx, 
                 const struct pcap_pkthdr *header, 
                 const void *data, 
                 unsigned int len, 
                 unsigned int report_fpx) {
    struct extractor x;
    
    if (report_fpx && fpx && header) {

	if (fpx->tcp_fp_len == 0) {
	    extractor_init(&x, data, len, fpx->tcp_fp, MAX_TCP_FP_LEN);  	    
	    fpx->tcp_fp_len = extractor_process_tcp(&x);
	}

	if (fpx->fp_len == 0) {
	    extractor_init(&x, data, len, fpx->fp, MAX_FP_LEN);  	    
	    fpx->fp_len = extractor_process_tls(&x);	    
	}
    }
}

static void fpx_print_json_unidirectional(const struct fpx *x, zfile f) {
    if (x->tcp_fp_len) {
	zprintf(f, "\"tcp\":");
	zprintf_raw_as_structured_hex(f, x->tcp_fp, x->tcp_fp_len);
	if (x->fp_len) {
	    zprintf(f, ",");
	}
    }
    if (x->fp_len) {
	zprintf(f, "\"tls\":");
	zprintf_raw_as_structured_hex(f, x->fp, x->fp_len);
    }
}

/**
 * \fn void fpx_print_json (const struct fpx *x1, const struct fpx *x2, zfile f)
 * \param x1 pointer to fpx structure (MUST NOT be NULL)
 * \param x2 pointer to fpx structure (MAY be NULL)
 * \param f output file
 * \return none
 */
void fpx_print_json (const struct fpx *x1, const struct fpx *x2, zfile f) {

    /*
     * check for fingerprints and print if needed
     */
    if (x1->tcp_fp_len || x1->fp_len) {
	zprintf(f, ",\"fingerprints\":{");
	fpx_print_json_unidirectional(x1, f);
	zprintf(f, "}");
    }

    /*
     * if flow twin x2 is present, check for fingerprints and print if needed
     */
    if (x2 && (x2->tcp_fp_len || x2->fp_len)) {
	zprintf(f, ",\"fingerprints_in\":{");
	fpx_print_json_unidirectional(x2, f);
	zprintf(f, "}");	
    }
}

/**
 * \brief Delete the memory of fpx struct.
 *
 * \param fpx_handle contains fpx structure to delete
 *
 * \return none
 */
void fpx_delete (struct fpx **fpx_handle) { 
    struct fpx *fpx = *fpx_handle;

    if (fpx == NULL) {
        return;
    }

    /* Free the memory and set to NULL */
    free(fpx);
    *fpx_handle = NULL;
}

/**
 * \fn void fpx_unit_test ()
 * \param none
 * \return none
 */
void fpx_unit_test () {
    // struct fpx *fpx = NULL;
    // const struct pcap_pkthdr *header = NULL; 

    /* TBD */
    
} 
