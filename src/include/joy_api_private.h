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
 * \file joy_api_private.h
 *
 * \brief Internal implementation specifics for the Joy API.
 *
 */

#ifndef JOY_API_PRV_H
#define JOY_API_PRV_H

#include "output.h"
#include "ipfix.h"

#ifdef JOY_USE_VPP_OPT
#include "vppinfra/vec.h"

/* VPP optimized implementations */

#define JOY_API_ALLOC_CONTEXT(a,b)   \
    vec_validate_aligned(a, (b-1), CLIB_CACHE_LINE_BYTES)

#define JOY_API_FREE_CONTEXT(a)    \
    vec_free(a)

#define JOY_MAX_CTX_INDEX(a)   \
    vec_len(a)

#define JOY_CTX_AT_INDEX(a,b)   \
    vec_elt_at_index(a,b)

#else

/* default standard implementations */

#define JOY_API_ALLOC_CONTEXT(a,b)   \
    a = calloc(1, (sizeof(struct joy_ctx_data) * b));    

#define JOY_API_FREE_CONTEXT(a)    \
    free(a);                       \
    a = NULL;

#define JOY_MAX_CTX_INDEX(a)   \
    joy_num_contexts

#define JOY_CTX_AT_INDEX(a,b)   \
    (a + b)

#endif

/* per instance context data */
struct joy_ctx_data  {
    unsigned int ctx_id;
    unsigned int idp_recs_ready;
    unsigned int tls_recs_ready;
    unsigned int splt_recs_ready;
    unsigned int salt_recs_ready;
    unsigned int bd_recs_ready;
    zfile output;
    char *output_file_basename;
    unsigned int records_in_file;
    struct timeval global_time;
    flocap_stats_t stats;
    flocap_stats_t last_stats;
    struct timeval last_stats_output_time;
    ipfix_message_t *export_message;
    flow_record_t *flow_record_chrono_first;
    flow_record_t *flow_record_chrono_last;
    flow_record_list flow_record_list_array[FLOW_RECORD_LIST_LEN];
    unsigned long int reserved_info;
    unsigned long int reserved_ctx;
#ifdef JOY_USE_VPP_OPT
    CLIB_CACHE_LINE_ALIGN_MARK(pad);
#endif
};

#endif /* JOY_API_PRV_H */
