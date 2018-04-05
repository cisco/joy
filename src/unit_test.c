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
 * \file unit_test.c
 *
 * \brief unit tests for various functions
 */

#include <stdio.h>
#include <string.h>
#include "radix_trie.h"
#include "modules.h"
#include "p2f.h"
#include "config.h"
#include "err.h"

/* per instance context data */
struct joy_ctx_data  {
    struct flocap_stats stats;
    struct flocap_stats last_stats;
    struct timeval last_stats_output_time;
    struct flow_record *flow_record_chrono_first;
    struct flow_record *flow_record_chrono_last;
    flow_record_list flow_record_list_array[FLOW_RECORD_LIST_LEN];
    unsigned long int reserved_info;
    unsigned long int reserved_ctx;
};
struct joy_ctx_data main_ctx;

struct configuration active_config;
struct configuration *glb_config;
zfile output = NULL;
FILE *info = NULL;

/**
 * \fn int main (int argc, char *argv[]) 
 * \brief main entry point for unit test execution
 * \param argc command line argument count
 * \param argv command line arguments
 * \return 0
 */
int main (int argc, char *argv[]) {

    memset(&main_ctx, 0x00, sizeof(struct joy_ctx_data));
    memset(&active_config, 0x00, sizeof(struct configuration));
    glb_config = &active_config;

    /*
     * use stdout/stderr for output 
     */
    info = stderr; 
    output = zattach(stdout,"w");
    if (output == NULL) {
        fprintf(stderr, "error: could not initialize (possibly compressed) stdout for writing\n");
    }

    /* Set logging to warning level */
    glb_config->verbosity = JOY_LOG_WARN;

    if (radix_trie_unit_test() != 0) {
        printf("error: radix_trie test failed\n");
    } else {
        printf("radix_trie tests passed\n");
    }

    /* Test p2f.c */
    p2f_unit_test();

    /* Test all feature modules */
    unit_test_all_features(feature_list);
  
    return 0;
}
