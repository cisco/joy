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
#include "joy_api.h"

/**
 * \fn int main (int argc, char *argv[]) 
 * \brief main entry point for unit test execution
 * \param argc command line argument count
 * \param argv command line arguments
 * \return 0
 */
int main (int argc, char *argv[]) {
    int rc = 0;
    joy_init_t init_data;

    /* setup the joy options we want */
    memset(&init_data, 0x00, sizeof(joy_init_t));

    /* Set logging to warning level */
    init_data.type = 1;
    init_data.verbosity = JOY_LOG_WARN;

    /* intialize joy */
    rc = joy_initialize(&init_data, NULL, NULL, NULL);
    if (rc != 0) {
        printf(" -= Joy Initialized Failed =-\n");
        return -1;
    }

    if (radix_trie_unit_test() != 0) {
        printf("error: radix_trie test failed\n");
    } else {
        printf("radix_trie tests passed\n");
    }

    /* Test p2f.c */
    p2f_unit_test();

    /* Test all feature modules */
    unit_test_all_features(feature_list);
  
    /* cleanup */
    joy_context_cleanup(0);
    joy_shutdown();

    return 0;
}
