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
#include "radix_trie.h"
#include "modules.h"
#include "p2f.h"
#include "dns.h"
#include "err.h"

/*
 * use the "info" output stream to represent secondary output - it is
 * called by debug_printf()
 */
FILE *info;

extern unsigned int verbosity;

/**
 * \fn int main (int argc, char *argv[]) 
 * \brief main entry point for unit test execution
 * \param argc command line argument count
 * \param argv command line arguments
 * \return 0
 */
int main (int argc, char *argv[]) {

    /*
     * use stderr for debug output 
     */
    info = stderr; 

    /* Set logging to warning level */
    verbosity = JOY_LOG_WARN;

    if (radix_trie_unit_test() != 0) {
        printf("error: radix_trie test failed\n");
    } else {
        printf("radix_trie tests passed\n");
    }

    unit_test_all_features(feature_list);
    flow_record_list_unit_test();
    dns_unit_test();
  
    return 0;
}
