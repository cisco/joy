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
 * \file example.c
 *
 * \brief An example of a data feature module that uses the C preprocessor
 * generic programming interface defined in feature.h.
 *
 */

#include <stdio.h>  
#include "example.h"     

/**
 * \fn __inline void example_init (struct example *example)
 * \param example structure to initialize
 * \return none
 */
__inline void example_init (struct example *example) {
    example->counter = 0;
}

/**
 * \fn void example_update (struct example *example,
 *                          const struct pcap_pkthdr *header,
                            const void *data,
                            unsigned int len,
                            unsigned int report_example)
 * \param example structure to initialize
 * \param header pointer to the pcap packet header
 * \param data data to use for update
 * \param len length of the data
 * \param report_example flag to determine if we filter example
 * \return none
 */
void example_update (struct example *example, 
		     const struct pcap_pkthdr *header, 
		     const void *data, 
		     unsigned int len, 
		     unsigned int report_example) {
    if (report_example) {
        example->counter += len;
    }
}

/**
 * \fn void example_print_json (const struct example *x1, const struct example *x2, zfile f)
 * \param x1 pointer to example structure
 * \param x2 pointer to example structure
 * \param f output file
 * \return none
 */
void example_print_json (const struct example *x1, const struct example *x2, zfile f) {
    unsigned int total;
  
    total = x1->counter;
    if (x2) {
        total += x2->counter;
    }
    if (total) {
        zprintf(f, ",\"example\":%u", total);
    }
}

/**
 * \fn void example_delete (struct example *example)
 * \param example pointer to example stucture
 * \return none
 */
void example_delete (struct example *example) { 
    /* no memory needs to be freed */
}

/**
 * \fn void example_unit_test ()
 * \param none
 * \return none
 */
void example_unit_test () {
    struct example example;
    const struct pcap_pkthdr *header = NULL; 
    zfile output;

    output = zattach(stdout, "w");
    if (output == NULL) {
        fprintf(stderr, "error: could not initialize (possibly compressed) stdout for writing\n");
    }
    example_init(&example);
    example_update(&example, header, NULL, 1, 1);
    example_update(&example, header, NULL, 2, 1);
    example_update(&example, header, NULL, 3, 1);
    example_update(&example, header, NULL, 4, 1);
    example_update(&example, header, NULL, 5, 1);
    example_update(&example, header, NULL, 6, 1);
    example_update(&example, header, NULL, 7, 1);
    example_update(&example, header, NULL, 8, 1);
    example_update(&example, header, NULL, 9, 1);
    example_print_json(&example, NULL, output);
} 

