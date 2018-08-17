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
 * \file plaintext.h
 *
 * \brief Plaintext RAT command detection
 */
#ifndef PLAINTEXT_H
#define PLAINTEXT_H

#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "output.h"

#define plaintext_usage "  plaintext=1                     RAT plaintext command detection\n"

#define plaintext_filter(record) \
    ((record->key.prot == 6))

#define PLAINTEXT_KEYWORDS_LENGTH (100)
#define MAX_SEARCH_LEN (32)
#define MAX_MATCHES (5)

typedef struct plaintext{
    int detected;
    int matches[MAX_MATCHES];
    int match_len;
} plaintext_t;

/** initialize http data structure */
void plaintext_init(struct plaintext **plaintext_handle);

/** update http data structure */
void plaintext_update(struct plaintext *plaintext,
                 const struct pcap_pkthdr *header,
                 const void *data,
                 unsigned int data_len,
                 unsigned int report_plaintext);

/** print out an http data structure */
void plaintext_print_json(const struct plaintext *h1,
                      const struct plaintext *h2,
                      zfile f);


/** remove an http data structure */
void plaintext_delete(struct plaintext **plaintext_handle);

void plaintext_unit_test();

#endif /* PLAINTEXT_H */
