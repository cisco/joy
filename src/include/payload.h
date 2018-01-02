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
 * \file payload.h
 *
 * \brief payload generic programming interface defined in feature.h.
 *
 */
#ifndef PAYLOAD_H
#define PAYLOAD_H

#include <stdio.h> 
#include <pcap.h>
#include "output.h"
#include "feature.h"

#define PAYLOAD_LEN 32

/** usage string */
#define payload_usage "  payload=N                  include N bytes of payload\n"

/** payload filter key */
#define payload_filter(key) 1
  
/** payload structure */
typedef struct payload {
    unsigned int length;
    unsigned char data[PAYLOAD_LEN]; 
} payload_t;


declare_feature(payload);

/** initialization function */
void payload_init(struct payload **payload_handle);

/** update payload */
void payload_update(struct payload *payload, 
		    const struct pcap_pkthdr *header,
		    const void *data, 
		    unsigned int len, 
		    unsigned int report_payload);

/** JSON print payload */
void payload_print_json(const struct payload *w1, 
		    const struct payload *w2,
		    zfile f);

/** delete payload */
void payload_delete(struct payload **payload_handle);

/** payload unit test entry point */
void payload_unit_test();

#endif /* PAYLOAD_H */
