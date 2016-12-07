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
 * \file salt.h
 *
 * \brief SALT module using the generic programming interface defined
 * in feature.h.
 *
 */
#ifndef SALT_H
#define SALT_H

#include <stdio.h> 
#include "output.h"
#include "feature.h"

#define MAX_NUM_PKT 200

/** usage string */
#define salt_usage "  salt=1                  include salt feature\n"

/** salt filter key */
#define salt_filter(key) 1
  
/** salt structure */
typedef struct salt {
    unsigned short pkt_len[MAX_NUM_PKT];  /*!< array of packet appdata lengths */  
    struct timeval pkt_time[MAX_NUM_PKT]; /*!< array of arrival times          */
    unsigned int ack[MAX_NUM_PKT];
    unsigned int seq[MAX_NUM_PKT];
    unsigned int np;
} salt_t;


declare_feature(salt);

/** initialization function */
void salt_init(struct salt *salt);

/** update salt */
void salt_update(struct salt *salt, 
		 const void *data, 
		 unsigned int len, 
		 unsigned int report_salt);

/** JSON print salt */
void salt_print_json(const struct salt *w1, 
		     const struct salt *w2,
		     zfile f);

/** delete salt */
void salt_delete(struct salt *salt);

/** salt unit test entry point */
void salt_unit_test();

#endif /* SALT_H */
