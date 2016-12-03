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
 * \file ip_id.h
 *
 * \brief ip_id generic programming interface defined in feature.h.
 *
 */
#ifndef IP_ID_H
#define IP_ID_H

#include <stdio.h> 
#include "output.h"
#include "feature.h"

/** 
 * MAX_NUM_IP_ID is the maximum number of IP ID fields that will be
 * reported for a single flow
 */
#define MAX_NUM_IP_ID 50

/** usage string */
#define ip_id_usage "  ip_id=1                    include ip_id feature\n"

/** ip_id filter key */
#define ip_id_filter(key) 1
  
/** ip_id structure */
typedef struct ip_id {
    unsigned short int num_ip_id;
    unsigned short int id[MAX_NUM_IP_ID];
} ip_id_t;


declare_feature(ip_id);

/** initialization function */
void ip_id_init(struct ip_id *ip_id);

/** update ip_id */
void ip_id_update(struct ip_id *ip_id, 
		    const void *data, 
		    unsigned int len, 
		    unsigned int report_ip_id);

/** JSON print ip_id */
void ip_id_print_json(const struct ip_id *w1, 
		    const struct ip_id *w2,
		    zfile f);

/** delete ip_id */
void ip_id_delete(struct ip_id *ip_id);

/** ip_id unit test entry point */
void ip_id_unit_test();

#endif /* IP_ID_H */
