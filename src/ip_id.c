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
 * \file ip_id.c
 *
 * \brief The ip_id data feature records the Internet Protocol version
 * four (IPv4) Identification header field, using the generic
 * programming interface defined in feature.h.
 *
 */

#include <stdio.h>  
#include <string.h>     /* for memset()      */

#ifndef WIN32
#include <arpa/inet.h>  /* for htons()       */
#endif

#include "pkt.h"        /* for struct ip_hdr */
#include "ip_id.h"     


/**
 * \fn void ip_id_init (struct ip_id *ip_id)
 * \param ip_id structure to initialize
 * \return none
 */
void ip_id_init (struct ip_id *ip_id) {
    memset(ip_id->id, 0, sizeof(ip_id->id));
    ip_id->num_ip_id = 0;
}

/**
 * \fn void ip_id_update (struct ip_id *ip_id,
 *                        const struct pcap_pkthdr *header,
                          const void *data,
                          unsigned int len,
                          unsigned int report_ip_id)
 * \param ip_id structure pointer
 * \param header pointer to the pcap packet header
 * \param data data to use for update
 * \param data_len length of the data
 * \param report_ip_id flag to determine if we filter ip_id
 * 
 * \return none
 */
void ip_id_update (struct ip_id *ip_id, 
		   const struct pcap_pkthdr *header,
		   const void *ip_hdr_data, 
		   unsigned int len, 
		   unsigned int report_ip_id) {
    const struct ip_hdr *ip_hdr = ip_hdr_data;

    if (report_ip_id && (ip_id->num_ip_id < MAX_NUM_IP_ID)) { 
	ip_id->id[ip_id->num_ip_id] = htons(ip_hdr->ip_id);
	ip_id->num_ip_id++;
    }
}

/**
 * \fn void ip_id_print_json (const struct ip_id *x1, const struct ip_id *x2, zfile f)
 * \param x1 pointer to ip_id structure
 * \param x2 pointer to ip_id structure
 * \param f output file
 * \return none
 */
void ip_id_print_json (const struct ip_id *x1, const struct ip_id *x2, zfile f) {
    unsigned int i;

    if (x1->num_ip_id) {
        zprintf(f, ",\"oip_id\":[");
	for (i=0; i < x1->num_ip_id; i++) {
	    if (i) {
		zprintf(f, ",");
	    }
	    zprintf(f, "%u", x1->id[i]);
	}
        zprintf(f, "]");
    }
    if (x2 && x2->num_ip_id) {
        zprintf(f, ",\"iip_id\":[");
	for (i=0; i < x2->num_ip_id; i++) {
	    if (i) {
		zprintf(f, ",");
	    }
	    zprintf(f, "%u", x2->id[i]);
	}
        zprintf(f, "]");
    }
}

/**
 * \fn void ip_id_delete (struct ip_id *ip_id)
 * \param ip_id pointer to ip_id stucture
 * \return none
 */
void ip_id_delete (struct ip_id *ip_id) { 
    /* no memory needs to be freed */
}

/**
 * \fn void ip_id_unit_test ()
 * \param none
 * \return none
 */
void ip_id_unit_test () {
    
    /* no unit test - it's not clear that one is needed */

} 

