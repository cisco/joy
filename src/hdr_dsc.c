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
 * \file hdr_dsc.c
 *
 * \brief header description and protocol identification implementation
 */

#include "hdr_dsc.h"
#include <string.h> 
#include "p2f.h"

/** maximum number of description headers */
#define MAX_NUM_HDRS 10

#if 0 /* this code not yet used */

/*
 * packet format description
 */
#define FD_NONE  0
#define FD_CONST 1
#define FD_INCR  2

struct format_element {
    unsigned char type;
    unsigned char length;
};

#define FD_MAX      16
#define FD_DATA_MAX 32 

struct format_description {
    struct format_element element[FD_MAX];
    unsigned char data[FD_DATA_MAX];
};

#endif


/**
 * \fn void header_description_init (header_description_t *hd)
 * \param hd pointer to the header description structure
 * \return none
 */
void header_description_init (header_description_t *hd) {
    if (hd != NULL) {
        memset(hd->const_value, 0, sizeof(hd->const_value));
        memset(hd->const_mask, 0, sizeof(hd->const_mask));
        memset(hd->seq_mask, 0, sizeof(hd->seq_mask));
        hd->num_headers_seen = 0;
    }
}

/**
 * \fn void header_description_set_initial (header_description_t *hd, const void *packet, unsigned int len)
 * \param hd pointer to the header description structure
 * \param packet packet used for setting the initial header description
 * \param len length of the packet
 * \return none
 */
void header_description_set_initial (header_description_t *hd, const void *packet, unsigned int len) {
    if ((hd != NULL) && (packet != NULL)) {
        memcpy(hd->initial, packet, len);
        memcpy(hd->const_value, packet, len);
        memset(hd->const_mask, 0xff, sizeof(hd->const_mask));
        hd->num_headers_seen = 1;
    }
}

/**
 * \fn void header_description_set (header_description_t *hd, const void *packet, unsigned int len)
 * \param hd pointer to the header description structure
 * \param packet packet used for setting the initial header description
 * \param len length of the packet
 * \return none
 */
void header_description_set (header_description_t *hd, const void *packet, unsigned int len) {
    int i;
    const unsigned char *p = packet;

    if ((hd == NULL) || (packet == NULL)) {
        return;
    }

    /*
     * find constant part of header, and set the constant mask and value
     * in the header description
     */
    for (i=0; i<len; i++) {
        hd->const_mask[i] &= ~(hd->const_value[i] ^ p[i]);
        hd->const_value[i] = hd->const_mask[i] & p[i];
    }

    /* 
     * loop over bytes of h1 and h2 from least significant to most
     * significant, and for bytes that are not constant, detect
     * counters, and assume counters propagate from least significant
     * bytes to most significant bytes (i.e.  assume network byte order)
     */
    i=len-1; 
    while (i >= 0) {
        while ((hd->const_mask[i] == 0) && (hd->const_value[i] + 1 == p[i])) {
              hd->seq_mask[i] = 0xff;
              i--;
        }
        i--;
    }
  
    hd->num_headers_seen++;
}

/**
 * \fn inline void header_description_update (header_description_t *hd,
             const void *packet,
             unsigned int report_hd)
 * \param hd pointer to the header description structure
 * \param packet pointer to the packet to use for udpate
 * \param report_hd determine whether or not to process header decriptors
 * \return none
 */
inline void header_description_update (header_description_t *hd, 
			       const void *packet, 
			       unsigned int report_hd) {

    if (report_hd) {
        if (hd->num_headers_seen == 0) {
            header_description_set_initial(hd, packet, report_hd);
        } else if (hd->num_headers_seen < MAX_NUM_HDRS) {
            header_description_set(hd, packet, report_hd);
        }
        /*
         * we could refine our description of the header based on an
         * analysis of many successive headers, but for now we only do ten
         */
    }
} 

/**
 * \fn void header_description_printf (const header_description_t *hd, zfile f, unsigned int len)
 * \breif what representation should be output?  perhaps a list of
 * type/length/values, with types = const, integer, and other?
 * \param hd pointer to the header description structure
 * \param f file to send output to
 * \param len header lengths
 * \return none
 */
void header_description_printf (const header_description_t *hd, zfile f, unsigned int len) {
    unsigned int i;

    if (hd->num_headers_seen < 2) {
        return;  /* no point in printing out information-free data */
    }

    /*
     * hdr_dsc: [ 
     *      { t: 0, l: 8, v: 0xff }     
     *      { t: 1, l: 16, v: 0xcafe }
     *      { t: 2, l: 32, v: 0x00001 }
     *    ] 
     *
     *  0 = constant
     *  1 = integexr
     *  2 = other
     */

    zprintf(f, ",\"hd\":{\"n\":%u,\"cm\":\"", hd->num_headers_seen);
    for (i=0; i<len; i++) {
        zprintf(f, "%02x", hd->const_mask[i]);
    }
    zprintf(f, "\",\"cv\":\"");
    for (i=0; i<len; i++) {
        zprintf(f, "%02x", hd->const_value[i]);
    }
    zprintf(f, "\",\"sm\":\"");
    for (i=0; i<len; i++) {
        zprintf(f, "%02x", hd->seq_mask[i]);
    }
    zprintf(f, "\",\"i\":\"");
    for (i=0; i<len; i++) {
        zprintf(f, "%02x", hd->initial[i]);
    }
    zprintf(f, "\"}");

}

