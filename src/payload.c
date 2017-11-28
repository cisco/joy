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
 * \file payload.c
 *
 * \brief Payload feature module - captures the initial bytes of the
 * TCP, UDP, or IDP payload, using the C preprocessor generic
 * programming interface defined in feature.h.
 *
 */

#include <stdio.h>  
#include <stdlib.h>
#include <string.h>
#include "payload.h"     
#include "err.h"
#include "p2f.h"    

/**
 * \brief Initialize the memory of the payload struct.
 *
 * \param payload_handle contains payload structure to init
 *
 * \return none
 */
__inline void payload_init (struct payload **payload_handle) {
   if (*payload_handle != NULL) {
        payload_delete(payload_handle);
    }

    *payload_handle = malloc(sizeof(struct payload));
    if (*payload_handle == NULL) {
        /* Allocation failed */
        joy_log_err("malloc failed");
        return;
    }
    (*payload_handle)->length = 0;
    // memset(*payload_handle, 0, sizeof(struct payload));
}


/**
 * \fn void payload_update (struct payload *payload,
 *                          const struct pcap_pkthdr *header,
                            const void *data,
                            unsigned int len,
                            unsigned int report_payload)
 * \param payload structure to initialize
 * \param header pointer to the pcap packet header
 * \param data data to use for update
 * \param len length of the data
 * \param report_payload flag to determine if we filter payload
 * \return none
 */
void payload_update (struct payload *payload, 
		     const struct pcap_pkthdr *header, 
		     const void *data, 
		     unsigned int len, 
		     unsigned int report_payload) {
    
    if (payload == NULL || payload->length != 0) {
	return;
    }
    if (report_payload && len) {
	unsigned int copylen = len > PAYLOAD_LEN ? PAYLOAD_LEN : len;
	payload->length = copylen;
	memcpy(payload->data, data, copylen);
    }
}

/**
 * \fn void payload_print_json (const struct payload *x1, const struct payload *x2, zfile f)
 * \param x1 pointer to payload structure
 * \param x2 pointer to payload structure
 * \param f output file
 * \return none
 */
void payload_print_json (const struct payload *x1, const struct payload *x2, zfile f) {

    if (x1->length || (x2 && x2->length)) {
        zprintf(f, ",\"payload\":{");
	if (x1->length) {
	    zprintf(f, "\"out\":");
	    zprintf_raw_as_hex(f, x1->data, x1->length);
	}
	if (x2 && x2->length) {
	    if (x1->length) {
		zprintf(f, ",");		
	    }
	    zprintf(f, "\"in\":");
	    zprintf_raw_as_hex(f, x2->data, x2->length);
	}
        zprintf(f, "}");
    }
}

/**
 * \brief Delete the memory of Payload struct.
 *
 * \param payload_handle contains payload structure to delete
 *
 * \return none
 */
void payload_delete (struct payload **payload_handle) { 
    struct payload *payload = *payload_handle;

    if (payload == NULL) {
        return;
    }

    /* Free the memory and set to NULL */
    free(payload);
    *payload_handle = NULL;
}

/**
 * \fn void payload_unit_test ()
 * \param none
 * \return none
 */
void payload_unit_test () {
    struct payload *payload = NULL;
    const struct pcap_pkthdr *header = NULL; 

    payload_init(&payload);
    payload_update(payload, header, NULL, 1, 1);

    payload_delete(&payload);
} 

