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
 * \file salt.c
 *
 * \brief Sequence of Application Lengths and Times (SALT) data
 * feature module, using the C preprocessor generic programming
 * interface defined in feature.h.
 *
 */

#include <stdio.h>  
#include <string.h>   /* for memset() */
#include <stdlib.h>
#include "salt.h"     
#include "pkt.h"      /* for tcp macros */
#include "err.h"


/**
 * \brief Initialize the memory of SALT struct.
 *
 * \param salt_handle contains salt structure to init
 *
 * \return none
 */
void salt_init(struct salt **salt_handle) {
    if (*salt_handle != NULL) {
        salt_delete(salt_handle);
    }

    *salt_handle = malloc(sizeof(struct salt));
    if (*salt_handle == NULL) {
        /* Allocation failed */
        joy_log_err("malloc failed");
        return;
    }
    memset(*salt_handle, 0, sizeof(struct salt));
}

/**
 * \fn void salt_update (struct salt *salt,
 *                       const struct pcap_pkthdr *header,
                         const void *data,
                         unsigned int len,
                         unsigned int report_salt)
 * \param salt structure to initialize
 * \param header pointer to the pcap packet header
 * \param data data to use for update
 * \param len length of the data
 * \param report_salt flag to determine if we filter salt
 * 
 * \return none
 */
void salt_update (struct salt *salt, 
		  const struct pcap_pkthdr *header,
		  const void *tcp_start, 
		  unsigned int len, 
		  unsigned int report_salt) {
    const struct tcp_hdr *tcp = tcp_start;  

    if (report_salt) {
        if (salt->np < MAX_NUM_PKT) {
	    salt->seq[salt->np] = ntohl(tcp->tcp_seq);
	    salt->ack[salt->np] = ntohl(tcp->tcp_ack);	
	    salt->np++;
	} 
    }
}

/**
 * \fn void salt_print_json (const struct salt *x1, const struct salt *x2, zfile f)
 * \param x1 pointer to salt structure
 * \param x2 pointer to salt structure
 * \param f output file
 * \return none
 */
void salt_print_json (const struct salt *x1, const struct salt *x2, zfile f) {
    unsigned int i;

#if 0

    if (x1->np) {
        zprintf(f, ",\"oseq\":[");
	for (i=0; i < x1->np; i++) {
	    if (i) {
		zprintf(f, ",");
	    }
	    zprintf(f, "%u", x1->seq[i] - x1->seq[0]);
	}
        zprintf(f, "],oack\":[");
	for (i=0; i < x1->np; i++) {
	    if (i) {
		zprintf(f, ",");
	    }
	    zprintf(f, "%u", x1->ack[i] - x1->ack[0]);
	}
        zprintf(f, "]");
    }
    if (x2 && x2->np) {
        zprintf(f, ",\"iseq\":[");
	for (i=0; i < x2->np; i++) {
	    if (i) {
		zprintf(f, ",");
	    }
	    zprintf(f, "%u", x2->seq[i] - x2->seq[0]);
	}
        zprintf(f, "],iack\":[");
	for (i=0; i < x2->np; i++) {
	    if (i) {
		zprintf(f, ",");
	    }
	    zprintf(f, "%u", x2->ack[i] - x2->ack[0]);
	}
        zprintf(f, "]");
    }

#else 
    
    if (x1->np) {
        zprintf(f, ",\"oseq\":[");
	for (i=0; i < x1->np; i++) {
	    if (i) {
		zprintf(f, ",%u", x1->seq[i] - x1->seq[i-1]);
	    } else {
		zprintf(f, "%u", x1->seq[i]);
	    }
	}
        zprintf(f, "],oack\":[");
	for (i=0; i < x1->np; i++) {
	    if (i) {
		zprintf(f, ",%u", x1->ack[i] - x1->ack[i-1]);
	    } else {
		zprintf(f, "%u", x1->ack[i]);
	    }
	}
        zprintf(f, "]");
    }
    if (x2 && x2->np) {
        zprintf(f, ",\"iseq\":[");
	for (i=0; i < x2->np; i++) {
	    if (i) {
		zprintf(f, ",%u", x2->seq[i] - x2->seq[i-1]);
	    } else {
		zprintf(f, "%u", x2->seq[i]);
	    }
	}
        zprintf(f, "],iack\":[");
	for (i=0; i < x2->np; i++) {
	    if (i) {
		zprintf(f, ",%u", x2->ack[i] - x2->ack[i-1]);
	    } else {
		zprintf(f, "%u", x2->ack[i]);
	    }
	}
        zprintf(f, "]");
    }

#endif

}

/**
 * \brief Delete the memory of SALT struct.
 *
 * \param salt_handle contains salt structure to delete
 *
 * \return none
 */
void salt_delete (struct salt **salt_handle) { 
    struct salt *salt = *salt_handle;

    if (salt == NULL) {
        return;
    }

    /* Free the memory and set to NULL */
    free(salt);
    *salt_handle = NULL;
}

/**
 * \fn void salt_unit_test ()
 * \param none
 * \return none
 */
void salt_unit_test () {
    
    /* no unit test at this time */

} 

