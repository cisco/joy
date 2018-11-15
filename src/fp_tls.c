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
 * \file tls_fp.c
 *
 * \brief TLS fingerprinting data feature module that uses the C
 * preprocessor generic programming interface defined in feature.h.
 *
 */

#include <stdio.h>  
#include <stdlib.h>
#include <string.h>    
#include "config.h"
#include "fp_tls.h"
#include "p2f.h"     /* for zprintf_raw_as_hex() */
#include "err.h"
#include "extractor.h"

extern FILE *info;

/* tls fingerprint functions */

#define LEN MAX_FP_LEN

#define ciphersuite_start 44

static void encode_uint16(unsigned char *p, uint16_t x) {
    p[0] = x >> 8;
    p[1] = 0xff & x;
}

static uint16_t raw_to_uint16 (const void *x) {
    uint16_t y;
    const unsigned char *z = x;

    y = z[0];
    y = y << 8;
    y += z[1];
    return y;
}

unsigned int ciphersuite_is_grease(uint16_t cs) {
    switch(cs) {
    case 0x0A0A:
    case 0x1A1A:
    case 0x2A2A:
    case 0x3A3A:
    case 0x4A4A:
    case 0x5A5A:
    case 0x6A6A:
    case 0x7A7A:
    case 0x8A8A:
    case 0x9A9A:
    case 0xAAAA:
    case 0xBABA:
    case 0xCACA:
    case 0xDADA:
    case 0xEAEA:
    case 0xFAFA:
	return 1; // TRUE
    default:
	return 0; // FALSE
    }
    return 0;     // FALSE
}

static void ciphersuite_vector_normalize_grease(void *cs_vector,
						int len) {
    // unsigned int num_ciphersuites;
    uint16_t cs;
    unsigned char *data = cs_vector;
    
    // num_ciphersuites = raw_to_uint16(data)/2;
    //    fprintf(stderr, "num ciphersuites: %hx\n", num_ciphersuites);
    data += 2;
    len -= 2;
    
    while (len > 0) {
	cs = raw_to_uint16(data);
	if (ciphersuite_is_grease(cs)) {
	    // fprintf(stderr, "ciphersuite: %hx is GREASE (len: %d)\n", cs, len);
	    data[0] = 0x0A;
	    data[1] = 0x0A;
	} else {
	    // fprintf(stderr, "ciphersuite: %hx is NOT GREASE (len: %d)\n", cs, len);
	}
	data += 2;
	len -= 2;
    }

}


unsigned int extension_is_static(uint16_t ext_type) {
    switch(ext_type) {
    case 5:         /* status_request                         */
    case 10:        /* supported_groups                       */
    case 11:        /* ec_point_formats                       */
    case 13:        /* signature_algorithms                   */
    case 16:        /* application_layer_protocol_negotiation */
    case 43:        /* supported_versions                     */
    case 45:        /* psk_key_exchange_modes                 */
	return 1;   /* TRUE  */
    default:
	return 0;   /* FALSE */
    }
    return 0;       /* FALSE */     
}

unsigned int extension_needs_degreasing(uint16_t ext_type) {
    switch(ext_type) {
    case 10:        /* supported_groups                       */
    case 11:        /* ec_point_formats                       */
    case 13:        /* signature_algorithms                   */
    case 43:        /* supported_versions                     */
	return 1;   /* TRUE  */
    default:
	return 0;   /* FALSE */
    }
    return 0;       /* FALSE */     
}

#define extension_is_grease(ext_type) ciphersuite_is_grease(ext_type)


#define L_ContentType              1    
#define L_ProtocolVersion          2    
#define L_RecordLength             2    
#define L_HandshakeType            1    
#define L_HandshakeLength          3    
#define L_ProtocolVersion          2    
#define L_Random                  32
#define L_SessionIDLength          1
#define L_CipherSuiteVectorLength  2
#define L_CompressionMethodsLength 1
#define L_ExtensionsVectorLength   2
#define L_ExtensionType            2
#define L_ExtensionLength          2


/*
 * Hex strings for TLS ClientHello (which appear at the start of the
 * TCP Data field):
 * 
 *    16 03 01  *  * 01   v1.0 data
 *    16 03 02  *  * 01   v1.1 data
 *    16 03 03  *  * 01   v1.2 data
 *    ---------------------------------------
 *    ff ff fc 00 00 ff   mask
 *    16 03 00 00 00 01   value = data & mask 
 *    
 */


static unsigned int tls_client_hello_get_fp_new(const unsigned char *data,
					    int len,
					    void *fp) {
    size_t tmp_len;
    struct extractor x, y;
    unsigned char tls_client_hello_mask[] = {
	0xff, 0xff, 0xfc, 0x00, 0x00, 0xff
    };
    unsigned char tls_client_hello_value[] = {
	0x16, 0x03, 0x00, 0x00, 0x00, 0x01
    };

    /* 
     * verify that we are looking at a TLS ClientHello 
     */
    if (match(data,
	      len,
	      tls_client_hello_mask,
	      tls_client_hello_value,
	      sizeof(tls_client_hello_mask)) == 0) {
	return 0;  /* not a clientHello */
    }
    
    extractor_init(&x, data, len, fp, MAX_FP_LEN);

    /*
     * skip over initial fields 
     */
    if (extractor_skip(&x, (L_ContentType +
			    L_ProtocolVersion +
			    L_RecordLength +
			    L_HandshakeType +
			    L_HandshakeLength))) {
	goto bail;
    }
    
    /* 
     * copy clientHello.ProtocolVersion 
     */
    if (extractor_copy(&x, L_ProtocolVersion)) {
	goto bail;
    }
    
    /*
     * skip over Random
     */
    if (extractor_skip(&x, L_Random)) {
	goto bail;
    }
    
    /* skip over SessionID and SessionIDLen */
    if (extractor_read_uint(&x, L_SessionIDLength, &tmp_len)) {
	goto bail;
    }
    if (extractor_skip(&x, tmp_len + L_SessionIDLength)) {
	goto bail;
    }

    /* copy ciphersuite offer vector */
    if (extractor_read_uint(&x, L_CipherSuiteVectorLength, &tmp_len)) {
	goto bail;
    }
    if (extractor_copy_and_degrease(&x, tmp_len + L_CipherSuiteVectorLength)) {
	goto bail;
    }

    /* skip over compression methods */
    if (extractor_read_uint(&x, L_CompressionMethodsLength, &tmp_len)) {
	goto bail;
    }
    if (extractor_skip(&x, tmp_len + L_CompressionMethodsLength)) {
	goto bail;
    }
    
    /*
     * parse extensions vector by pushing a new extractor and then
     * looping over all extensions in its data
     */
    if (extractor_push_vector_extractor(&y, &x, L_ExtensionsVectorLength)) {
	goto bail;
    }    
    while (extractor_get_data_length(&y) > 0) {
	size_t tmp_type;
	
	if (extractor_read_uint(&y, L_ExtensionType, &tmp_type)) {
	    break;
	}
	if (extractor_copy_and_degrease(&y, L_ExtensionType)) {
	    break;
	}
	if (extractor_read_uint(&y, L_ExtensionLength, &tmp_len)) {
	    break;
	}

	// fprintf(stderr, "t: %u\tl: %u\tD: %d\tL: %d\tO: %d\n", tmp_type, tmp_len, y.data_end-y.data, y.output-y.output_start, y.output_end-y.output);

	if (extension_is_static(tmp_type)) {
	    if (extension_needs_degreasing(tmp_type)) {
		if (extractor_copy_and_degrease(&y, tmp_len + L_ExtensionLength)) {
		    break;
		}
	    } else {
		if (extractor_copy(&y, tmp_len + L_ExtensionLength)) {
		    break;
		}		
	    }
	} else {
	    if (extractor_copy(&y, L_ExtensionLength)) {
		break;
	    }
	    if (extractor_skip(&y, tmp_len)) {
		break;
	    }
	}	
    }

    /*
     * we are done parsing extensions, so pop the vector extractor
     */
    extractor_pop_vector_extractor(&x, &y);
    
    return extractor_get_output_length(&x);
    
 bail:
    /*
     * handle packet parsing errors
     */
    fprintf(stderr, "warning: TLS clientHello processing did not fully complete\n");
    return extractor_get_output_length(&x);
}




/**
 * \brief Initialize the memory of fp_tls struct.
 *
 * \param fp_tls_handle contains fp_tls structure to init
 *
 * \return none
 */
__inline void fp_tls_init (struct fp_tls **fp_tls_handle) {
    if (*fp_tls_handle != NULL) {
        fp_tls_delete(fp_tls_handle);
    }

    *fp_tls_handle = calloc(1, sizeof(struct fp_tls));
    if (*fp_tls_handle == NULL) {
        /* Allocation failed */
        joy_log_err("malloc failed");
        return;
    }
}

/**
 * \fn void fp_tls_update (struct fp_tls *fp_tls,
 *                          const struct pcap_pkthdr *header,
                            const void *data,
                            unsigned int len,
                            unsigned int report_fp_tls)
 * \param fp_tls structure to initialize
 * \param header pointer to the pcap packet header
 * \param data data to use for update
 * \param len length of the data
 * \param report_fp_tls flag to determine if we filter fp_tls
 * \return none
 */
void fp_tls_update (struct fp_tls *fp_tls, 
		    const struct pcap_pkthdr *header, 
		    const void *data, 
		    unsigned int len, 
		    unsigned int report_fp_tls) {

    if (report_fp_tls) {
        if (fp_tls->fp_len > 0) {
	    return;
	} else {
	    fp_tls->fp_len = tls_client_hello_get_fp_new(data, len, fp_tls->fp);
	}
    }
}

/**
 * \fn void fp_tls_print_json (const struct fp_tls *x1, const struct fp_tls *x2, zfile f)
 * \param x1 pointer to fp_tls structure
 * \param x2 pointer to fp_tls structure
 * \param f output file
 * \return none
 */
void fp_tls_print_json (const struct fp_tls *x1, const struct fp_tls *x2, zfile f) {

    if (x1->fp_len || 1) {
        zprintf(f, ",\"fp_tls\":");
	zprintf_raw_as_hex(f, x1->fp, x1->fp_len);
    }
    if (x2->fp_len) {
	;
    }

}

/**
 * \brief Delete the memory of fp_tls struct.
 *
 * \param fp_tls_handle contains fp_tls structure to delete
 *
 * \return none
 */
void fp_tls_delete (struct fp_tls **fp_tls_handle) { 
    struct fp_tls *fp_tls = *fp_tls_handle;

    if (fp_tls == NULL) {
        return;
    }

    /* Free the memory and set to NULL */
    free(fp_tls);
    *fp_tls_handle = NULL;
}

/**
 * \fn void fp_tls_unit_test ()
 * \param none
 * \return none
 */
void fp_tls_unit_test () {
    // struct fp_tls *fp_tls = NULL;
    // const struct pcap_pkthdr *header = NULL; 

    /* TBD */
    
} 
