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

#include <string.h>   /* for memcpy()   */
#include <stdio.h>

#include "extractor.h"
#include "output.h"

/* utility functions */

static void encode_uint16(unsigned char *p, uint16_t x) {
    p[0] = x >> 8;
    p[1] = 0xff & x;
}

static uint16_t decode_uint16 (const void *x) {
    uint16_t y;
    const unsigned char *z = x;

    y = z[0];
    y = y << 8;
    y += z[1];
    return y;
}

/* extractor methods */

void extractor_init(struct extractor *x,
		    const unsigned char *data,
		    unsigned int data_len,
		    unsigned char *output,
		    unsigned int output_len) {
    x->data = data;
    x->data_end = data + data_len;
    x->output = output;
    x->output_start = output;
    x->output_end = output + output_len;
    x->tmp_location = NULL;
    // fprintf(stderr, "note in %s: initialized with %td bytes\n", __func__, x->data_end - x->data);
}

enum status extractor_push(struct extractor *y,
			   const struct extractor *x,
			   size_t length) {
    
    if (x->data + length <= x->data_end) {
	y->data         = x->data;
	y->data_end     = x->data + length;
	y->output       = x->output;
	y->output_start = x->output;
	y->output_end   = x->output_end;
	return status_ok;
    }
    return status_err;
}

void extractor_pop(struct extractor *x,
		   const struct extractor *y) {
    x->data   = y->data;
    x->output = y->output;
}

enum status extractor_skip(struct extractor *x,
			   unsigned int len) {

    if (x->data + len <= x->data_end) {
	x->data = x->data + len;
	return status_ok;
    }
    // fprintf(stderr, "error in %s: tried to skip %u, only %td remaining\n", __func__, len, x->data_end - x->data);
    return status_err;
}

enum status extractor_skip_to(struct extractor *x,
			      const unsigned char *location) {

    if (location <= x->data_end) {
	x->data = location;
	return status_ok;
    }
    // fprintf(stderr, "error in %s: tried to skip %td, only %td remaining\n", __func__, location - x->data_end, x->data_end - x->data);
    return status_err;
}

enum status extractor_read_u8(struct extractor *x,
			      unsigned char *output) {

    if (x->data + 1 < x->data_end) {
	*output = *x->data;
	return status_ok;
    }
    return status_err;
}

enum status extractor_read_u16(struct extractor *x,
			      uint16_t *output) {

    if (x->data + sizeof(uint16_t) <= x->data_end) {
	*output = decode_uint16(x->data);
	return status_ok;
    }
    return status_err;
}

enum status extractor_read_uint(struct extractor *x,
				unsigned int num_bytes,
				size_t *output) {
    size_t tmp = 0;
    const unsigned char *c;

    if (x->data + num_bytes <= x->data_end) {
	for (c = x->data; c < x->data + num_bytes; c++) {
	    tmp = (tmp << 8) + *c;
	}	
	*output = tmp; 
	// fprintf(stderr, "L: %u\tX: %u (decimal) %x (hex)\tY: %x%x\n", num_bytes, tmp, tmp, x->data[0], x->data[1]);
	return status_ok;
    }
    return status_err;
}

enum status extractor_copy(struct extractor *x,
			   unsigned int len) {

    if (x->data + len <= x->data_end && x->output + len + 2 <= x->output_end) {
	x->tmp_location = x->output;
	encode_uint16(x->output, len);
	x->output += 2;
	memcpy(x->output, x->data, len);
	x->data += len;
	x->output += len;
	return status_ok;
    }
    return status_err;
}

enum status extractor_copy_append(struct extractor *x,
				  unsigned int len) {
    uint16_t tmp;
    
    if (x->data + len <= x->data_end && x->output + len <= x->output_end) {
	/*
	 * add len into the previously encoded length in the output buffer
	 */
	tmp = decode_uint16(x->tmp_location);
	encode_uint16(x->tmp_location, tmp + len);
	
	/*
	 * copy data to output buffer
	 */
	memcpy(x->output, x->data, len);
	x->data += len;
	x->output += len;
	return status_ok;
    }
    return status_err;
}

#define PARENT_NODE_INDICATOR 0x8000
#define LENGTH_MASK           0x7fff

void zprintf_element_as_structured_hex(zfile f,
				       const unsigned char *data,
				       unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;
    uint16_t tmp, element_len, parent_node;

    while (x < end) {

	/* 
	 * decode length from data stream
	 */
	if (x + sizeof(uint16_t) > end) {
	    return;
	}
	tmp = decode_uint16(x);

	parent_node = tmp & PARENT_NODE_INDICATOR;
	element_len = tmp & LENGTH_MASK;

	if (x + element_len > end) {
	    return;
	}
	x += sizeof(uint16_t);

	/*
	 * print out parenthesized data
	 */
	zprintf(f, "(");
	if (parent_node) {
	    /* 
	     * print out data element as a list of elements
	     */
	    zprintf_element_as_structured_hex(f, x, element_len);
	    x += element_len;
	    
	} else {
	    /* 
	     * print out data element as a raw octet string
	     */
	    while (element_len-- > 0) {
		zprintf(f, "%02x", *x++);
	    }
	}
	zprintf(f, ")");
    }

}

void zprintf_raw_as_structured_hex (zfile f,
				    const unsigned char *data,
				    unsigned int len) {
    
    zprintf(f, "\"");   /* quotes needed for JSON */
    zprintf_element_as_structured_hex(f, data, len);
    zprintf(f, "\"");
}

enum status extractor_copy_alt(struct extractor *x,
			       unsigned char *data, /* alternative data source */
			       unsigned int len) {
    return status_ok;
}

enum status extractor_reserve_output(struct extractor *x,
				     size_t length) {

    if (x->output + length < x->output_end) {
	x->tmp_location = x->output;
	x->output += length;
	return status_ok;
    }
    return status_err;
}

ptrdiff_t extractor_get_data_length(struct extractor *x) {
    return x->data_end - x->data;
}

ptrdiff_t extractor_get_output_length(const struct extractor *x) {
    return x->output - x->output_start;
}

enum status extractor_push_vector_extractor(struct extractor *y,
					    struct extractor *x,
					    size_t bytes_in_length_field) {
    size_t tmp_len;
    
    /*  extensions length */
    if (extractor_read_uint(x, bytes_in_length_field, &tmp_len)) {
	return status_err;
    }
    // fprintf(stderr, "extensions length: %zu\n", tmp_len);
    if (extractor_skip(x, bytes_in_length_field)) {
	return status_err;
    }
    if (extractor_reserve_output(x, bytes_in_length_field)) {
	return status_err;
    }
    if (extractor_push(y, x, tmp_len)) {
	return status_err;
    }
    return status_ok;
}

void extractor_pop_vector_extractor(struct extractor *x,
				    struct extractor *y) {

     /* 
     * encode normalized extensions length into reserved location 
     */
    //fprintf(stderr, "XXX: %x\n", extractor_get_output_length(y) | PARENT_NODE_INDICATOR);
    encode_uint16(x->tmp_location, extractor_get_output_length(y) | PARENT_NODE_INDICATOR);
    extractor_pop(x, y);
}

unsigned int match(const unsigned char *data,
		   size_t data_len,
		   const unsigned char *mask,
		   const unsigned char *value,
		   size_t value_len) {
    int i;

    if (data_len >= value_len) {
	for (i = 0; i < value_len; i++) {
	    if ((data[i] & mask[i]) != value[i]) {
		return 0;
	    }
	}
	return 1;
    }    
    return 0;
}

unsigned int extractor_match(struct extractor *x,
			     const unsigned char *value,
			     size_t value_len,
			     const unsigned char *mask) {
    int i;

    if (x->data + value_len <= x->data_end) {
	if (mask) {
	    for (i = 0; i < value_len; i++) {
		if ((x->data[i] & mask[i]) != value[i]) {
		    return 0;
		}
	    }
	} else { /* mask == NULL */
	    for (i = 0; i < value_len; i++) {
		if (x->data[i] != value[i]) {
		    return 0;
		}	    
	    }
	}
	x->data += value_len;
	return 1;
    }    
    return 0;
}

unsigned int uint16_match(uint16_t x,
			  const uint16_t *ulist,
			  unsigned int num) {
    const uint16_t *ulist_end = ulist + num;

    while (ulist < ulist_end) {
	if (x == *ulist++) {
	    return 1;
	}
    }
    return 0;
}

void fprintf_hex(const unsigned char *data, size_t len) {
    while (len-- > 0) {
	fprintf(stderr, "%02hhx", *data++);
    }
    fprintf(stderr, "\n");
}

/* 
 * TCP fingerprinting
 *
 * The following data are extracted from the SYN packet: the ordered
 * list of all TCP option kinds, with repeated values allowed in the
 * list.  The length and data for the MSS and WS TCP options are
 * included, but are not for other option kinds.
 */


/*
 * TCP macros
 *
 * The following macros indicate the lengths of each field in the TCP
 * header, in the same order of appearance as on the wire.  The needed
 * option kinds (EOL, NOP, MSS, and WS) are defined, as is the value
 * of the Flag field for a SYN pakcet (TCP_SYN).
 */

#define L_src_port      2
#define L_dst_port      2
#define L_tcp_seq       4
#define L_tcp_ack       4
#define L_tcp_offrsv    1
#define L_tcp_flags     1
#define L_tcp_win       2
#define L_tcp_csm       2
#define L_tcp_urp       2
#define L_option_kind   1
#define L_option_length 1

#define TCP_OPT_EOL     0
#define TCP_OPT_NOP     1
#define TCP_OPT_MSS     2
#define TCP_OPT_WS      3

#define TCP_SYN      0x02

/*
 * The function extractor_process_tcp processes a TCP packet.  The
 * extractor MUST have previously been initialized with its data
 * pointer set to the initial octet of a TCP header.
 */

unsigned int extractor_process_tcp(struct extractor *x) {
    size_t flags, offrsv;
    
    // fprintf(stderr, "processing packet (len %d)\n", len);
    // fprintf_hex(data, len);
    
    if (extractor_skip(x, L_src_port + L_dst_port + L_tcp_seq + L_tcp_ack)) {
	goto bail;
    }
    if (extractor_read_uint(x, L_tcp_offrsv, &offrsv)) {
	goto bail;
    }
    if (extractor_skip(x, L_tcp_offrsv)) {
	goto bail;
    }
    if (extractor_read_uint(x, L_tcp_flags, &flags)) {
	goto bail;
    }
    if (flags != TCP_SYN) {
	/*
	 * note: we could process the TCP Data payload here, but for
	 * now we leave that to another function
	 */
	return 0;	
    }   
    if (extractor_skip(x, L_tcp_flags + L_tcp_win + L_tcp_csm + L_tcp_urp)) {
	goto bail;
    }

    while (extractor_get_data_length(x) > 0) {
	size_t option_kind, option_length;
	
	if (extractor_read_uint(x, L_option_kind, &option_kind)) {
	    goto bail;
	}
	if (extractor_copy(x, L_option_kind)) {
	    goto bail;
	}

	if (option_kind == TCP_OPT_EOL || option_kind == TCP_OPT_NOP) {

	    /* note: no option_length field is present for these kinds */
	    ;
	    
	} else {
	    if (extractor_read_uint(x, L_option_length, &option_length)) {
		goto bail;
	    }
	    if (option_kind == TCP_OPT_MSS || option_kind == TCP_OPT_WS) {
		
		if (extractor_copy_append(x, option_length - L_option_kind)) {
		    goto bail;
		}
	    } else {
		unsigned char zero[] = { 0x00 };
		
		if (extractor_copy_alt(x, zero, L_option_length)) {
		    goto bail;
		}
		if (extractor_skip(x, option_length - L_option_kind)) {
		    goto bail;
		}
	    }
	}
    }    

    return extractor_get_output_length(x);
    
 bail:
    /*
     * handle packet parsing errors
     */
    // fprintf(stderr, "warning: TCP processing did not fully complete\n");
    return extractor_get_output_length(x);
}


/*
 * TLS fingerprint extraction
 */

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

#define num_static_extension_types 7

/*
 * The function extractor_process_tls processes a TLS packet.  The
 * extractor MUST have previously been initialized with its data
 * pointer set to the initial octet of the TCP header of the TLS
 * packet.
 */
unsigned int extractor_process_tls(struct extractor *x) {
    size_t tmp_len, offrsv;
    struct extractor y;
    unsigned char tls_client_hello_mask[] = {
	0xff, 0xff, 0xfc, 0x00, 0x00, 0xff
    };
    unsigned char tls_client_hello_value[] = {
	0x16, 0x03, 0x00, 0x00, 0x00, 0x01
    };
    uint16_t static_extension_types[num_static_extension_types] = {
	5,         /* status_request                         */
	10,        /* supported_groups                       */
	11,        /* ec_point_formats                       */
	13,        /* signature_algorithms                   */
	16,        /* application_layer_protocol_negotiation */
	43,        /* supported_versions                     */
	45         /* psk_key_exchange_modes                 */
    };
    const unsigned char *data = x->data;

    /* skip over TCP header */
    
    if (extractor_skip(x, L_src_port + L_dst_port + L_tcp_seq + L_tcp_ack)) {
	goto bail;
    }
    if (extractor_read_uint(x, L_tcp_offrsv, &offrsv)) {
	goto bail;
    }
    if (extractor_skip(x, L_tcp_offrsv)) {
	goto bail;
    }

    /* compute offset to the TCP Data field */
    if (extractor_skip_to(x, data + ((offrsv >> 4) * 4))) {
	goto bail;
    }
    
    /* 
     * verify that we are looking at a TLS ClientHello 
     */
    if (!extractor_match(x,
			tls_client_hello_value,
			L_ContentType +	L_ProtocolVersion + L_RecordLength + L_HandshakeType,
			tls_client_hello_mask)) {
	return 0; /* not a clientHello */
    }
    
    /*
     * skip over initial fields 
     */
    if (extractor_skip(x, L_HandshakeLength)) {
	goto bail;
    }
    
    /* 
     * copy clientHello.ProtocolVersion 
     */
    if (extractor_copy(x, L_ProtocolVersion)) {
	goto bail;
    }
    
    /*
     * skip over Random
     */
    if (extractor_skip(x, L_Random)) {
	goto bail;
    }
    
    /* skip over SessionID and SessionIDLen */
    if (extractor_read_uint(x, L_SessionIDLength, &tmp_len)) {
	goto bail;
    }
    if (extractor_skip(x, tmp_len + L_SessionIDLength)) {
	goto bail;
    }

    /* copy ciphersuite offer vector */
    if (extractor_read_uint(x, L_CipherSuiteVectorLength, &tmp_len)) {
	goto bail;
    }
    if (extractor_skip(x, L_CipherSuiteVectorLength)) {
	goto bail;
    }    
    if (extractor_copy(x, tmp_len)) {
	goto bail;
    }

    /* skip over compression methods */
    if (extractor_read_uint(x, L_CompressionMethodsLength, &tmp_len)) {
	goto bail;
    }
    if (extractor_skip(x, tmp_len + L_CompressionMethodsLength)) {
	goto bail;
    }
    
    /*
     * parse extensions vector by pushing a new extractor and then
     * looping over all extensions in its data
     */
    if (extractor_push_vector_extractor(&y, x, L_ExtensionsVectorLength)) {
	goto bail;
    }    
    while (extractor_get_data_length(&y) > 0) {
	size_t tmp_type;
	
	if (extractor_read_uint(&y, L_ExtensionType, &tmp_type)) {
	    break;
	}
	if (extractor_copy(&y, L_ExtensionType)) {
	    break;
	}
	if (extractor_read_uint(&y, L_ExtensionLength, &tmp_len)) {
	    break;
	}

	//fprintf(stderr, "t: %zu\tl: %zu\tD: %d\tL: %d\n", tmp_type, tmp_len, y.data_end-y.data+2, y.output-y.output_start-2);

	if (uint16_match(tmp_type, static_extension_types, num_static_extension_types)) { 
	    if (extractor_copy_append(&y, tmp_len + L_ExtensionLength)) {
		break;
	    }		
	} else {
 	    unsigned char zero[L_ExtensionLength] = { 0x00, 0x00 };
	    
	    if (extractor_copy_alt(&y, zero, L_ExtensionLength)) {
	       break;
	    }
	    if (extractor_skip(&y, tmp_len + L_ExtensionLength)) {
		break;
	    }
	}	
    }

    /*
     * we are done parsing extensions, so pop the vector extractor
     */
    extractor_pop_vector_extractor(x, &y);
    
    return extractor_get_output_length(x);
    
 bail:
    /*
     * handle packet parsing errors
     */
    // fprintf(stderr, "warning: TLS clientHello processing did not fully complete\n");
    return extractor_get_output_length(x);
    
}
