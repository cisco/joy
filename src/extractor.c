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

#include "extractor.h"

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

    if (x->data + len < x->data_end) {
	x->data = x->data + len;
	return status_ok;
    }
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
	*output = raw_to_uint16(x->data);
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
	*output = tmp; // raw_to_uint16(x->data);
	// fprintf(stderr, "L: %u\tX: %u (decimal) %x (hex)\tY: %x%x\n", num_bytes, tmp, tmp, x->data[0], x->data[1]);
	return status_ok;
    }
    return status_err;
}

enum status extractor_copy(struct extractor *x,
			   unsigned int len) {

    if (x->data + len <= x->data_end && x->output + len <= x->output_end) {
	memcpy(x->output, x->data, len);
	x->data += len;
	x->output += len;
	return status_ok;
    }
    return status_err;
}

enum status extractor_reserve_output(struct extractor *x,
				     size_t length,
				     unsigned char **tmp_location) {

    if (x->output + length < x->output_end) {
	*tmp_location = x->output;
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


enum status extractor_copy_and_degrease(struct extractor *x,
					int len) {
    uint16_t cs;
        
    if (x->data + len <= x->data_end && x->output + len <= x->output_end) {
	
	while (len > 0) {
	    cs = raw_to_uint16(x->data);
	    if (ciphersuite_is_grease(cs)) {
		// fprintf(stderr, "ciphersuite: %hx is GREASE (len: %d)\n", cs, len);
		x->output[0] = 0x0A;
		x->output[1] = 0x0A;
	    } else {
		x->output[0] = x->data[0];
		x->output[1] = x->data[1];
		// fprintf(stderr, "ciphersuite: %hx is NOT GREASE (len: %d)\n", cs, len);
	    }
	    x->output += 2;
	    x->data += 2;
	    len -= 2;
	}
	return status_ok;
    }

    return status_err;
}


enum status extractor_push_vector_extractor(struct extractor *y,
					    struct extractor *x,
					    size_t bytes_in_length_field) {
    size_t tmp_len;
    
    /*  extensions length */
    if (extractor_read_uint(x, bytes_in_length_field, &tmp_len)) {
	return status_err;
    }
    if (extractor_skip(x, bytes_in_length_field)) {
	return status_err;
    }
    if (extractor_reserve_output(x, bytes_in_length_field, &y->tmp_location)) {
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
    encode_uint16(y->tmp_location, extractor_get_output_length(y));
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
