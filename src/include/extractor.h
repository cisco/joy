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

#ifndef EXTRACTOR_H
#define EXTRACTOR_H

#include <stddef.h>
#include <stdint.h>
#include "output.h"   /* for zfile */

/*
 * An extractor is an object that parses data in one buffer, selects
 * some of the data fields and writes them into a second output
 * buffer.  An extractor maintains a pointers into the data buffer
 * (from where the next byte will be read) and into the output buffer
 * (to where the next copied byte will be written).  Its method
 * functions perform all of the necessary bounds checking to ensure
 * that all of the reading and writing operations respect buffer
 * bounaries.  Some operations advance both the data and output
 * pointers, while others advance just the data pointer or just the
 * output pointer, and others advance neither.  
 * 
 * Some data formats require the parsing of a variable-length data
 * field, whose length is encoded in the data.  To facilitate this, a
 * second 'inner' extractor can be pushed on top of an extractor with
 * the extractor_push function, which initializes the inner extractor
 * to read from the data buffer defined by the variable-length field.
 * After the inner data has been read, a call to extractor_pop updates
 * the outer extractor appropriately.
 * 
 * For protocol fingerprinting, the data copied into the output buffer
 * should contain enough information that it can be parsed without the
 * help of any additional information.
 * 
 */
struct extractor {
    const unsigned char *data;          /* data being parsed/copied  */
    const unsigned char *data_end;      /* end of data buffer        */
    unsigned char *output_start;        /* buffer for output         */
    unsigned char *output;              /* buffer for output         */
    unsigned char *output_end;          /* end of output buffer      */
    unsigned char *tmp_location;        /* location in output stream */
};

enum status {
    status_ok  = 0,
    status_err = 1,
    status_err_no_more_data = 2
};


/*
 * extractor_init initializes an extractor object with a data buffer
 * (holding the data to be parsed) and an output buffer (to which
 * selected data will be copied)
 */
void extractor_init(struct extractor *x,
		    const unsigned char *data,
		    unsigned int data_len,
		    unsigned char *output,
		    unsigned int output_len);


/*
 * extractor_skip advances the data pointer by len bytes, but does not
 * advance the output pointer.  It does not copy any data.
 */
enum status extractor_skip(struct extractor *x,
			   unsigned int len);

/* 
 * extractor_skip_to advances the data pointer to the location
 * provided as input, but does not advance the output pointer.  It
 * does not copy any data.
 */
enum status extractor_skip_to(struct extractor *x,
			      const unsigned char *location);

/*
 * extractor_copy copies data from the data buffer to the output
 * buffer, after prepending the length of that data, and advances both
 * the data pointer and the output pointer.
 */
enum status extractor_copy(struct extractor *x,
			   unsigned int len);


/*
 * extractor_copy_append copies data from the data buffer to the
 * output buffer, after updating the length of the previously copied
 * data, then advances both the data pointer and the output pointer.
 */
enum status extractor_copy_append(struct extractor *x,
				  unsigned int len);

 /*
 * extractor_read_uint reads the next num_bytes from the data buffer,
 * interprets them as an unsigned integer in network byte (big endian)
 * order, and writes the resulting value into the size_t at
 * uint_output.  Neither the data pointer nor output pointer are
 * advanced.
 */
enum status extractor_read_uint(struct extractor *x,
				unsigned int num_bytes,
				size_t *uint_output);


/*
 * extractor_push initializes the extractor inner with the current
 * data and output pointers of extractor outer, with the data buffer
 * restricted to the number of bytes indicated by the length parameter
 */
enum status extractor_push(struct extractor *inner,
			   const struct extractor *outer,
			   size_t length);

/* 
 * extractor_pop removes the inner extractor and updates the outer
 * extractor appropriately.  The length of data copied into the output
 * buffer is encoded into the appropriate location of that buffer;
 * that is, this function ensures that the variable-length field
 * copied into the output buffer is accurate and complete.
 */
void extractor_pop(struct extractor *outer,
		   const struct extractor *inner);

/*
 * extractor_reserve_output reserves num_bytes bytes of the output
 * stream as the location to which data can be written in the future,
 * and remembers that location (by storing it into its tmp_location
 * variable).  This function can be used to encode variable-length
 * data in the output (and it is used by extractor_push and
 * extractor_pop).
 */
enum status extractor_reserve_output(struct extractor *x,
				     size_t num_bytes);

/*
 * extractor_get_data_length returns the number of bytes remaining in
 * the data buffer.  Callers should expect that the value returned may
 * be negative.
 */
ptrdiff_t extractor_get_data_length(struct extractor *x);

/*
 * extractor_get_output_length returns the number of bytes of output
 * that have been written into the output buffer.
 */
ptrdiff_t extractor_get_output_length(const struct extractor *x);

enum status extractor_push_vector_extractor(struct extractor *y,
					    struct extractor *x,
					    size_t bytes_in_length_field);

void extractor_pop_vector_extractor(struct extractor *x,
				    struct extractor *y);

enum status extractor_copy_alt(struct extractor *x,
			       unsigned char *data, /* alternative data source */
			       unsigned int len);

unsigned int match(const unsigned char *data,
		   size_t data_len,
		   const unsigned char *mask,
		   const unsigned char *value,
		   size_t value_len);


unsigned int extractor_match(struct extractor *x,
			     const unsigned char *value,
			     size_t value_len,
			     const unsigned char *mask);

unsigned int uint16_match(uint16_t x,
			  const uint16_t *ulist,
			  unsigned int num);

void zprintf_raw_as_structured_hex(zfile f,
				   const unsigned char *data,
				   unsigned int len);

/*
 * protocol-specific functions
 */

unsigned int extractor_process_tcp(struct extractor *x);

unsigned int extractor_process_tls(struct extractor *x);


#endif /* EXTRACTOR_H */
