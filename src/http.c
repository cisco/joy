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

/*
 * http.c
 *
 * http data extraction
 */

#include <ctype.h>
#include "http.h"

#define HTTP_LEN 2048

#include <string.h>   /* for memset()            */
#include <stdlib.h>   /* for malloc() and free() */
#include "p2f.h"

/*
 *
 */

unsigned int memcpy_up_to_crlfcrlf(char *dst, const char *src, unsigned int length) {
  unsigned int i;
  unsigned char state = 0;
  
  /*
   * state table
   * 
   * 0 = not in CRLF
   * 1 = found first CR
   * 2 = found first LF
   * 3 = found second CR
   * 4 = found second LF
   */

  for (i=0; i<(length-1); i++) {
    dst[i] = src[i];
    
    /* make string printable*/
    if (!isprint(dst[i])) {  // could add && !isspace(dst[i])
      dst[i] = '.';
    }
    /* avoid JSON confusion */
    if (dst[i] == '"') {
      dst[i] = '.';
    }

    /* advance lexer state  */
    if (src[i] == '\r') {
      if (state == 0) {
	state = 1;
      } else if (state == 2) {
	state = 3;
      }
    } else if (src[i] == '\n') {
      if (state == 1) {
	state = 2;
      } else if (state == 3) {
	state = 4;
      }
    } else {
      state = 0;
    }

    /* return if we have found a CRLFCRLF*/
    if (state == 4) {
      i++;
      break;
    }
  }
  dst[i] = 0;  /* NULL termination */
  
  return i+1;
}

void http_init(struct http_data *data) {
  data->header = NULL;
  data->header_length = 0;
}

void http_update(struct http_data *data,
			const void *http_start, 
			unsigned long bytes_in_msg,
			unsigned int report_http) {
  
  if (report_http && (data->header == NULL)) {
    unsigned int len = bytes_in_msg < HTTP_LEN ? bytes_in_msg : HTTP_LEN;
    /*
     * note: we leave room for null termination in the data buffer
     */

    data->header = malloc(len);
    if (data->header == NULL) {
      return; 
    }
    data->header_length = memcpy_up_to_crlfcrlf(data->header, http_start, len);
  }

} 

void http_printf(const struct http_data *data, char *string, FILE *f) {

  if (data->header && data->header_length && (data->header_length < HTTP_LEN)) {
    fprintf(f, ",\n\t\t\t\"%s:\": \"%s\"", string, data->header);
  }
}

void http_delete(struct http_data *data) {
  free(data->header);
}
