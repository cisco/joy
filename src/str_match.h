/*
 * str_match.h
 *
 * declarations for string matching functions
 *
 */
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

#ifndef STR_MATCH_H
#define STR_MATCH_H

#include <string.h>
#include "acsm.h"

#define MATCH_ARRAY_LEN 32

struct matches {
  size_t start[MATCH_ARRAY_LEN];
  size_t stop[MATCH_ARRAY_LEN];
  unsigned int count;
};

#define matches_init(x) (x->count = 0)

void matches_add(struct matches *matches, size_t stop, size_t length);

void matches_print(struct matches *matches, char *text);

typedef acsm_context_t *str_match_ctx;

void str_match_ctx_find_all_longest(const str_match_ctx ctx, 
				    const unsigned char *text, 
				    size_t len, 
				    struct matches *matches);


typedef enum status (*string_transform)(const char *input, 
					unsigned int inlen, 
					char *output,
					unsigned int outlen);

int str_match_ctx_init_from_file(str_match_ctx ctx, const char *filename, string_transform transform);

#define str_match_ctx_alloc() acsm_alloc(NO_CASE)

#define str_match_ctx_free(ctx) acsm_free(ctx)

#endif /* STR_MATCH_H */
