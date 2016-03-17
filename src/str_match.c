/*
 * str_match.c
 *
 * string matching functions
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

#include "str_match.h"

void matches_add(struct matches *matches, size_t stop, size_t length) {
  int i;
  size_t start = stop - length + 1;

  if (matches->count >= MATCH_ARRAY_LEN) {
    return;
  }
  if (matches->count == 0) {
    matches->start[0] = start;
    matches->stop[0] = stop;
    matches->count = 1;

  } else {
    
    /* check for overlaps with previous matches */
    for (i=matches->count; i > 0; i--) {
      if (start > matches->stop[i-1]) {
	break;
      }
      // printf("found overlap with match %d\n", i-1);
    }
    if (matches->count == i) {
      matches->count++;
    } else {
      matches->count = i + 1;
    }
    matches->start[i] = start;
    matches->stop[i] = stop;
  }
  // printf("adding match with start[%d]: %zu\tstop[%d]: %zu\tcount: %u\n", 
  //	 i, start, i, stop, matches->count);
}

void matches_print(struct matches *matches, char *text) {
  unsigned int i;
  char tmp[1024];

  for (i=0; i < matches->count; i++) {
    size_t len = matches->stop[i] - matches->start[i] + 1;
    if (len > 1024) {
      return;
    }
    memcpy(tmp, text + matches->start[i], len);
    tmp[len] = 0;
    printf("match %d: %s\n", i, tmp);
  }
}

void str_match_ctx_find_all_longest(const str_match_ctx ctx, const unsigned char *text, size_t len, struct matches *matches) {
  static int state = 0;
  const unsigned char *p;
  const unsigned char *last;
  unsigned char ch;
  
  matches_init(matches);
  
  p = text;
  last = text + len;
  
  while (p < last) {
    ch = ctx->no_case ? acsm_tolower((*p)) : (*p);
    
    while (ctx->state_table[state].next_state[ch] == ACSM_FAIL_STATE) {
      state = ctx->state_table[state].fail_state;
    }
    
    state = ctx->state_table[state].next_state[ch];
    
    if (ctx->state_table[state].match_list) {      
      acsm_pattern_t *pattern = ctx->state_table[state].match_list;

      do {
	// printf("\nMATCH: %s\n", pattern->string);
	matches_add(matches, p - text, pattern->len);

      } while ((pattern = pattern->next) != NULL);

    }
    
    p++;
  }
  
  return;
}


/*
 * file loading functions
 */

void strip_newline(char *line) {
  while (*line != 0) {
    if (*line == '\n' || *line == '\r' || *line == ' ') {
      *line = 0;
      break;
    }
    line++;
  }
}

int str_match_ctx_init_from_file(str_match_ctx ctx, char *filename) {
  // acsm_pattern_t *pattern;
  FILE *fp;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  fp = fopen(filename, "r");
  if (fp == NULL) {
    fprintf(stderr, "error: count not open file %s\n", filename);
    return -1;
  }

  while ((read = getline(&line, &len, fp)) != -1) {
    strip_newline(line);
    // printf("adding pattern \"%s\"\n", line);
    if (acsm_add_pattern(ctx, (unsigned char *)line, acsm_strlen(line)) != 0) {
      fprintf(stderr, "acsm_add_pattern() with pattern \"%s\" error.\n", line);
      return -1;
    }  
  }
  free(line);
  
  if (acsm_compile(ctx) != 0) {
    fprintf(stderr, "acsm_compile() error.\n");
    return -1;
  }

  return 0;
}
