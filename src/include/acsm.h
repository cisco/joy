/*
= Multi-Pattern Search Engine =

== DOCUMENT ==

See the main function in acsm.c as an example.

==COPYRIGHT & LICENSE==

This code is published under the BSD license.

Copyright (C) 2011 by Weibin Yao <yaoweibin@gmail.com>.

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

*   Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

*   Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */
#ifndef _ACSM_H_
#define _ACSM_H_

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
//#include <string.h>
#include "safe_lib.h"
#include <stddef.h>

#ifdef WIN32
#include "win_types.h"
#endif

#define ASCIITABLE_SIZE    (256)     

#define PATTERN_MAXLEN   (1024) 

#define ACSM_FAIL_STATE  (-1)     


typedef struct acsm_queue_s {
    struct acsm_queue_s  *prev;
    struct acsm_queue_s  *next;
} acsm_queue_t;

typedef struct {
    int          state;
    acsm_queue_t queue;
} acsm_state_queue_t;


typedef struct acsm_pattern_s {
    u_char        *string;
    size_t         len;

    struct acsm_pattern_s *next;
} acsm_pattern_t;


typedef struct {
    int next_state[ASCIITABLE_SIZE];
    int fail_state;

    /* output */
    acsm_pattern_t *match_list;
} acsm_state_node_t;


typedef struct {
    unsigned max_state;
    unsigned num_state;

    acsm_pattern_t    *patterns;
    acsm_state_node_t *state_table;

    void *pool;

    acsm_state_queue_t work_queue;
    acsm_state_queue_t free_queue;

    unsigned no_case;
} acsm_context_t;


#define acsm_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)

#define acsm_strlen(s, mlen)       strnlen_s((const char *) s, mlen)


#define NO_CASE 0x01

acsm_context_t *acsm_alloc(int flag);
void acsm_free(acsm_context_t *ctx);

int acsm_add_pattern(acsm_context_t *ctx, u_char *string, size_t len); 
int acsm_compile(acsm_context_t *ctx);
int acsm_search(acsm_context_t *ctx, u_char *string, size_t len);

#endif /* _ACSM_H_ */
