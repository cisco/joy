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
 * \file fingerprint.h
 *
 * \brief header file for data fingerprinting
 */

#ifndef FINGERPRINT_H
#define FINGERPRINT_H

#include <stdint.h>

#define MAX_FINGERPRINT_LEN 512
#define MAX_FINGERPRINT_LABELS 64
#define MAX_FINGERPRINT_LABEL_LEN 64
#define MAX_FINGERPRINT_DESCRIPTION 64
#define MAX_FINGERPRINT_DB 100

typedef struct fingerprint {
    char description[MAX_FINGERPRINT_DESCRIPTION];
    char labels[MAX_FINGERPRINT_LABELS][MAX_FINGERPRINT_LABEL_LEN];
    uint8_t label_count;
    uint16_t fingerprint[MAX_FINGERPRINT_LEN];
    uint16_t fingerprint_len;
} fingerprint_t;

typedef struct fingerprint_db {
    fingerprint_t fingerprints[MAX_FINGERPRINT_DB];
    uint16_t fingerprint_count;
} fingerprint_db_t;

int fingerprint_copy(fingerprint_t *dest_fp,
                     fingerprint_t *src_fp);

fingerprint_t *fingerprint_db_match_exact(fingerprint_db_t *db,
                                          fingerprint_t *in_fingerprint);

#endif /* FINGERPRINT_H */

