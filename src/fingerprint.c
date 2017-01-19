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
 * \file fingerprint.c
 *
 * \brief contains the functionality for data fingerprinting
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "fingerprint.h"

int fingerprint_copy(fingerprint_t *dest_fp,
                     fingerprint_t *src_fp) {

    if (dest_fp == NULL) {
        fprintf(stderr, "api-error: dest_fp is null");
        return 1;
    }

    if (src_fp == NULL) {
        fprintf(stderr, "api-error: src_fp is null");
        return 1;
    }

    memcpy(dest_fp, src_fp, sizeof(fingerprint_t));

    return 0;
}

/*
 * @brief Find an exact fingerprint match in the database.
 *
 * Use the \p in_fingerprint to search the known fingerprint database for a match.
 * If match is found then return a pointer to the database fingerprint that was
 * matched successfully.
 * If a match is found then copy the known data, such as library versions, into the
 * label fields of \p in_fingerprint.
 *
 * @param db Database of known fingerprints that will be searched.
 * @param in_fingerprint The input fingerprint.
 *
 * return Database fingerprint if match, NULL otherwise
 */
fingerprint_t *fingerprint_db_match_exact(fingerprint_db_t *db,
                                          fingerprint_t *in_fingerprint) {
    fingerprint_t *fp_match = NULL;
    uint16_t db_count = 0;
    size_t i = 0;
    int match = -1;

    if (db == NULL) {
      return NULL;
    }

    db_count = db->fingerprint_count;

    /* Iterate through the db->fingerprints */
    for (i = 0; i < db_count; i++) {
        /* Optimize by comparing fingerprint length first */
        if (in_fingerprint->fingerprint_len == db->fingerprints[i].fingerprint_len) {
            /* Compare the memory of the 2 fingerprints */
            match = memcmp(in_fingerprint->fingerprint, db->fingerprints[i].fingerprint,
                           in_fingerprint->fingerprint_len);
            if (match == 0) {
                fp_match = &db->fingerprints[i];
                return fp_match;
            }
        }
    }

    /* No fingerprints were matched */
    return NULL;
}
