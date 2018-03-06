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
 * \file proto_identify.c
 *
 * \brief Protocol identification (source)
 *
 */

#include <stdlib.h>
#include <string.h>

#include "proto_identify.h"

struct protocol_identifier {
    char *str;
    uint8_t str_len;
};

#define MAX_PI_COUNT 10
struct pi_container {
    uint16_t app_port;
    uint8_t count;
    struct protocol_identifier pi[MAX_PI_COUNT];
};

#define MAX_PI_DB 16
struct pi_db {
    uint16_t count;
    struct pi_container containers[MAX_PI_DB];
};

static struct pi_db pi_db;
static uint8_t pi_db_initialized = 0;

static void pi_db_init(void) {
    struct pi_container *container = NULL;

    memset(&pi_db, 0, sizeof(struct pi_db));

    /*
     * Assign TLS
     */
    container = &pi_db.containers[pi_db.count];
    container->app_port = 443;

    container->pi[container->count].str = "\x16\x03\x00\x00";
    container->pi[container->count].str_len = 4;
    container->count++;

    container->pi[container->count].str = "\x16\x03\x01\x01";
    container->pi[container->count].str_len = 4;
    container->count++;

    /* Increment the count of database entries */
    pi_db.count++;

    /*
     * Assign HTTP
     */
    container = &pi_db.containers[pi_db.count];
    container->app_port = 80;

    container->pi[container->count].str = "\x47\x45\x54\x20";
    container->pi[container->count].str_len = 4;
    container->count++;

    container->pi[container->count].str = "\x50\x4f\x53\x54\x20\x2f";
    container->pi[container->count].str_len = 6;
    container->count++;

    /* Increment the count of database entries */
    pi_db.count++;

    /* Database is ready */
    pi_db_initialized = 1;
}

uint16_t identify_tcp_protocol(const char *tcp_data, unsigned int len) {
    int k, m = 0;

    if (len == 0) {
        return 0;
    }

    /* Load the database if not already done so */
    if (! pi_db_initialized) {
        pi_db_init();
    }

    /* Iterate over all the protocol containers */
    for (k = 0; k < pi_db.count; k++) {
        struct pi_container *container = &pi_db.containers[k];

        /* Try to match the protocol strings */
        for (m = 0; m < container->count; m++) {
            struct protocol_identifier *pi = &container->pi[m];

            if (memcmp(tcp_data, pi->str, pi->str_len) == 0) {
                return container->app_port;
            }
        }
    }

    return 0;
}

