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
 * \file http.h
 *
 * \brief http data extraction interface
 */
#ifndef HTTP_H
#define HTTP_H

#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "output.h"

#define http_usage "  http=1                     report http information\n"

#define http_filter(record) \
    ((record->key.prot == 6) && \
     (record->app == 80 || (record->key.sp == 80 || record->key.dp == 80)) \
    )

enum http_line_type {
    HTTP_LINE_INVALID  = 0,
    HTTP_LINE_REQUEST   = 1,
    HTTP_LINE_STATUS    = 2,
};

struct http_header_status_line {
    char *version;
    char *code;
    char *reason;
};

struct http_header_request_line {
    char *method;
    char *uri;
    char *version;
};

struct http_header_element {
    char *name;
    char *value;
};

#define HTTP_MAX_HEADER_ELEMENTS 32

struct http_header {
    union {
        struct http_header_status_line status;
        struct http_header_request_line request;
    } line;
    enum http_line_type line_type;
    struct http_header_element elements[HTTP_MAX_HEADER_ELEMENTS];
    uint8_t num_elements;
};

struct http_message {
    struct http_header header;
    char *body;
    uint32_t body_length;
};

#define HTTP_MAX_MESSAGES 16

/** http data structure */
typedef struct http {
    uint16_t num_messages;
    struct http_message messages[HTTP_MAX_MESSAGES];
} http_t;

/** initialize http data structure */
void http_init(struct http **http_handle);

/** update http data structure */
void http_update(struct http *http,
                 const struct pcap_pkthdr *header,
                 const void *data,
                 unsigned int data_len,
                 unsigned int report_http);

/** print out an http data structure */
void  http_print_json(const struct http *h1,
                      const struct http *h2,
                      zfile f);


/** remove an http data structure */
void http_delete(struct http **http_handle);

void http_unit_test();

#endif /* HTTP_H */
