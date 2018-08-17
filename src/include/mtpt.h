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
 * \file mtpt.h
 *
 * \brief mtpt check interface
 */
#ifndef METERPRETER_H
#define METERPRETER_H

#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "output.h"

#define mtpt_usage "  mtpt=1                     report mtpt information\n"

#define mtpt_filter(record) \
    ((record->key.prot == 6)) //&& (record->app == 80 || (record->key.sp == 80 || record->key.dp == 80)))

#define MAX_PACKETS_NUM 2000
#define MAX_HEADERS 20
#define MAX_BUFFER 50
#define MAX_SESSIONS 4

struct mtpt_header_raw{
    unsigned char xor_key[4];
    unsigned char guid[16];
    unsigned char encrypt_flag[4];
    unsigned char length[4];
    unsigned char type[4];
};

struct mtpt_header{
    unsigned char xor_key[4];
    unsigned char guid[16];
    uint32_t encrypted;
    uint32_t length;
    uint32_t type;
};

struct mtpt_session{
    struct mtpt_header headers[MAX_HEADERS];
    int msg_nb;
};

struct mtpt_buffer{
    struct mtpt_header header;
    int bytes_left_to_read;
    int invalid;
};

typedef struct mtpt{
    struct mtpt_session sessions[MAX_SESSIONS];
    struct mtpt_buffer buffer[MAX_BUFFER];
    struct http *http_msg;
    
    int buffer_size;
    int session_nb;
} mtpt_t;

/** initialize http data structure */
void mtpt_init(struct mtpt **mtpt_handle);

/** update http data structure */
void mtpt_update(struct mtpt *mtpt,
                 const struct pcap_pkthdr *header,
                 const void *data,
                 unsigned int data_len,
                 unsigned int report_mtpt);

/** print out an http data structure */
void  mtpt_print_json(struct mtpt *h1,
                      struct mtpt *h2,
                      zfile f);


/** remove an http data structure */
void mtpt_delete(struct mtpt **mtpt_handle);

void mtpt_unit_test();

#endif /* METERPRETER_H */
