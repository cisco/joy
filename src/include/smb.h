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
 * \file smb.h
 *
 * \brief smb parser interface
 */
#ifndef SMB_H
#define SMB_H

#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "output.h"

#define smb_usage "  smb=1                     gather SMB data\n"

#define smb_filter(record) \
    ((record->key.prot == 6) && (record->app == 445 || (record->key.sp == 445 || record->key.dp == 445)))

#define MAX_SMB_PACKETS 64
#define MAGIC_SMB 32
#define MAX_PARAMETER_SIZE 1024
#define MAX_PRINT_SIZE 2048

/* SMB Structures */

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;

struct NetBIOS{
    uint8_t message_type;
    uint8_t length[3];
}__attribute__((packed));

// Test order, one of the two is wrong

struct flags1{
    uint8_t reply: 1;
    uint8_t obpatch: 1;
    uint8_t oplocks: 1;
    uint8_t canonicalized_paths: 1;
    
    uint8_t case_insensitive: 1;
    uint8_t reserved: 1;
    uint8_t buf_available: 1;
    uint8_t lock_and_read_ok: 1;
}__attribute__((packed));

struct flags2{
    uint8_t long_names_allowed: 1;
    uint8_t eas_supported: 1;
    uint8_t security_signature_supported: 1;
    uint8_t compressed: 1;
    
    uint8_t security_signatures_required: 1;
    uint8_t unused_1: 1;
    uint8_t long_names_used: 1;
    uint8_t unused_2: 3;
    
    uint8_t reparse_path: 1;
    uint8_t extended_security_negociation: 1;
    
    uint8_t dfs: 1;
    uint8_t execute_only: 1;
    uint8_t error_code_type: 1;
    uint8_t unicode: 1;
}__attribute__((packed));

struct SMB_header{
    /* Protocol information */
    uint8_t deliminator;
    uint8_t protocol_id[3];
    
    /* Command and error */
    uint8_t cmd;
    uint8_t error_class;
    uint8_t reserved_1;
    uint16_t error_code;
    
    /* Flags */
    struct flags1 flags1;
    struct flags2 flags2;
    
    /* Identification */
    uint16_t pid_high;
    uint16_t signature[4];
    uint16_t reserved_2;
    uint16_t tid;
    uint16_t pid_low;
    uint16_t uid;
    uint16_t mid;
}__attribute__((packed));

struct SMB_data{
    uint16_t byte_count;
    uint8_t data[MAGIC_SMB];
}__attribute__((packed));

struct SMB_parameter{
    uint8_t word_count;
    uint16_t words[MAX_PARAMETER_SIZE];
}__attribute__((packed));

struct SMB_raw{
    struct NetBIOS netbios_hdr;
    struct SMB_header header;
    uint8_t word_count;
}__attribute__((packed));

struct SMB{
    struct NetBIOS netbios_hdr;
    struct SMB_header header;
    struct SMB_parameter command;
    struct SMB_data data;
}__attribute__((packed));

typedef struct SMB_collection{
    struct SMB packets[MAX_SMB_PACKETS];
    int nb_packets;
} smb_t;


/** initialize http data structure */
void smb_init(smb_t **smb_handle);

/** update http data structure */
void smb_update(smb_t *smb,
                 const struct pcap_pkthdr *header,
                 const void *data,
                 unsigned int data_len,
                 unsigned int report_smb);

/** print out an http data structure */
void  smb_print_json(const smb_t *h1,
                     const smb_t *h2,
                     zfile f);


/** remove an http data structure */
void smb_delete(smb_t **smb_handle);

void smb_unit_test();

#endif /* SMB_H */
