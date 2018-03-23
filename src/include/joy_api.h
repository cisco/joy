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
 * \file joy_api.h
 *
 * \brief Interface to joy library code.
 *
 */

#ifndef JOY_API_H
#define JOY_API_H

#include <stdio.h>
#include <stdlib.h>
#include "pcap.h"

#define JOY_EXPIRED_FLOWS 0
#define JOY_ALL_FLOWS 1
#define MAX_FILENAME_LEN 1024
#define DEFAULT_IPFIX_EXPORT_PORT 4739
#define DEFAULT_IDP_SIZE 1300

/* Bitmask values for turning on various network data features */
#define JOY_BIDIR_ON           0x01
#define JOY_DNS_ON             0x02
#define JOY_SSH_ON             0x04
#define JOY_TLS_ON             0x08
#define JOY_DHCP_ON            0x10
#define JOY_HTTP_ON            0x20
#define JOY_IKE_ON             0x40
#define JOY_PAYLOAD_ON         0x080
#define JOY_EXE_ON             0x100
#define JOY_ZERO_ON            0x200
#define JOY_RETRANS_ON         0x400
#define JOY_BYTE_DIST_ON       0x800
#define JOY_ENTROPY_ON         0x1000
#define JOY_CLASSIFY_ON        0x2000
#define JOY_HEADER_ON          0x4000
#define JOY_PREMPTIVE_TMO_ON   0x8000
#define JOY_IPFIX_EXPORT_ON    0x10000


/* structure used to initialize joy through the API Library */
struct joy_init {
    int type;                    /* type 1 (SPLT) 2 (SALT) */
    int verbosity;               /* verbosity 0 (off) - 5 (critical) */
    int idp;                     /* idp size to report, recommend 1300 */
    char *ipfix_host;            /* ip string of the host to send IPFix data to */
    uint32_t ipfix_port;         /* port to send IPFix to remote on */
    uint32_t bitmask;            /* bitmask representing which features are on */
};

/* prototypes for the API interface */
extern int joy_initialize (struct joy_init *data, char *output_dir,
      char *output_file, char *logfile);

extern int joy_anon_subnets (char *anon_file);

extern int joy_anon_http_usernames (char *anon_http_file);

extern int joy_update_splt_bd_params (char *splt_filename, char *bd_filename);

extern int joy_get_compact_bd (char *filename);

extern int joy_label_subnets (char *label, char* filename);

extern void joy_process_packet (unsigned char *ignore,
    const struct pcap_pkthdr *header, const unsigned char *packet);

extern void joy_print_flow_data (int type);

extern void joy_export_flows_ipfix (int type);

extern void joy_cleanup (void);

#endif /* JOY_API_H */
