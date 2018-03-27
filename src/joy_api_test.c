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
 * \file joy_test.c
 *
 * \brief Program to test the Joy API and joylib.a functionality
 * 
 */

#include <stdlib.h>  
#include <stdio.h>
#include <string.h>
#include "joy_api.h"
#include "pcap.h"

/* test program variables */
#define NUM_PACKETS_IN_LOOP 5

int process_pcap_file (char *file_name) {
    int more = 1;
    pcap_t *handle = NULL;
    bpf_u_int32 net = PCAP_NETMASK_UNKNOWN;
    struct bpf_program fp;
    char *filter_exp = "ip or vlan";
    char errbuf[PCAP_ERRBUF_SIZE];

    /* initialize fp structure */
    memset(&fp, 0x00, sizeof(struct bpf_program));

    handle = pcap_open_offline(file_name, errbuf);
    if (handle == NULL) {
        printf("Couldn't open pcap file %s: %s\n", file_name, errbuf);
        return -1;
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "error: could not parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        return -2;
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "error: could not install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        return -3;
    }

    while (more) {
        /* Loop over all packets in capture file */
        more = pcap_dispatch(handle, NUM_PACKETS_IN_LOOP, joy_process_packet, NULL);
        /* Print out expired flows */
        joy_print_flow_data(JOY_EXPIRED_FLOWS);
    }

    /* Cleanup */
    pcap_close(handle);
    return 0;
}

int main (int argc, char **argv)
{
    int rc = 0;
    int ipfix_export = 0;
    struct joy_init init_data;

    /* see if we want to do IPFix exporting
     * simple check, this is an example program only!
     */
    if (argc == 3) {
        /* shell-1> joy_api_test export <pcap filename> */
        ipfix_export = 1;
    }

    /* setup the joy options we want */
    memset(&init_data, 0x00, sizeof(struct joy_init));

    if (ipfix_export) {
        /* this setup is for IPFix exporting */
        init_data.type = 1;                       /* type 1 (SPLT) 2 (SALT) */
        init_data.verbosity = 4;                  /* verbosity 0 (off) - 5 (critical) */
        init_data.idp = 1300;                     /* number of bytes of idp to report */
        init_data.ipfix_host = "72.163.4.161";    /* Host to send IPFix data to */
        init_data.ipfix_port = 4739;              /* port to send IPFix data to */
        init_data.bitmask = (JOY_IPFIX_EXPORT_ON | JOY_TLS_ON | JOY_HTTP_ON);

    } else {
        /* this setup is for general processing */
        init_data.type = 1;                       /* type 1 (SPLT) 2 (SALT) */
        init_data.verbosity = 4;                  /* verbosity 0 (off) - 5 (critical) */
        init_data.bitmask = (JOY_BIDIR_ON | JOY_TLS_ON | JOY_HTTP_ON);
    }

    /* intialize joy */
    rc = joy_initialize(&init_data, NULL, NULL, NULL);
    if (rc != 0) {
        printf(" -= Joy Initialized Failed =-\n");
        return -1;
    }

    /* setup anonymization of subnets */
    joy_anon_subnets("internal.net");

    /* setup anonymization of http usernames */
    joy_anon_http_usernames("anon_http.txt");

    /* setup subnet labels */
    joy_label_subnets("JoyLabTest",JOY_FILE_SUBNET,"internal.net");

    /* print out the configuration */
    if (ipfix_export) {
        joy_print_config(JOY_TERMINAL_FORMAT);
    } else {
        joy_print_config(JOY_JSON_FORMAT);
    }

    /* process the file from the command line */
    if (argc == 2) process_pcap_file(argv[1]);
    else if (argc == 3) process_pcap_file(argv[2]);

    if (ipfix_export) {
        /* export the flows */
        joy_export_flows_ipfix(JOY_ALL_FLOWS);

    } else {
        /* print the flows */
        joy_print_flow_data(JOY_ALL_FLOWS);
    }

    /* cleanup */
    joy_cleanup();

    return 0;
}

