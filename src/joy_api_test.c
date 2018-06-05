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
#include <unistd.h>
#include "pthread.h"
#include "joy_api.h"
#include "pcap.h"

/* test program variables */
#define NUM_PACKETS_IN_LOOP 20

int process_pcap_file (unsigned long index, char *file_name) {
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
        more = pcap_dispatch(handle, NUM_PACKETS_IN_LOOP, joy_process_packet, (unsigned char*)index);
        /* Print out expired flows */
        joy_print_flow_data(index,JOY_EXPIRED_FLOWS);
    }

    /* Cleanup */
    pcap_close(handle);
    return 0;
}

void *thread_main1 (void *file)
{
    sleep(1);
    printf("Thread 1 Starting\n");
    joy_print_config(0, JOY_JSON_FORMAT);
    process_pcap_file(0, file);
    joy_print_flow_data(0, JOY_ALL_FLOWS);
    joy_cleanup(0);
    printf("Thread 1 Finished\n");
    return NULL;
}

void *thread_main2 (void *file)
{
    sleep(1);
    printf("Thread 2 Starting\n");
    joy_print_config(1, JOY_JSON_FORMAT);
    process_pcap_file(1, file);
    joy_print_flow_data(1, JOY_ALL_FLOWS);
    joy_cleanup(1);
    printf("Thread 2 Finished\n");
    return NULL;
}

void *thread_main3 (void *file)
{
    sleep(1);
    printf("Thread 3 Starting\n");
    joy_print_config(2, JOY_JSON_FORMAT);
    process_pcap_file(2, file);
    joy_print_flow_data(2, JOY_ALL_FLOWS);
    joy_cleanup(2);
    printf("Thread 3 Finished\n");
    return NULL;
}

int main (int argc, char **argv)
{
    int rc = 0;
    struct joy_init init_data;
    pthread_t thread1, thread2, thread3;

    /* setup the joy options we want */
    memset(&init_data, 0x00, sizeof(struct joy_init));

   /* this setup is for general processing */
    init_data.type = 1;           /* type 1 (SPLT) 2 (SALT) */
    init_data.verbosity = 4;      /* verbosity 0 (off) - 5 (critical) */
    init_data.max_records = 0;    /* max records in output file, 0 means single output file */
    init_data.contexts = 3;       /* use 3 worker contexts for processing */
    init_data.bitmask = (JOY_BIDIR_ON | JOY_HTTP_ON | JOY_TLS_ON | JOY_EXE_ON);

    /* intialize joy */
    rc = joy_initialize(&init_data, NULL, NULL, NULL);
    if (rc != 0) {
        printf(" -= Joy Initialized Failed =-\n");
        return -1;
    }

    /* setup anonymization of subnets */
    //joy_anon_subnets("internal.net");

    /* setup anonymization of http usernames */
    //joy_anon_http_usernames("anon_http.txt");

    /* setup subnet labels */
    //joy_label_subnets("JoyLabTest",JOY_FILE_SUBNET,"internal.net");

    /* start up thread1 for processing */
    rc = pthread_create(&thread1, NULL, thread_main1, (char*)argv[1]);
    if (rc) {
         printf("error: could not thread1 pthread_create() rc: %d\n", rc);
         return -6;
    }

    /* start up thread2 for processing */
    rc = pthread_create(&thread2, NULL, thread_main2, (char*)argv[2]);
    if (rc) {
         printf("error: could not thread2 pthread_create() rc: %d\n", rc);
         return -6;
    }

    /* start up thread3 for processing */
    rc = pthread_create(&thread3, NULL, thread_main3, (char*)argv[3]);
    if (rc) {
         printf("error: could not thread3 pthread_create() rc: %d\n", rc);
         return -6;
    }

    /* let the threads run */
    sleep(10);
    return 0;
}

