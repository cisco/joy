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
#ifdef HAVE_CONFIG_H
#include "joy_config.h"
#endif
#include <stdlib.h>  
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "pthread.h"
#include "joy_api.h"

/* test program variables */
#define NUM_PACKETS_IN_LOOP 20

int proc_pcap_file (unsigned long index, char *file_name) {
    int more = 1;
    pcap_t *handle = NULL;
    bpf_u_int32 net = PCAP_NETMASK_UNKNOWN;
    struct bpf_program fp;
    char filter_exp[PCAP_ERRBUF_SIZE];
    char errbuf[PCAP_ERRBUF_SIZE];

    /* initialize fp structure */
    memset(&fp, 0x00, sizeof(struct bpf_program));
    strcpy(filter_exp,"ip or vlan");

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
        more = pcap_dispatch(handle, NUM_PACKETS_IN_LOOP, joy_libpcap_process_packet, (unsigned char*)index);
        /* Print out expired flows */
        //joy_print_flow_data(index,JOY_EXPIRED_FLOWS);
    }

    /* Cleanup */
    pcap_close(handle);
    return 0;
}

void my_idp_callback(void *curr_rec, unsigned int data_len, unsigned char *data) {
    flow_record_t *rec = (flow_record_t *)curr_rec;

    if ((data_len == 0) && (data == NULL)) {
        printf("IDP len=%d\n",rec->idp_len);
    }
}

void my_tls_callback(void *curr_rec, unsigned int data_len, unsigned char *data) {
    flow_record_t *rec = (flow_record_t *)curr_rec;

    if ((data_len == 0) && (data == NULL)) {
        if (rec->tls != NULL) {
           printf("tls version=%d\n",rec->tls->version);
        } else {
           printf("tls version=unknown\n");
        }
    }
}

void my_splt_callback(void *curr_rec, unsigned int data_len, unsigned char *data) {
    unsigned int i = 0;
    unsigned int splt_recs = 0;
    short *formatted_data = (short*)data;

    if ((curr_rec == NULL) || (formatted_data == NULL)) return;

    splt_recs = data_len / 4;
    if (splt_recs > 10) {
        printf("Incorrect SPLT Data Length (%d)\n",data_len);
        return;
    }

    printf("SPLT REC(%d) LENGTHS: ",splt_recs);
    for (i=0; i<splt_recs; ++i) {
        if (i == (splt_recs-1))
            printf("{%d}", *(formatted_data+i));
        else
            printf("{%d}, ", *(formatted_data+i));
    }
    printf("\n");
    printf("SPLT REC(%d) TIMES: ",splt_recs);
    for (i=0; i<splt_recs; ++i) {
        if (i == (splt_recs-1))
            printf("{%d}", *(formatted_data+splt_recs+i));
        else
            printf("{%d}, ", *(formatted_data+splt_recs+i));
    }
    printf("\n");
}

void my_salt_callback(void *curr_rec, unsigned int data_len, unsigned char *data) {
    unsigned int i = 0;
    unsigned int salt_recs = 0;
    short *formatted_data = (short*)data;

    if ((curr_rec == NULL) || (formatted_data == NULL)) return;

    salt_recs = data_len / 4;
    if (salt_recs > 10) {
        printf("Incorrect SALT Data Length (%d)\n",data_len);
        return;
    }

    printf("SALT REC(%d) LENGTHS: ",salt_recs);
    for (i=0; i<salt_recs; ++i) {
        if (i == (salt_recs-1))
            printf("{%d}", *(formatted_data+i));
        else
            printf("{%d}, ", *(formatted_data+i));
    }
    printf("\n");
    printf("SALT REC(%d) TIMES: ",salt_recs);
    for (i=0; i<salt_recs; ++i) {
        if (i == (salt_recs-1))
            printf("{%d}", *(formatted_data+salt_recs+i));
        else
            printf("{%d}, ", *(formatted_data+salt_recs+i));
    }
    printf("\n");
}

void my_bd_callback(void *curr_rec, unsigned int data_len, unsigned char *data) {
    int i = 0;
    uint16_t *formatted_data = (uint16_t*)data;

    if ((curr_rec == NULL) || (formatted_data == NULL)) return;

    if (data_len != 512) return;

    /* Each ASCII byte value */
    printf("BYTE COUNTS: ");
    for (i=0; i<256; ++i) {
        if (i == 255)
            printf("{%d}", *(formatted_data+i));
        else
            printf("{%d}, ", *(formatted_data+i));
    }
    printf("\n");
}

void *thread_main1 (void *file)
{
    unsigned int recs = 0;

    sleep(1);
    printf("Thread 1 Starting\n");
    joy_print_config(0, JOY_JSON_FORMAT);
    if (file != NULL) {
        proc_pcap_file(0, file);
        joy_idp_external_processing(0, my_idp_callback);
        joy_tls_external_processing(0, my_tls_callback);
        //joy_splt_external_processing(0, JOY_NFV9_EXPORT, 1, my_splt_callback);
        joy_splt_external_processing(0, JOY_IPFIX_EXPORT, 1, my_splt_callback);
        //joy_salt_external_processing(0, JOY_NFV9_EXPORT, 1, my_salt_callback);
        joy_salt_external_processing(0, JOY_IPFIX_EXPORT, 1, my_salt_callback);
        joy_bd_external_processing(0, 1, my_bd_callback);
        recs = joy_purge_old_flow_records(0, 300);
        printf("Thread 1 deleted %d records\n",recs);
        //joy_export_flows_ipfix(0, JOY_ALL_FLOWS);
        joy_print_flow_data(0, JOY_ALL_FLOWS);
        //recs = joy_delete_flow_records(0, JOY_DELETE_ALL);
        //printf("Thread 1 deleted %d records\n",recs);
    } else {
        printf("Thread 1 No File to Process\n");
    }
    joy_context_cleanup(0);
    printf("Thread 1 Finished\n");
    return NULL;
}

void *thread_main2 (void *file)
{
    sleep(1);
    printf("Thread 2 Starting\n");
    joy_print_config(1, JOY_JSON_FORMAT);
    if (file != NULL) {
        proc_pcap_file(1, file);
        joy_print_flow_data(1, JOY_ALL_FLOWS);
    } else {
        printf("Thread 2 No File to Process\n");
    }
    joy_context_cleanup(1);
    printf("Thread 2 Finished\n");
    return NULL;
}

void *thread_main3 (void *file)
{
    sleep(1);
    printf("Thread 3 Starting\n");
    joy_print_config(2, JOY_JSON_FORMAT);
    if (file != NULL) {
        proc_pcap_file(2, file);
        joy_print_flow_data(2, JOY_ALL_FLOWS);
    } else {
        printf("Thread 3 No File to Process\n");
    }
    joy_context_cleanup(2);
    printf("Thread 3 Finished\n");
    return NULL;
}

int main (int argc, char **argv)
{
    int rc = 0;
    joy_init_t init_data;
    pthread_t thread1, thread2, thread3;
    char *file1 = NULL;
    char *file2 = NULL;
    char *file3 = NULL;

    /* setup files */
    if (argc < 2) {
        printf("No files Specified to process\n");
        exit(0);
    } else {
        if (argc == 2) {
            file1 = (char*)argv[1];
            file2 = (char*)NULL;
            file3 = (char*)NULL;
        } else if (argc == 3) {
            file1 = (char*)argv[1];
            file2 = (char*)argv[2];
            file3 = (char*)NULL;
        } else if (argc == 4) {
            file1 = (char*)argv[1];
            file2 = (char*)argv[2];
            file3 = (char*)argv[3];
        }
    }

    /* setup the joy options we want */
    memset(&init_data, 0x00, sizeof(joy_init_t));

   /* this setup is for general processing */
    init_data.verbosity = 4;      /* verbosity 0 (off) - 5 (critical) */
    init_data.max_records = 0;    /* max records in output file, 0 means single output file */
    init_data.num_pkts = 20;      /* report on at most 20 packets */
    init_data.contexts = 3;       /* use 3 worker contexts for processing */
    init_data.idp = 2048;
    init_data.ipfix_host = "72.163.4.161";    /* Host to send IPFix data to */
    init_data.ipfix_port = 0;                 /* use default IPFix port */
    init_data.bitmask = (JOY_HTTP_ON | JOY_TLS_ON | JOY_IDP_ON | JOY_SALT_ON | JOY_BYTE_DIST_ON);

#ifdef HAVE_CONFIG_H
    printf("Joy Version = %s\n", joy_get_version());
#endif

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
    rc = pthread_create(&thread1, NULL, thread_main1, file1);
    if (rc) {
         printf("error: could not thread1 pthread_create() rc: %d\n", rc);
         return -6;
    }

    /* start up thread2 for processing */
    rc = pthread_create(&thread2, NULL, thread_main2, file2);
    if (rc) {
         printf("error: could not thread2 pthread_create() rc: %d\n", rc);
         return -6;
    }

    /* start up thread3 for processing */
    rc = pthread_create(&thread3, NULL, thread_main3, file3);
    if (rc) {
         printf("error: could not thread3 pthread_create() rc: %d\n", rc);
         return -6;
    }

    /* let the threads run */
    sleep(10);
    joy_shutdown();
    return 0;
}

