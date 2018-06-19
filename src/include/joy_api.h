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
#include <stdint.h>
#include "pcap.h"

/* Definitions of contants used in the Joy Library API */
#define JOY_EXPIRED_FLOWS 0
#define JOY_ALL_FLOWS 1
#define JOY_TERMINAL_FORMAT 0
#define JOY_JSON_FORMAT 1
#define JOY_SINGLE_SUBNET 0
#define JOY_FILE_SUBNET 1
#define MAX_DIRNAME_LEN 256
#define MAX_FILENAME_LEN 1024
#define DEFAULT_IPFIX_EXPORT_PORT 4739
#define DEFAULT_IDP_SIZE 1300
#define MAX_LIB_CONTEXTS 10
#define MAX_RECORDS 2147483647

/*
 * Joy Library Bitmask Values
 * 
 *    Bitmask values for turning on various network data features.
 *    Each value represents a feature within the Joy Library and
 *    whether or not it is turned on.
 * 
 */
#define JOY_BIDIR_ON               (1 << 0)
#define JOY_DNS_ON                 (1 << 1)
#define JOY_SSH_ON                 (1 << 2)
#define JOY_TLS_ON                 (1 << 3)
#define JOY_DHCP_ON                (1 << 4)
#define JOY_HTTP_ON                (1 << 5)
#define JOY_IKE_ON                 (1 << 6)
#define JOY_PAYLOAD_ON             (1 << 7)
#define JOY_EXE_ON                 (1 << 8)
#define JOY_ZERO_ON                (1 << 9)
#define JOY_RETRANS_ON             (1 << 10)
#define JOY_BYTE_DIST_ON           (1 << 11)
#define JOY_ENTROPY_ON             (1 << 12)
#define JOY_CLASSIFY_ON            (1 << 13)
#define JOY_HEADER_ON              (1 << 14)
#define JOY_PREMPTIVE_TMO_ON       (1 << 15)
#define JOY_IPFIX_SIMPLE_EXPORT_ON (1 << 16)
#define JOY_IPFIX_IDP_EXPORT_ON    (1 << 17)


/* structure used to initialize joy through the API Library */
struct joy_init {
    int type;                    /* type 1 (SPLT) 2 (SALT) */
    int verbosity;               /* verbosity 0 (off) - 5 (critical) */
    uint32_t max_records;        /* max record in output file */
    int contexts;                /* number of contexts the app wants to use */
    int idp;                     /* idp size to report, recommend 1300 */
    char *ipfix_host;            /* ip string of the host to send IPFix data to */
    uint32_t ipfix_port;         /* port to send IPFix to remote on */
    uint32_t bitmask;            /* bitmask representing which features are on */
};

/* structure definition for the library context data */
typedef struct joy_ctx_data joy_ctx_data;

/* definition for external processing callback */
typedef void (joy_flow_rec_callback)(void*);

/* prototypes for the API interface */

/*
 * Function: joy_initialize
 *
 * Description: This function initializes the Joy library
 *      to analyze the data features defined in the bitmask.
 *      If the IPFIX_EXPORT option is turned on, we will set
 *      additional items related to the export. The caller
 *      has the option to change the output destinations.
 *
 *      joy_initialize must be called before using any of the other
 *      API functions.
 *
 * Parameters:
 *      init_data - structure of Joy options
 *      output_dir - the destination output directory
 *      output_file - the destination outputfile name
 *      logfile - the destination file for errors/info/debug messages
 *
 * Returns:
 *      0 - success
 *      1 - failure
 *
 */
extern int joy_initialize (struct joy_init *data, char *output_dir,
			   char *output_file, char *logfile);

/*
 * Function: joy_print_config
 *
 * Description: This function prints out the configuration
 *      of the Joy library in either JSON or terminal format.
 *
 * Parameters:
 *      index - index of the context to print the config into
 *      format - JOY_JSON_FORMAT or JOY_TERMINAL_FORMAT
 *
 * Returns:
 *      none
 *
 */
extern void joy_print_config (int index, int format);

/*
 * Function: joy_anon_subnets
 *
 * Description: This function processes a file of subnets to
 *      anonymized when processing the packet/flow data.
 *
 * Parameters:
 *      anon_file - file of subnets to anonymize
 *
 * Expected format of the file:
 *
 * # subnets for address anonymization
 * 10.0.0.0/8         #  RFC 1918 address space
 * 172.16.0.0/12      #  RFC 1918 address space
 * 192.168.0.0/16     #  RFC 1918 address space
 *
 * Returns:
 *      0 - success
 *      1 - failure
 *
 */
extern int joy_anon_subnets (char *anon_file);

/*
 * Function: joy_anon_http_usernames
 *
 * Description: This function processes a file of usernames
 *      to anonymized when processing the packet/flow http data.
 *
 * Parameters:
 *      anon_http_file - file of usernames to anonymize
 *
 * Expected format of the file:
 * username1
 * username2
 *     .
 *     .
 *     .
 * usernameN
 *
 * Returns:
 *      0 - success
 *      1 - failure
 *
 */
extern int joy_anon_http_usernames (char *anon_http_file);

/*
 * Function: joy_update_splt_bd_params
 *
 * Description: This function processes two files to update the
 *      values used for SPLT and BD processing in the machine learning
 *      classifier. The format of the file should match the format
 *      produced from the python program (model.py) from the
 *      Joy repository.
 *
 * Parameters:
 *      splt_filename - file of SPLT values
 *      bd_filename - file of BD values
 *
 * Returns:
 *      0 - success
 *      1 - failure
 *
 */
extern int joy_update_splt_bd_params (char *splt_filename, char *bd_filename);

/*
 * Function: joy_get_compact_bd
 *
 * Description: This function processes a file to update the
 *      compact BD values used for counting the distribution 
 *      in a given flow.
 *
 * Parameters:
 *      filename - file of compact BD values
 *
 * Returns:
 *      0 - success
 *      1 - failure
 *
 */
extern int joy_get_compact_bd (char *filename);

/*
 * Function: joy_label_subnets
 *
 * Description: This function applies the label to the subnets specified
 *      in the subnet file.
 *
 * Parameters:
 *      label - label to be output for the subnets
 *      type - JOY_SINGLE_SUBNET or JOY_FILE_SUBNET
 *      subnet_str - a subnet address or a filename that contains subnets
 *
 * Returns:
 *      0 - success
 *      1 - failure
 *
 */
extern int joy_label_subnets (char *label, int type, char* subnet_str);

/*
 * Function: joy_process_packet
 *
 * Description: This function is formatted to match the libpcap
 *      prototype for processing packets. This is essentially
 *      wrapper function for the code used within the Joy library.
 *
 * Parameters:
 *      ctx_index - index of the context to use
 *      header - libpcap header which contains timestamp, cap length
 *               and length
 *      packet - the actual data packet
 *
 * Returns:
 *      none
 *
 */
extern void joy_process_packet (unsigned char *ctx_idx,
				const struct pcap_pkthdr *header, 
				const unsigned char *packet);

/*
 * Function: joy_print_flow_data
 *
 * Description: This function is prints out the flow data from
 *      the Joy data structures to the output destination specified
 *      in the joy_initialize call. The output is formatted as
 *      Joy JSON objects.
 *      Part this operation will check to see if there is any
 *      host flow data to collect, if the option is turned on.
 *
 * Parameters:
 *      index - index of the context to use
 *      type - JOY_EXPIRED_FLOWS or JOY_PRINT_ALL_FLOWS
 *
 * Returns:
 *      none
 *
 */
extern void joy_print_flow_data (unsigned int index, int type);

/*
 * Function: joy_export_flows_ipfix
 *
 * Description: This function is exports the flow data from
 *      the Joy data structures to the destination specified
 *      in the joy_initialize call. The flow data is exported
 *      as IPFix packets to the destination.
 *
 * Parameters:
 *      index - index of the context to use
 *      type - JOY_EXPIRED_FLOWS or JOY_ALL_FLOWS
 *
 * Returns:
 *      none
 *
 */
extern void joy_export_flows_ipfix (unsigned int index, int type);

/*
 * Function: joy_flow_record_external_processing
 *
 * Description: This function allows the calling application of
 *      the Joy library to handle the processing of the flow record.
 *      This function simply goes through the flow records and invokes
 *      the callback function to process the record.
 *      Records that get processed will be removed from the flow
 *      record list.
 *
 * Parameters:
 *      index - index of the context to use
 *      type - JOY_EXPIRED_FLOWS or JOY_ALL_FLOWS
 *      callback - function that actually does the flow record processing
 *
 * Returns:
 *      none
 *
 */
extern void joy_flow_record_external_processing(unsigned int index, 
						int type, 
						joy_flow_rec_callback callback_fn);

/*
 * Function: joy_cleanup
 *
 * Description: This function cleans up any leftover data that maybe
 *      hanging around. If IPFix exporting is turned on, then it also
 *      flushes any remaining records out to the destination.
 *
 * Parameters:
 *      index - index of the context to use
 *
 * Returns:
 *      none
 *
 */
extern void joy_cleanup (unsigned int index);

#endif /* JOY_API_H */
