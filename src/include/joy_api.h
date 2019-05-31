/*
 *
 * Copyright (c) 2018-2019 Cisco Systems, Inc.
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

/* Definitions of contants used in the Joy Library API */
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

typedef enum {
    JOY_EXPIRED_FLOWS          = 0,
    JOY_ALL_FLOWS              = 1
} joy_flow_type_e;

typedef enum {
    JOY_NFV9_EXPORT            = 0,
    JOY_IPFIX_EXPORT           = 1
} joy_export_type_e;

/*
 * These flags define if a flow record has sufficient data
 * collected in order to successfully process that
 * particular data feature.
 */
#define JOY_IDP_READY           (1 << 0)
#define JOY_TLS_READY           (1 << 1)
#define JOY_SPLT_READY          (1 << 2)
#define JOY_SALT_READY          (1 << 3)
#define JOY_BD_READY            (1 << 4)

/*
 * Joy Library Flow Record Delete Bitmask Values
 * Each value represents a data feature that has been
 * processed by an external application. When calling
 * joy_delete_flow_records, the caller will represent
 * which flow records are ok to delete by supplying the
 * bitmask of the data features that they have already
 * processed.
 *
 */
#define JOY_DELETE_ALL          (0)
#define JOY_IDP_PROCESSED       (1 << 0)
#define JOY_TLS_PROCESSED       (1 << 1)
#define JOY_SALT_PROCESSED      (1 << 2)
#define JOY_SPLT_PROCESSED      (1 << 3)
#define JOY_BD_PROCESSED        (1 << 4)

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
#define JOY_IDP_ON                 (1 << 16)
#define JOY_IPFIX_EXPORT_ON        (1 << 17)
#define JOY_PPI_ON                 (1 << 18)
#define JOY_SALT_ON                (1 << 19)
#define JOY_RETAIN_LOCAL_ON        (1 << 20)
#define JOY_UPDATER_ON             (1 << 21)
#define JOY_FPX_ON                 (1 << 22)


/* structure to hold feature ready counts for reporting */
typedef struct joy_ctx_feat_count {
    uint32_t idp_recs_ready;
    uint32_t tls_recs_ready;
    uint32_t splt_recs_ready;
    uint32_t salt_recs_ready;
    uint32_t bd_recs_ready;
} joy_ctx_feat_count_t;

/* structure used to initialize joy through the API Library */
typedef struct joy_init {
    uint8_t verbosity;           /* verbosity 0 (off) - 5 (critical) */
    uint32_t max_records;        /* max record in output file */
    uint16_t num_pkts;           /* num_pkts to report on per flow */
    uint8_t contexts;            /* number of contexts the app wants to use */
    uint16_t inact_timeout;      /* seconds for inactive timeout - if 0, then default used */
    uint16_t act_timeout;        /* seconds for active timeout - if 0, then default used */
    uint16_t idp;                /* idp size to report, recommend 1300 */
    const char *ipfix_host;      /* ip string of the host to send IPFix data to */
    uint16_t ipfix_port;         /* port to send IPFix to remote on */
    const char *upload_srvname;  /* upload server name */
    const char *upload_keyfile;  /* upload key file name */
    uint32_t bitmask;            /* bitmask representing which features are on */
} joy_init_t;

/* structure definition for the library context data */
typedef struct joy_ctx_data joy_ctx_data;

/* definition for external processing callback */
typedef void (joy_flow_rec_callback)(void *rec, unsigned int data_len, unsigned char *data);

#include "pcap.h"
#include "p2f.h"

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
extern int joy_initialize (joy_init_t *data, const char *output_dir,
                           const char *output_file, const char *logfile);

/*
 * Function: joy_initialize_no_config
 *
 * Description: This function initializes the Joy library
 *      to analyze the data features. This fucntion does not
 *      perform any configuration options as it is expetced that
 *      the caller did configuration prior to calling this function.
 *
 *      joy_initialize must be called before using any of the other
 *      API functions.
 *
 * Parameters:
 *      config - pointer to pre-setup config
 *      err_info - pointer to the file for error logging
 *      data - structure of Joy options
 *
 * Returns:
 *      0 - success
 *      1 - failure
 *
 */
extern int joy_initialize_no_config (void *config, FILE *err_info, joy_init_t *data);

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
extern void joy_print_config (uint8_t index, uint8_t format);

/*
 * Function: joy_print_flocap_stats_output
 *
 * Description: This function prints out flow capture statistics.
 *
 * Parameters:
 *      index - index of the context to print the config into
 *
 * Returns:
 *      none
 *
 */
extern void joy_print_flocap_stats_output (uint8_t index);

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
extern int joy_anon_subnets (const char *anon_file);

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
extern int joy_anon_http_usernames (const char *anon_http_file);

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
extern int joy_update_splt_bd_params (const char *splt_filename, const char *bd_filename);

/*
 * Function: joy_update_compact_bd
 *
 * Description: This function processes a file to update the
 *      compact BD values used for processing in the machine learning
 *      classifier.
 *
 * Parameters:
 *      filename - file of compact BD values
 *
 * Returns:
 *      0 - success
 *      1 - failure
 *
 */
extern int joy_update_compact_bd (const char *filename);

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
extern int joy_label_subnets (const char *label, uint8_t type, const char* subnet_str);

/*
 * Function: joy_update_ctx_global_time
 *
 * Description: This function updates the global time of a given
 *      JOY library context. This is useful is adjusting the expiration
 *      of flow records when packets are not submitted for processing.
 *
 * Parameters:
 *      ctx_index - the index number of the JOY context
 *      new_time - pointer to the timeval structure containin the new time
 *
 * Returns:
 *      none.
 */
extern void joy_update_ctx_global_time (uint8_t ctx_index,
                                        struct timeval *new_time);

/*
 * Function: joy_packet_to_context
 *
 * Description: This function takes in an IP packet and using the
 *      5-tuple determines which context it should be sent to for
 *      data feature processing. This APi is useful for applications
 *      that use the JOY library and want to use the libraries default
 *      scheme for dividing up traffic among various worker contexts.
 *
 * Parameters:
 *      packet - pointer to the IP packet data
 *      num_contexts - number of contexts to use for distribution
 *
 * Returns:
 *      context - the context number the packet belongs to for JOY processing.
 *          This algorithm keeps bidirectional flows in the same context.
 *
 */
extern uint8_t joy_packet_to_context (const unsigned char *packet, uint8_t num_contexts);

/*
 * Function: joy_index_to_context
 *
 * Description: This function takes in an index and returns a
 *      pointer to the context.
 *
 * Parameters:
 *      ctx_index - index of the context you want
 *
 * Returns:
 *      context - pointer to the context structure
 *
 */
extern void* joy_index_to_context (uint8_t ctx_index);

/*
 * Function: joy_process_packet
 *
 * Description: This function invoked the packet processing function
 *      however, the application is permitted store some small amount
 *      of data in the flow record once it is created. This can be
 *      useful on the back end when an application wants to associate
 *      some data with a flow record during processing of the flow record.
 *
 * Parameters:
 *      ctx_index - index of the thread context to use
 *      header - libpcap header which contains timestamp, cap length
 *               and length
 *      packet - the actual data packet
 *      app_data_len - length of the application specific data
 *      app_data - pointer to the application data
 *
 * Notes:
 *      The application specific data length and data will be stored
 *      in the flow record. The application data is copied, so the calling
 *      application is responsible for freeing the data buffer, if necessary,
 *      when this function returns.
 *
 * Returns:
 *      Pointer to the flow record
 *
 */
extern void* joy_process_packet (unsigned char *ctx_index,
                                 const struct pcap_pkthdr *header,
                                 const unsigned char *packet,
                                 unsigned int app_data_len,
                                 const unsigned char *app_data);

/*
 * Function: joy_libpcap_process_packet
 *
 * Description: This function is formatted to match the libpcap
 *      prototype for processing packets. This is essentially
 *      wrapper function for the code used within the Joy library.
 *
 * Parameters:
 *      ctx_index - index of the thread context to use
 *      header - libpcap header which contains timestamp, cap length
 *               and length
 *      packet - the actual data packet
 *
 * Returns:
 *      none
 *
 */
extern void joy_libpcap_process_packet (unsigned char *ctx_index,
                                        const struct pcap_pkthdr *header,
                                        const unsigned char *packet);

/*
 * Function: joy_print_flow_data
 *
 * Description: This function is prints out the flow data from
 *      the Joy data structures to the output destination specified
 *      in the joy_initialize call. The output is formatted as
 *      Joy JSON objects.
 *
 *      Part this operation will check to see if there is any
 *      host flow data to collect, if the option is turned on.
 *
 *      This function will remove the records that are printed from
 *      the flow record list.
 *
 * Parameters:
 *      index - index of the context to use
 *      type - JOY_EXPIRED_FLOWS or JOY_PRINT_ALL_FLOWS
 *
 * Returns:
 *      none
 *
 */
extern void joy_print_flow_data (uint8_t index, joy_flow_type_e type);

/*
 * Function: joy_export_flows_ipfix
 *
 * Description: This function is exports the flow data from
 *      the Joy data structures to the destination specified
 *      in the joy_initialize call. The flow data is exported
 *      as IPFix packets to the destination.
 *
 *      This function will remove the records that are exported
 *      from the flow record list.
 *
 * Parameters:
 *      index - index of the context to use
 *      type - JOY_EXPIRED_FLOWS or JOY_ALL_FLOWS
 *
 * Returns:
 *      none
 *
 */
extern void joy_export_flows_ipfix (uint8_t index, joy_flow_type_e type);

/*
 * Function: joy_get_feature_counts
 *
 * Description: This function is pulls the record count for each
 *      data feature that is ready for a given context.
 *
 * Parameters:
 *      index - index of the context to use
 *      feat_counts - structure containing the record counts of each feature ready
 *
 * Returns:
 *      none
 *
 */
extern void joy_get_feature_counts (uint8_t index, joy_ctx_feat_count_t *feat_counts);

/*
 * Function: joy_idp_external_processing
 *
 * Description: This function is allows the calling application of
 *      the Joy library to handle the processing of the flow records
 *      that have IDP information ready for export.
 *      This function simply goes through the flow records and invokes
 *      the callback function to process the records that have IDP data.
 *
 *      Records that get processed have the IDP processed flag updated
 *      but are NOT removed from the flow record list.
 *
 * Parameters:
 *      index - index of the context to use
 *      callback - function that actually does the flow record processing
 *
 * Returns:
 *      none
 *
 * Notes:
 *      The callback function will get passed a pointer to the flow record.
 *      The data_len and data fields will be ZERO and NULL respectively. This
 *      is because the IDP data can be retrieved directly from the flow record.
 */
extern void joy_idp_external_processing (uint8_t index,
                                         joy_flow_rec_callback callback_fn);

/*
 * Function: joy_tls_external_processing
 *
 * Description: This function is allows the calling application of
 *      the Joy library to handle the processing of the flow records
 *      that have TLS information ready for export.
 *      This function simply goes through the flow records and invokes
 *      the callback function to process the records that have TLS data.
 *
 *      Records that get processed have the TLS processed flag updated
 *      but are NOT removed from the flow record list.
 *
 * Parameters:
 *      index - index of the context to use
 *      callback - function that actually does the flow record processing
 *
 * Returns:
 *      none
 *
 * Notes:
 *      The callback function will get passed a pointer to the flow record.
 *      The data_len and data fields will be ZERO and NULL respectively. This
 *      is because the TLS data can be retrieved directly from the flow record.
 */
extern void joy_tls_external_processing (uint8_t index,
                                         joy_flow_rec_callback callback_fn);

/*
 * Function: joy_splt_external_processing
 *
 * Description: This function is allows the calling application of
 *      the Joy library to handle the processing of the flow records
 *      that have SPLT information ready for export.
 *      This function simply goes through the flow records and invokes
 *      the callback function to process the records that have SPLT data.
 *
 *      Records that get processed have the SPLT processed flag updated
 *      but are NOT removed from the flow record list.
 *
 * Parameters:
 *      index - index of the context to use
 *      export_frmt - formatting of the exported data
 *      min_pkts - minimum number of packets processed before export occurs
 *      callback - function that actually does the flow record processing
 *
 * Returns:
 *      none
 *
 * Notes:
 *      The callback function will get passed a pointer to the flow record.
 *      The SPLT data needs to be preprocessed for export and as such, the
 *      data_len field will be the length of the preprocessed data and the
 *      data field will be a pointer to the actual preprocessed data. The callback
 *      does not need to worry about freeing the memory associated with the data.
 *      Once control returns from the callback function, the library will handle that
 *      memory. IF the callback function needs access to this data after it returns
 *      control to the library, then it should copy that data for later use.
 *
 *      For NetFlow V9:
 *           Data Length returned is always 40 bytes (10 records times 4 bytes per record)
 *           If actual number of records is less than 10, padding occurs
 *      For IPFix:
 *           Data Length returned will be N * 4 (N records times 4 bytes per record)
 *              Maximum value for N is 10
 *           If actual number of records is less than 10, NO padding occurs
 *      Format of the Data (NetFlow V9 & IPFix):
 *           All length values (16-bits) followed by all times (16-bits)
 *           ie: for data length of 20 bytes
 *             format: len,len,len,len,len,time,time,time,time,time
 */
extern void joy_splt_external_processing (uint8_t index,
                                          joy_export_type_e export_frmt,
                                          unsigned int min_pkts,
                                          joy_flow_rec_callback callback_fn);

/*
 * Function: joy_salt_external_processing
 *
 * Description: This function is allows the calling application of
 *      the Joy library to handle the processing of the flow records
 *      that have SALT information ready for export.
 *      This function simply goes through the flow records and invokes
 *      the callback function to process the records that have SPLT data.
 *
 *      Records that get processed have the SALT processed flag updated
 *      but are NOT removed from the flow record list.
 *
 * Parameters:
 *      index - index of the context to use
 *      export_frmt - formatting of the exported data
 *      min_pkts - minimum number of packets processed before export occurs
 *      callback - function that actually does the flow record processing
 *
 * Returns:
 *      none
 *
 * Notes:
 *      The callback function will get passed a pointer to the flow record.
 *      The SALT data needs to be preprocessed for export and as such, the
 *      data_len field will be the length of the preprocessed data and the
 *      data field will be a pointer to the actual preprocessed data. The callback
 *      does not need to worry about freeing the memory associated with the data.
 *      Once control returns from the callback function, the library will free that
 *      memory. IF the callback function needs access to this data after it returns
 *      control to the library, then it should copy that data for later use.
 *
 *      For NetFlow V9:
 *           Data Length returned is always 40 bytes (10 records times 4 bytes per record)
 *           If actual number of records is less than 10, padding occurs
 *      For IPFix:
 *           Data Length returned will be N * 4 (N records times 4 bytes per record)
 *              Maximum value for N is 10
 *           If actual number of records is less than 10, NO padding occurs
 *      Format of the Data (NetFlow V9 & IPFix):
 *           All length values (16-bits) followed by all times (16-bits)
 *           ie: for data length of 20 bytes
 *             format: len,len,len,len,len,time,time,time,time,time
 */
extern void joy_salt_external_processing (uint8_t index,
                                          joy_export_type_e export_frmt,
                                          unsigned int min_pkts,
                                          joy_flow_rec_callback callback_fn);

/*
 * Function: joy_bd_external_processing
 *
 * Description: This function is allows the calling application of
 *      the Joy library to handle the processing of the flow records
 *      that have BD (byte distribution) information ready for export.
 *      This function simply goes through the flow records and invokes
 *      the callback function to process the records that have SPLT data.
 *
 *      Records that get processed have the BD processed flag updated
 *      but are NOT removed from the flow record list.
 *
 * Parameters:
 *      index - index of the context to use
 *      min_octets - minimum number of octets processed before ready
 *      callback - function that actually does the flow record processing
 *
 * Returns:
 *      none
 *
 * Notes:
 *      The callback function will get passed a pointer to the flow record.
 *      The BD data needs to be preprocessed for export and as such, the
 *      data_len field will be the length of the preprocessed data and the
 *      data field will be a pointer to the actual preprocessed data. The callback
 *      does not need to worry about freeing the memory associated with the data.
 *      Once control returns from the callback function, the library will free that
 *      memory. IF the callback function needs access to this data after it returns
 *      control to the library, then it should copy that data for later use.
 *
 *      For NetFlow V9 and IPFix:
 *          The data length is always 512 bytes. Currently only BD format uncompressed
 *              is defined in the spec.
 *          The data format is a series of 16-bit values representing the count of a
 *              given ascii value. The first 16-bit value represents the number of
 *              times ascii value 0 was seen in the flow. The second 16-bit value
 *              represents the number times the ascii value 1 was seen in the flow.
 *              This continues for all ascii values up to value 255.
 */
extern void joy_bd_external_processing (uint8_t index,
                                        unsigned int min_octets,
                                        joy_flow_rec_callback callback_fn);

/*
 * Function: joy_delete_flow_records
 *
 * Description: This function is allows the calling application of
 *      the Joy library to handle the explicit deletion of flow records
 *      from the flow_record list.
 *
 * Parameters:
 *      index - index of the context to use
 *      cond_bitmask - bitmask of conditions on which records to delete
 *             (JOY_IDP_PROCESSED, JOY_TLS_PROCESSED, JOY_SALT_PROCESSED,
 *              JOY_SPLT_PROCESSED, JOY_BD_PROCESSED, JOY_ANY_PROCESSED)
 *
 * Returns:
 *      unsigned int - number of records deleted
 *
 */
extern unsigned int joy_delete_flow_records (uint8_t index,
                                             unsigned int cond_bitmask);

/*
 * Function: joy_purge_old_flow_records
 *
 * Description: This function allows the calling application of
 *      the Joy library to handle the forced removal of flow records
 *      that are older than the time value passed in by the caller.
 *
 * Parameters:
 *      index - index of the context to use
 *      rec_age - age of the records in seconds
 *
 * Returns:
 *      unsigned int - number of records deleted
 *
 */
extern unsigned int joy_purge_old_flow_records (uint8_t index,
                                                unsigned int rec_age);

/*
 * Function: joy_context_cleanup
 *
 * Description: This function cleans up any lefotover data that maybe
 *      hanging around for the context worker. If IPFix exporting is turned
 *      on, then it also flushes any remaining records out to the destination.
 *
 * Parameters:
 *      index - index of the context to use
 *
 * Returns:
 *      none
 *
 */
extern void joy_context_cleanup (uint8_t index);

/*
 * Function: joy_shutdown
 *
 * Description: This function cleans up the JOY library and essentially
 *      shuts the library down and reverts back to clean unused state.
 *
 * Parameters:
 *      none
 *
 * Returns:
 *      none
 *
 */
extern void joy_shutdown (void);

#ifdef HAVE_CONFIG_H
extern const char * joy_get_version(void);
#endif


#endif /* JOY_API_H */
