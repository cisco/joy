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
 * \file joy_api.c
 *
 * \brief API interface into the Joy library. Joy library converts pcap
 * files or live packet capture using libpcap into flow/intraflow 
 * data in JSON format
 * 
 */

#include <sys/types.h>
#include <stdlib.h>  
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>  

#include "config.h"
#include "pcap.h"
#include "p2f.h"
#include "anon.h"
#include "radix_trie.h"
#include "classify.h"
#include "joy_api.h"

/* All of the global varibales are defined in p2f.c
 * they are refenced here for usage purposes.
 */
extern enum SALT_algorithm salt_algo;
extern FILE *info;
extern zfile output;
extern unsigned int bidir;
extern unsigned int include_zeroes;
extern unsigned int include_retrans;
extern unsigned int byte_distribution;
extern char *compact_byte_distribution;
extern unsigned int report_entropy;
extern unsigned int report_idp;
extern unsigned int report_hd;
extern unsigned int include_classifier;
extern unsigned int nfv9_capture_port;
extern unsigned int ipfix_collect_port;
extern unsigned int ipfix_collect_online;
extern unsigned int ipfix_export_port;
extern unsigned int ipfix_export_remote_port;
extern unsigned int preemptive_timeout;
extern char *ipfix_export_remote_host;
extern char *ipfix_export_template;
extern char *aux_resource_path;
extern unsigned int verbosity;
extern unsigned int num_subnets;
extern unsigned short compact_bd_mapping[16];
extern radix_trie_t rt;

define_all_features_config_extern_uint(feature_list)

/* config is the global configuration */
extern struct configuration config;

/* external prototypes not included */
extern int data_sanity_check();
extern int ipfix_export_flush_message(void);
extern void ipfix_module_cleanup(void);
extern void process_packet(unsigned char *ignore, const struct pcap_pkthdr *header, const unsigned char *packet);

/*
 * Function: joy_initialize
 *
 * Description: This function initializes the Joy library
 *      to analize the data features defined in the bitmask.
 *      If the IPFIX_EXPORT option is turned on, we will set
 *      additional items related to the export. The caller
 *      has the option to change the output destinations.
 *
 * Parameters:
 *      init_data - structure of Joy options
 *      output_dir - the destination output directory
 *      output_file - the destination outputfile name
 *      logfile - the destination file for errors/info/debug messages
 *
 * Returns:
 *      ok or failure
 *
 */
int joy_initialize(struct joy_init *init_data,
        char *output_dir, char *output_file, char *logfile)
{
    char output_filename[MAX_FILENAME_LEN];

    /* clear out the configuration structure */
    memset(&config, 0x00, sizeof(struct configuration));

    /* sanity check the expected values for the packet headers */
    if (data_sanity_check() != ok) {
        return failure;
    }

    /* setup the logfile */
    if (logfile != NULL) {
        info = fopen(logfile, "a");
        if (info == NULL) {
            joy_log_err("could not open log file %s (%s)", logfile, strerror(errno));
            return failure;
        }
    } else {
        /* set 'info' to stderr as a precaution */
        info = stderr;
    }

    /* set the output directory */
    if (output_dir != NULL) {
        int len = strlen(output_dir);
        strcpy(output_filename, output_dir);
        if (output_filename[len-1] != '/') {
            strcat(output_filename, "/");
        }
    } else {
        strcpy(output_filename, "./");
    }

    /* setup the output file */
    if (output_file != NULL) {
        strcat(output_filename,output_file);
        output = zopen(output_filename, "w");
        if (output == NULL) {
            joy_log_err("could not open output file %s (%s)", output_filename, strerror(errno));
            joy_log_err("choose a new output name or move/remove the old data set");
            return failure;
        }
    } else {
        /* attach output to the stdout */
        output = zattach(stdout, "w");
    }

    /* set the configuration defaults */
    config_set_defaults(&config);
    config.type = init_data->type;
    config.verbosity = init_data->verbosity;

    /* setup joy with the output options */
    if (output_dir)
        config.outputdir = strdup(output_dir);
    if (output_file)
        config.filename = strdup(output_file);
    if (logfile)
        config.logfile = strdup(logfile);

    /* data features */
    config.bidir = ((init_data->bitmask & JOY_BIDIR_ON) ? 1 : 0);
    config.report_dns = ((init_data->bitmask & JOY_DNS_ON) ? 1 : 0);
    config.report_ssh = ((init_data->bitmask & JOY_SSH_ON) ? 1 : 0);
    config.report_tls = ((init_data->bitmask & JOY_TLS_ON) ? 1 : 0);
    config.report_dhcp = ((init_data->bitmask & JOY_DHCP_ON) ? 1 : 0);
    config.report_http = ((init_data->bitmask & JOY_HTTP_ON) ? 1 : 0);
    config.report_ike = ((init_data->bitmask & JOY_IKE_ON) ? 1 : 0);
    config.report_payload = ((init_data->bitmask & JOY_PAYLOAD_ON) ? 1 : 0);
    config.report_exe = ((init_data->bitmask & JOY_EXE_ON) ? 1 : 0);
    config.include_zeroes = ((init_data->bitmask & JOY_ZERO_ON) ? 1 : 0);
    config.include_retrans = ((init_data->bitmask & JOY_RETRANS_ON) ? 1 : 0);
    config.byte_distribution = ((init_data->bitmask & JOY_BYTE_DIST_ON) ? 1 : 0);
    config.report_entropy = ((init_data->bitmask & JOY_ENTROPY_ON) ? 1 : 0);
    config.report_hd = ((init_data->bitmask & JOY_HEADER_ON) ? 1 : 0);
    config.preemptive_timeout = ((init_data->bitmask & JOY_PREMPTIVE_TMO_ON) ? 1 : 0);

    /* check for IPFix export option */
    if (init_data->bitmask & JOY_IPFIX_EXPORT_ON) {
        config.ipfix_export_template = "idp";
        if (init_data->idp > 0) {
            config.idp = init_data->idp;
        } else {
            config.idp = DEFAULT_IDP_SIZE;
        }
        if (init_data->ipfix_host != NULL) {
            config.ipfix_export_remote_host =  strdup(init_data->ipfix_host);
        } else {
            /* default to the loopback address */
            config.ipfix_export_remote_host = "127.0.0.1";
        }
        if (init_data->ipfix_port > 0) {
            config.ipfix_export_port = init_data->ipfix_port - 1;
            config.ipfix_export_remote_port = init_data->ipfix_port;
        } else {
            config.ipfix_export_port = DEFAULT_IPFIX_EXPORT_PORT - 1;
            config.ipfix_export_remote_port = DEFAULT_IPFIX_EXPORT_PORT;
        }
    }

    /* setup the globals used within the Joy library itself */
    bidir = config.bidir;
    include_zeroes = config.include_zeroes;
    include_retrans = config.include_retrans;
    byte_distribution = config.byte_distribution;
    compact_byte_distribution = config.compact_byte_distribution;
    report_entropy = config.report_entropy;
    report_hd = config.report_hd;
    include_classifier = config.include_classifier;
    report_idp = config.idp;
    salt_algo = config.type;
    nfv9_capture_port = config.nfv9_capture_port;
    ipfix_collect_port = config.ipfix_collect_port;
    ipfix_collect_online = config.ipfix_collect_online;
    ipfix_export_port = config.ipfix_export_port;
    ipfix_export_remote_port = config.ipfix_export_remote_port;
    ipfix_export_remote_host = config.ipfix_export_remote_host;
    ipfix_export_template = config.ipfix_export_template;
    preemptive_timeout = config.preemptive_timeout;
    aux_resource_path = config.aux_resource_path;
    verbosity = config.verbosity;

    set_config_all_features(feature_list)

    /* intialize the data structures */
    flow_record_list_init();
    flocap_stats_timer_init();

    /* print the configuration in the output */
    config_print_json(output, &config);

    return ok;
}

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
int joy_anon_subnets(char *anon_file)
{
    if (anon_file != NULL) {
        config.anon_addrs_file = anon_file;
        if (anon_init(config.anon_addrs_file, info) == 1) {
            joy_log_err("could not initialize anonymization subnets from file %s",
                            config.anon_addrs_file);
            return 1;
        }
    } else {
        /* no file specified */
        joy_log_err("could not initialize anonymization subnets - no file specified");
        return 1;
    }

    return 0;
}

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
int joy_anon_http_usernames(char *anon_http_file)
{
    if (anon_http_file != NULL) {
        config.anon_http_file = anon_http_file;
        if (anon_http_init(config.anon_http_file, info, mode_anonymize, ANON_KEYFILE_DEFAULT) == 1) {
            joy_log_err("could not initialize anonymization for http usernames from file %s",
                            config.anon_http_file);
            return 1;
        }
    } else {
        /* no file specified */
        joy_log_err("could not initialize anonymization for http usernames - no file specified");
        return 1;
    }

    return 0;
}

/*
 * Function: joy_update_splt_bd_params
 *
 * Description: This function processes two files to update the
 *      values used for SPLT and BD processing in the machine learning
 *      classifer. The format of the file should match the format
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
int joy_update_splt_bd_params(char *splt_filename, char *bd_filename)
{
    if ((splt_filename == NULL) || (bd_filename == NULL)) {
        /* no file specified */
        joy_log_err("could not update SPLT/BD parameters - missing update file(s)");
        return 1;
    } else {
        update_params(SPLT_PARAM_TYPE, splt_filename);
        update_params(BD_PARAM_TYPE, bd_filename);
    }

    return 0;
}

/*
 * Function: joy_get_compact_bd
 *
 * Description: This function processes a file to update the
 *      compact BD values used for processing in the machine learning
 *      classifer.
 *
 * Parameters:
 *      filename - file of compact BD values
 *
 * Returns:
 *      0 - success
 *      1 - failure
 *
 */
int joy_get_compact_bd(char *filename)
{
    FILE *fp;
    int count = 0;
    unsigned short b_value, map_b_value;

    if (filename == NULL) {
        joy_log_err("couldn't update compact BD values - no file specified");
        return 1;
    }

    memset(compact_bd_mapping, 0, sizeof(compact_bd_mapping));

    fp = fopen(filename, "r");
    if (fp != NULL) {
        while (fscanf(fp, "%hu\t%hu", &b_value, &map_b_value) != EOF) {
            compact_bd_mapping[b_value] = map_b_value;
            count++;
            if (count >= 256) {
                break;
            }
        }
        fclose(fp);
        config.compact_byte_distribution = filename;
        compact_byte_distribution = config.compact_byte_distribution;
    } else {
        joy_log_err("could not open compact BD file %s", filename);
        return 1;
    }

    return 0;
}

/*
 * Function: joy_label_subnets
 *
 * Description: This function applies the label to the subnets specified
 *      in the subnet file.
 *
 * Parameters:
 *      label - label to be output for the subnets
 *      filename - file of subnets the label applies to
 *
 * Returns:
 *      0 - success
 *      1 - failure
 *
 */
int joy_label_subnets(char *label, char *filename)
{
    attr_flags subnet_flag;
    enum status err;

    /* see if we need a new radix_trie */
    if (rt == NULL) {
        rt = radix_trie_alloc();
        if (rt == NULL) {
            joy_log_err("could not allocate memory for labeled subnets");
            return 1;
        }

        /* initialize our new radix_trie */
        err = radix_trie_init(rt);
        if (err != ok) {
            joy_log_err("could not initialize subnet labels (radix_trie)");
            return 1;
        }
    }

    /* processing the subnet file now */
    subnet_flag = radix_trie_add_attr_label(rt, label);
    if (subnet_flag == 0) {
          joy_log_err("could not add subnet label %s to radix_trie", label);
          return 1;
    }

    err = radix_trie_add_subnets_from_file(rt, filename, subnet_flag, info);
    if (err != ok) {
          joy_log_err("could not add labeled subnets from file %s", filename);
          return 1;
    }

    /* increment the number of subnets we have configured */
    ++config.num_subnets;
    return 0;
}

/*
 * Function: joy_process_packet
 *
 * Description: This function is formatted to match the libpcap
 *      prototype for processing packets. This is essentially
 *      wrapper function for the code used within the Joy library.
 *
 * Parameters:
 *      ignore - Joy does not use this paramter
 *      header - libpcap header which contains timestamp, cap lenth and length
 *      packet - the actual data packet
 *
 * Returns:
 *      none
 *
 */
void joy_process_packet(unsigned char *ignore,
        const struct pcap_pkthdr *header,
        const unsigned char *packet)
{
    process_packet(ignore, header, packet);
}

/*
 * Function: joy_print_flow_data
 *
 * Description: This function is prints out the flow data from
 *      the Joy data structres to the output destination specified
 *      in the joy_initialize call. The output is formatted as
 *      Joy JSON objects.
 *      Part this operation will check to see if there is any
 *      host flow data to collect, if the option is turned on.
 *
 * Parameters:
 *      type - JOY_EXPIRED_FLOWS or JOY_PRINT_ALL_FLOWS
 *
 * Returns:
 *      none
 *
 */
void joy_print_flow_data(int type)
{
    /* see if we should collect host information */
    if (config.report_exe) {
        joy_log_info("retrieveing process information\n");
        if (get_host_flow_data() != 0) {
            joy_log_warn("Could not obtain host/process flow data\n");
        }
    }

    /* print the flow records */
    flow_record_list_print_json(type);
}

/*
 * Function: joy_export_flows_ipfix
 *
 * Description: This function is exports the flow data from
 *      the Joy data structres to the destination specified
 *      in the joy_initialize call. The flow data is exported
 *      as IPFix packets to the destination.
 *
 * Parameters:
 *      type - JOY_EXPIRED_FLOWS or JOY_ALL_FLOWS
 *
 * Returns:
 *      none
 *
 */
void joy_export_flows_ipfix(int type)
{
    /* export the flow records */
    flow_record_export_as_ipfix(type);
}

/*
 * Function: joy_cleanup
 *
 * Description: This function cleans up any lefotover data that maybe
 *      hanging around. If IPFix exporting is turned on, then it also
 *      flushes any remaining records out to the destination.
 *
 * Parameters:
 *      none
 *
 * Returns:
 *      none
 *
 */
void joy_cleanup(void)
{
    /* Flush any unsent exporter messages in Ipfix module */
    if (config.ipfix_export_port) {
        ipfix_export_flush_message();
    }

    /* Cleanup any leftover memory, sockets, etc. in Ipfix module */
    ipfix_module_cleanup();

    /* free up the flow records */
    flow_record_list_free();
}

