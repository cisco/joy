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
#include "joy_api_private.h"
#include "pthread.h"
#include "proto_identify.h"
#include "output.h"
#include "ipfix.h"
#include "pkt_proc.h"

/* file destination variables */
FILE *info = NULL;

/* config is the global library configuration */
struct configuration active_config;

/* global library intialization flag */
static int joy_library_initialized = 0;

/* global data for the context configuration */
static int joy_num_contexts = 0;
static struct joy_ctx_data *ctx_data = NULL;

/*
 * Function: format_output_filename
 *
 * Description: This function formats the output filename
 *      using a timestamp. This is used for library initializations
 *      set the record limits in an output file. This will get
 *      called upon initial start up and then when output files
 *      need to roll over to the new output file.
 *
 * Parameters:
 *      basename - the destination output file base name
 *      output_filename - the complete destination output file name
 *
 * Returns:
 *      none, but rewrites output_filename to be the correct destination output file
 *
 */
static void format_output_filename(char *basename, char *output_filename)
{
    time_t now = time(0);
    struct tm *t = localtime(&now);
    static int fud = 0; /* ensures unique name in case max_records is too small */

    snprintf(output_filename, MAX_FILENAME_LEN, "%s-%.2d-%d%.2d%.2d%.2d%.2d%.2d%s", basename, ++fud,
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, zsuffix);
}

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
int joy_initialize(joy_init_t *init_data,
        char *output_dir, char *output_file, char *logfile)
{
    int i = 0;
    char output_dirname[MAX_DIRNAME_LEN];
    char output_filename[MAX_FILENAME_LEN];

    /* sanity check the context information */
    if (init_data->contexts < 1) {
        init_data->contexts = 1; /* default to 1 context thread */
    }

    /* clear out the configuration structure */
    memset(&active_config, 0x00, sizeof(struct configuration));
    glb_config = &active_config;

    /* allocate the context memory */
    JOY_API_ALLOC_CONTEXT(ctx_data, init_data->contexts)
    joy_num_contexts = init_data->contexts;

    /* set 'info' to stderr as a precaution */
    info = stderr;

    /* sanity check the expected values for the packet headers */
    if (data_sanity_check() != ok) {
        JOY_API_FREE_CONTEXT(ctx_data)
        return failure;
    }

    /* setup the logfile */
    if (logfile != NULL) {
        info = fopen(logfile, "a");
        if (info == NULL) {
            joy_log_err("could not open log file %s (%s)", logfile, strerror(errno));
            JOY_API_FREE_CONTEXT(ctx_data)
            return failure;
        }
    }

    /* set the output directory */
    memset(output_dirname, 0x00, MAX_DIRNAME_LEN);
    if (output_dir != NULL) {
        int len = strlen(output_dir);
        if (len > (MAX_DIRNAME_LEN-1)) {
            /* output dir is too long, default to /tmp */
            strncpy(output_dirname, "/tmp/", 5);
        } else {
            strncpy(output_dirname, output_dir, len);
            if (output_dirname[len-1] != '/') {
                strncat(output_dirname, "/", 1);
            }
        }
    } else {
        strncpy(output_dirname, "/tmp/", 5);
    }

    /* set the configuration defaults */
    if ((init_data->type > 0) && (init_data->type < 3)) {
        glb_config->type = init_data->type;
    }
    glb_config->verbosity = init_data->verbosity;
    glb_config->flow_key_match_method = EXACT_MATCH;

    /* setup joy with the output options */
    glb_config->outputdir = strdup(output_dirname);
    if (output_file)
        glb_config->filename = strdup(output_file);
    else
        glb_config->filename = "joy-output";
    if (logfile)
        glb_config->logfile = strdup(logfile);
    else
        glb_config->logfile = "stderr";

    /* setup the max records in a given output file */
    if (init_data->max_records > MAX_RECORDS) {
        glb_config->max_records = MAX_RECORDS;
    } else {
        glb_config->max_records = init_data->max_records;
    }

    /* data features */
    glb_config->bidir = ((init_data->bitmask & JOY_BIDIR_ON) ? 1 : 0);
    glb_config->report_dns = ((init_data->bitmask & JOY_DNS_ON) ? 1 : 0);
    glb_config->report_ssh = ((init_data->bitmask & JOY_SSH_ON) ? 1 : 0);
    glb_config->report_tls = ((init_data->bitmask & JOY_TLS_ON) ? 1 : 0);
    glb_config->report_dhcp = ((init_data->bitmask & JOY_DHCP_ON) ? 1 : 0);
    glb_config->report_http = ((init_data->bitmask & JOY_HTTP_ON) ? 1 : 0);
    glb_config->report_ike = ((init_data->bitmask & JOY_IKE_ON) ? 1 : 0);
    glb_config->report_payload = ((init_data->bitmask & JOY_PAYLOAD_ON) ? 1 : 0);
    glb_config->report_exe = ((init_data->bitmask & JOY_EXE_ON) ? 1 : 0);
    glb_config->include_zeroes = ((init_data->bitmask & JOY_ZERO_ON) ? 1 : 0);
    glb_config->include_retrans = ((init_data->bitmask & JOY_RETRANS_ON) ? 1 : 0);
    glb_config->byte_distribution = ((init_data->bitmask & JOY_BYTE_DIST_ON) ? 1 : 0);
    glb_config->report_entropy = ((init_data->bitmask & JOY_ENTROPY_ON) ? 1 : 0);
    glb_config->report_hd = ((init_data->bitmask & JOY_HEADER_ON) ? 1 : 0);
    glb_config->preemptive_timeout = ((init_data->bitmask & JOY_PREMPTIVE_TMO_ON) ? 1 : 0);

    /* check if IDP option is set */
    if (init_data->bitmask & JOY_IDP_ON) {
        glb_config->ipfix_export_template = "idp";
        if (init_data->idp > 0) {
            glb_config->idp = init_data->idp;
        } else {
            glb_config->idp = DEFAULT_IDP_SIZE;
        }
    } else {
        glb_config->ipfix_export_template = "simple";
        glb_config->idp = 0;
    }

    /* setup the IPFix exporter configuration */
    if (init_data->bitmask & JOY_IPFIX_EXPORT_ON) {
        if (init_data->ipfix_host != NULL) {
            glb_config->ipfix_export_remote_host =  strdup(init_data->ipfix_host);
        } else {
            /* default to the loopback address */
            glb_config->ipfix_export_remote_host = "127.0.0.1";
        }
        if (init_data->ipfix_port > 0) {
            glb_config->ipfix_export_port = init_data->ipfix_port;
            glb_config->ipfix_export_remote_port = init_data->ipfix_port;
        } else {
            glb_config->ipfix_export_port = DEFAULT_IPFIX_EXPORT_PORT;
            glb_config->ipfix_export_remote_port = DEFAULT_IPFIX_EXPORT_PORT;
        }
        ipfix_exporter_init(glb_config->ipfix_export_remote_host);
    }

    /* initialize the protocol identification dictionary */
    if (proto_identify_init()) {
        joy_log_err("could not initialize the protocol identification dictionary");
        JOY_API_FREE_CONTEXT(ctx_data)
        return failure;
    }

    /* initialize all the data context structures */
    for (i=0; i < JOY_MAX_CTX_INDEX(ctx_data) ++i) {
        struct joy_ctx_data *this = JOY_CTX_AT_INDEX(ctx_data,i)

        /* id the context */
        this->ctx_id = i;

        /* setup the output file basename for the context */
        memset(output_filename, 0x00, MAX_FILENAME_LEN);
        if (output_file != NULL) {
            if (strlen(output_file) > (MAX_FILENAME_LEN - strlen(output_dirname) - 16)) {
                /* dirname + filename is too long, use default filename scheme */
                snprintf(output_filename,MAX_FILENAME_LEN,"%sjoy-output.ctx%d",output_dirname,this->ctx_id);
            } else {
                snprintf(output_filename,MAX_FILENAME_LEN,"%s%s.ctx%d",output_dirname,output_file,this->ctx_id);
            }
        } else {
            snprintf(output_filename,MAX_FILENAME_LEN,"%sjoy-output.ctx%d",output_dirname,this->ctx_id);
        }

        /* store off the output file base name */
        this->output_file_basename = malloc(strlen(output_filename)+1);
        if (this->output_file_basename == NULL) {
            joy_log_err("could not store off base output filename");
            JOY_API_FREE_CONTEXT(ctx_data)
            return failure;
        } else {
            memset(this->output_file_basename, 0x00, strlen(output_filename)+1);
            strncpy(this->output_file_basename, output_filename, strlen(output_filename));
        }

        /* open the output file */
        memset(output_filename, 0x00, MAX_FILENAME_LEN);
        if (glb_config->max_records) {
            format_output_filename(this->output_file_basename, output_filename);
        } else {
            snprintf(output_filename, MAX_FILENAME_LEN,"%s%s",this->output_file_basename,zsuffix);
        }
        printf("Context :%d Output:%s\n",this->ctx_id,output_filename);
        this->output = zopen(output_filename, "w");
        if (this->output == NULL) {
            joy_log_err("could not open output file %s (%s)", output_filename, strerror(errno));
            joy_log_err("choose a new output name or move/remove the old data set");
            free(this->output_file_basename);
            JOY_API_FREE_CONTEXT(ctx_data)
            return failure;
        }

        flow_record_list_init(this);
        flocap_stats_timer_init(this);
    }

    /* set library init flag */
    joy_library_initialized = 1;
    return ok;
}

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
void joy_print_config(int index, int format)
{
    joy_ctx_data *ctx = NULL;

    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return;
    }

    /* sanity check the index value */
    if (index >= joy_num_contexts ) {
        joy_log_crit("Joy Library invalid context (%d) for packet processing!", index);
        return;
    }

    /* get the context to print the config into */
    ctx = JOY_CTX_AT_INDEX(ctx_data,index)

    if (format == JOY_TERMINAL_FORMAT) {
        /* print the configuration in the output */
        config_print(info, glb_config);
    } else {
        /* print the configuration in the output */
        config_print_json(ctx->output, glb_config);
    }
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
    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return failure;
    }

    if (anon_file != NULL) {
        glb_config->anon_addrs_file = anon_file;
        if (anon_init(glb_config->anon_addrs_file, info) == 1) {
            joy_log_err("could not initialize anonymization subnets from file %s",
                            glb_config->anon_addrs_file);
            return failure;
        }
    } else {
        /* no file specified */
        joy_log_err("could not initialize anonymization subnets - no file specified");
        return failure;
    }

    return ok;
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
    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return failure;
    }

    if (anon_http_file != NULL) {
        glb_config->anon_http_file = anon_http_file;
        if (anon_http_init(glb_config->anon_http_file, info, mode_anonymize, ANON_KEYFILE_DEFAULT) == 1) {
            joy_log_err("could not initialize anonymization for http usernames from file %s",
                            glb_config->anon_http_file);
            return failure;
        }
    } else {
        /* no file specified */
        joy_log_err("could not initialize anonymization for http usernames - no file specified");
        return failure;
    }

    return ok;
}

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
int joy_update_splt_bd_params(char *splt_filename, char *bd_filename)
{
    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return failure;
    }

    if ((splt_filename == NULL) || (bd_filename == NULL)) {
        /* no file specified */
        joy_log_err("could not update SPLT/BD parameters - missing update file(s)");
        return failure;
    } else {
        update_params(SPLT_PARAM_TYPE, splt_filename);
        update_params(BD_PARAM_TYPE, bd_filename);
    }

    return ok;
}

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
int joy_update_compact_bd(char *filename)
{
    FILE *fp;
    int count = 0;
    unsigned short b_value, map_b_value;

    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return failure;
    }

    if (filename == NULL) {
        joy_log_err("couldn't update compact BD values - no file specified");
        return failure;
    }

    memset(glb_config->compact_bd_mapping, 0, sizeof(glb_config->compact_bd_mapping));

    fp = fopen(filename, "r");
    if (fp != NULL) {
        while (fscanf(fp, "%hu\t%hu", &b_value, &map_b_value) != EOF) {
	    if (b_value < COMPACT_BD_MAP_MAX) {
		glb_config->compact_bd_mapping[b_value] = map_b_value;
		count++;
		if (count >= 256) {
		    break;
		}
	    }
        }
        fclose(fp);
        glb_config->compact_byte_distribution = filename;
    } else {
        joy_log_err("could not open compact BD file %s", filename);
        return failure;
    }

    return ok;
}

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
int joy_label_subnets(char *label, int type, char *subnet_str)
{
    attr_flags subnet_flag;
    joy_status_e err;
    char single_addr[64];

    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return failure;
    }

    /* see if we need a new radix_trie */
    if (glb_config->rt == NULL) {
        glb_config->rt = radix_trie_alloc();
        if (glb_config->rt == NULL) {
            joy_log_err("could not allocate memory for labeled subnets");
            return failure;
        }

        /* initialize our new radix_trie */
        err = radix_trie_init(glb_config->rt);
        if (err != ok) {
            joy_log_err("could not initialize subnet labels (radix_trie)");
            return failure;
        }
    }

    /* add the label to the radix_trie */
    subnet_flag = radix_trie_add_attr_label(glb_config->rt, label);
    if (subnet_flag == 0) {
          joy_log_err("could not add subnet label %s to radix_trie", label);
          return failure;
    }

    /* see if we are adding a file of subnets or just a single subnet address */
    if (type == JOY_SINGLE_SUBNET) {
        /* processing just a single subnet address */
        memset(single_addr,0x00,64);
        strncpy(single_addr,subnet_str,63);
        err = radix_trie_add_subnet_from_string(glb_config->rt, single_addr, subnet_flag, info);
        if (err != ok) {
            joy_log_err("could not add labeled subnet for %s", single_addr);
            return failure;
        }
    } else {
        /* processing the subnet file now */
        err = radix_trie_add_subnets_from_file(glb_config->rt, subnet_str, subnet_flag, info);
        if (err != ok) {
            joy_log_err("could not add labeled subnets from file %s", subnet_str);
            return failure;
        }
    }

    /* increment the number of subnets we have configured */
    glb_config->subnet[glb_config->num_subnets] = strdup(label);
    ++glb_config->num_subnets;
    return ok;
}

/*
 * Function: joy_process_packet
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
void joy_process_packet(unsigned char *ctx_index,
			const struct pcap_pkthdr *header,
			const unsigned char *packet)
{
    unsigned long int index = 0;
    joy_ctx_data *ctx = NULL;

    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return;
    }

    /* ctx_index has the int value of the data context
     * This number is between 0 and max configured contexts
     */
    index = (unsigned long int)ctx_index;

    if (index >= joy_num_contexts ) {
        joy_log_crit("Joy Library invalid context (%lu) for packet processing!", index);
        return;
    }

    ctx = JOY_CTX_AT_INDEX(ctx_data,index)
    process_packet((unsigned char*)ctx, header, packet);
}

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
void joy_print_flow_data(unsigned int index, JOY_FLOW_TYPE type)
{
    joy_ctx_data *ctx = NULL;

    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return;
    }

    /* sanity check the index value */
    if (index >= joy_num_contexts ) {
        joy_log_crit("Joy Library invalid context (%d) for packet processing!", index);
        return;
    }

    ctx = JOY_CTX_AT_INDEX(ctx_data,index)

    /* see if we should collect host information */
    if (glb_config->report_exe) {
        joy_log_info("retrieving process information\n");
        if (get_host_flow_data(ctx) != 0) {
            joy_log_warn("Could not obtain host/process flow data\n");
        }
    }

    /* print the flow records */
    flow_record_list_print_json(ctx, type);

    /* see if we need to rotate the output files */
    if (glb_config->max_records) {
        if (ctx->records_in_file >= glb_config->max_records) {
            char output_filename[MAX_FILENAME_LEN];

            zclose(ctx->output);
            ctx->records_in_file = 0;
            memset(output_filename, 0x00, MAX_FILENAME_LEN);
            format_output_filename(ctx->output_file_basename, output_filename);
            printf("Rolling Context :%d Output:%s\n",index,output_filename);
            ctx->output = zopen(output_filename, "w");
            if (ctx->output == NULL) {
                joy_log_err("could not open output file %s (%s)", output_filename, strerror(errno));
                joy_log_err("Rolling the output file failed!");
                return;
            }
            /* print new JSON preamble */
            joy_print_config(index, JOY_JSON_FORMAT);
        }
    }
}

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
void joy_export_flows_ipfix(unsigned int index, JOY_FLOW_TYPE type)
{
    joy_ctx_data *ctx = NULL;

    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return;
    }

    /* sanity check the index value */
    if (index >= joy_num_contexts ) {
        joy_log_crit("Joy Library invalid context (%d) for packet processing!", index);
        return;
    }

    /* export the flow records */
    ctx = JOY_CTX_AT_INDEX(ctx_data,index)
    flow_record_export_as_ipfix(ctx, type);
}

/*
 * Function: joy_idp_external_processing
 *
 * Description: This function is allows the calling application of
 *      the Joy library to handle the processing of the flow records
 *      that have IDP information ready for export.
 *      This function simply goes through the flow records and invokes
 *      the callback function to process the records that have IDP data.
 *      Records that get processed have the IDP processed flag updated
 *      but are NOT removed from the flow record list.
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
void joy_idp_external_processing(unsigned int index,
				 JOY_FLOW_TYPE type, 
				 joy_flow_rec_callback callback_fn)
{
    flow_record_t *rec = NULL;
    joy_ctx_data *ctx = NULL;

    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return;
    }

    /* sanity check the index value */
    if (index >= joy_num_contexts ) {
        joy_log_crit("Joy Library invalid context (%d) for packet processing!", index);
        return;
    }

    /* get the correct context */
    ctx = JOY_CTX_AT_INDEX(ctx_data,index)

    /* go through the records and let the callback function process */
    rec = ctx->flow_record_chrono_first;
    while (rec != NULL) {
        /* see if we are processing all flows or just expired flows */
        if (type == JOY_EXPIRED_FLOWS) {
            /* don't process active flow in this mode */
            if (!flow_record_is_expired(ctx,rec)) {
                break;
            }
        }

        /* see if this record has IDP information */
        if ((rec->idp_ext_processed == 0) && (rec->idp_len > 0)) {
            /* let the callback function process the flow record */
            /* IDP data is pulled directly from flow_record */
            callback_fn(rec, 0, NULL);

            /* mark the IDP data as being processed */
            rec->idp_ext_processed = 1;
        }

        /* go to next record */
        rec = rec->time_next;
    }
}

/*
 * Function: joy_tls_external_processing
 *
 * Description: This function is allows the calling application of
 *      the Joy library to handle the processing of the flow records
 *      that have TLS information ready for export.
 *      This function simply goes through the flow records and invokes
 *      the callback function to process the records that have TLS data.
 *      Records that get processed have the TLS processed flag updated
 *      but are NOT removed from the flow record list.
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
void joy_tls_external_processing(unsigned int index,
				 JOY_FLOW_TYPE type, 
				 joy_flow_rec_callback callback_fn)
{
    flow_record_t *rec = NULL;
    joy_ctx_data *ctx = NULL;

    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return;
    }

    /* sanity check the index value */
    if (index >= joy_num_contexts ) {
        joy_log_crit("Joy Library invalid context (%d) for packet processing!", index);
        return;
    }

    /* get the correct context */
    ctx = JOY_CTX_AT_INDEX(ctx_data,index)

    /* go through the records and let the callback function process */
    rec = ctx->flow_record_chrono_first;
    while (rec != NULL) {
        /* see if we are processing all flows or just expired flows */
        if (type == JOY_EXPIRED_FLOWS) {
            /* don't process active flow in this mode */
            if (!flow_record_is_expired(ctx,rec)) {
                break;
            }
        }

        /* see if this record has TLS information */
        if ((rec->tls_ext_processed == 0) &&
            (rec->tls != NULL) & (rec->tls->done_handshake)) {
            /* let the callback function process the flow record */
            /* TLS data is pulled directly from flow_record */
            callback_fn(rec, 0, NULL);

            /* mark the TLS data as being processed */
            rec->tls_ext_processed = 1;
        }

        /* go to next record */
        rec = rec->time_next;
    }
}

/*
 * Function: joy_delete_flow_records
 *
 * Description: This function is allows the calling application of
 *      the Joy library to handle the explicit deletion of flow records
 *      from the flow_record list.
 *
 * Parameters:
 *      index - index of the context to use
 *      type - JOY_EXPIRED_FLOWS or JOY_ALL_FLOWS
 *      cond - condition on which records to delete
 *             (IDP processed, TLS processed, SALT processed,
 *              SPLT processed, BD processed, ANY) 
 *
 * Returns:
 *      unsigned int - number of records deleted
 *
 */
unsigned int joy_delete_flow_records(unsigned int index,
                                     JOY_FLOW_TYPE type,
                                     JOY_COND_TYPE cond)
{
    unsigned char ok_to_delete = 0;
    unsigned int records_deleted = 0;
    flow_record_t *rec = NULL;
    flow_record_t *next_rec = NULL;
    joy_ctx_data *ctx = NULL;

    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return records_deleted;
    }

    /* sanity check the index value */
    if (index >= joy_num_contexts ) {
        joy_log_crit("Joy Library invalid context (%d) for packet processing!", index);
        return records_deleted;
    }

    /* get the correct context */
    ctx = JOY_CTX_AT_INDEX(ctx_data,index)

    /* go through the records */
    rec = ctx->flow_record_chrono_first;
    while (rec != NULL) {
        ok_to_delete = 0;
        if (type == JOY_EXPIRED_FLOWS) {
            /* don't process active flow in this mode */
            if (!flow_record_is_expired(ctx,rec)) {
                break;
            }
        }

        /* check if ok to delete this record */
        switch (cond) {
            case (JOY_IDP_PROCESSED):
                if (rec->idp_ext_processed == 1) {
                    ok_to_delete = 1;
                }
                break;
            case (JOY_TLS_PROCESSED):
                if (rec->tls_ext_processed == 1) {
                    ok_to_delete = 1;
                }
                break;
            case (JOY_SALT_PROCESSED):
                if (rec->salt_ext_processed == 1) {
                    ok_to_delete = 1;
                }
                break;
            case (JOY_SPLT_PROCESSED):
                if (rec->splt_ext_processed == 1) {
                    ok_to_delete = 1;
                }
                break;
            case (JOY_BD_PROCESSED):
                if (rec->bd_ext_processed == 1) {
                    ok_to_delete = 1;
                }
                break;
            case (JOY_ANY_PROCESSED):
                /* doesn't matter, we are forcing this record to be deleted */
                ok_to_delete = 1;
                break;
        }

        /* remove the record and advance to next record */
        next_rec = rec->time_next;
        if (ok_to_delete) {
            remove_record_and_update_list(ctx,rec);

            /* increment the delete count */
            ++records_deleted;
        }

        /* go to the next record */
        rec = next_rec;
    }

    return records_deleted;
}

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
void joy_context_cleanup(unsigned int index)
{
    joy_ctx_data *ctx = NULL;

    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return;
    }

    /* sanity check the index value */
    if (index >= joy_num_contexts ) {
        joy_log_crit("Joy Library invalid context (%d) for packet processing!", index);
        return;
    }

    /* find the context */
    ctx = JOY_CTX_AT_INDEX(ctx_data,index)

    /* Flush any unsent exporter messages in Ipfix module */
    if (glb_config->ipfix_export_port) {
        ipfix_export_flush_message(ctx);

        /* Cleanup any leftover memory, sockets, etc. in Ipfix module */
        ipfix_module_cleanup(ctx);
    }


    /* free up the flow records */
    flow_record_list_free(ctx);
 
    /* close the output file */
    zclose(ctx->output);
    free(ctx->output_file_basename);
}

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
void joy_shutdown(void)
{
    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return;
    }

    /* clean up the protocol idenitfication dictionary */
    proto_identify_cleanup();

    /* free up the memory for the contexts */
    JOY_API_FREE_CONTEXT(ctx_data)

    /* clear out the configuration structure */
    memset(&active_config, 0x00, sizeof(struct configuration));
    glb_config = NULL;

    /* reset the library initialized flag */
    joy_library_initialized = 0;
}
