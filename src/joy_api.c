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

#ifdef HAVE_CONFIG_H
#include "joy_config.h"
#endif

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

#define MAX_NFV9_SPLT_SALT_PKTS 10
#define MAX_NFV9_SPLT_SALT_ARRAY_LENGTH 40
#define MAX_BYTE_COUNT_ARRAY_LENGTH 256

/* file destination variables */
FILE *info = NULL;

/* config is the global library configuration */
struct configuration active_config;
struct configuration *glb_config = NULL;

/* global library intialization flag */
static bool joy_library_initialized = 0;

/* global data for the context configuration */
static uint8_t joy_num_contexts = 0;
static struct joy_ctx_data *ctx_data = NULL;

/*
 * Function: joy_splt_format_data
 *
 * Description: This function formats the SPLT data from a flow
 *      record into a character string ready for use by an external
 *      entity. Typically the external entity can just grab the
 *      formatted data and send it along in an IPFix or NFv9 record.
 *
 * Parameters:
 *      rec - the flow record
 *      export_frmt - format of the exported data
 *      data - pointer to the formatted data memory buffer
 *
 * Returns:
 *      formatted data length is returned
 *
 */
static unsigned int joy_splt_format_data(flow_record_t *rec,
                                         joy_export_type_e export_frmt,
                                         unsigned char *data)
{
    unsigned int i = 0;
    unsigned int entries_used = 0;
    unsigned int num_of_pkts = 0;
    unsigned int data_len = 0;
    struct timeval ts;
    uint16_t *formatted_data = (uint16_t*)data;

    /* see how many packets we have to process - max is MAX_NFV9_SPLT_SALT_PKTS */
    num_of_pkts = (rec->op < MAX_NFV9_SPLT_SALT_PKTS) ? rec->op : MAX_NFV9_SPLT_SALT_PKTS;

    /* figure out the length of the data we are formatting */
    if (export_frmt == JOY_NFV9_EXPORT) {
        /* NFv9 is always 40 bytes */
        data_len = MAX_NFV9_SPLT_SALT_ARRAY_LENGTH;
    } else {
        /* IPFix is variable length - each entry is represented by 2 16-bit values */
        data_len = num_of_pkts * 4;
    }

    /* format for Netflow v9 export */
    if (export_frmt == JOY_NFV9_EXPORT) {
        /* loop through the SPLT lengths and store appropriately */
        for (i=0; i < num_of_pkts; ++i) {
            *(formatted_data+i) = (uint16_t)rec->pkt_len[i];
        }

        if (num_of_pkts < MAX_NFV9_SPLT_SALT_PKTS) {
            /* padding needs to occur */
            for (;i < MAX_NFV9_SPLT_SALT_PKTS; ++i) {
               *(formatted_data+i) = (uint16_t)-32768;
            }
        }

        /* loop through the SPLT times and store appropriately */
        for (i=0; i < num_of_pkts; ++i) {
            if (i > 0) {
                joy_timer_sub(&rec->pkt_time[i], &rec->pkt_time[i-1], &ts);
            } else {
                joy_timer_sub(&rec->pkt_time[i], &rec->start, &ts);
            }
            *(formatted_data+MAX_NFV9_SPLT_SALT_PKTS+i) =
                 (uint16_t)joy_timeval_to_milliseconds(ts);
        }

        if (num_of_pkts < MAX_NFV9_SPLT_SALT_PKTS) {
            /* padding needs to occur */
            for (;i < MAX_NFV9_SPLT_SALT_PKTS; ++ i) {
               *(formatted_data+MAX_NFV9_SPLT_SALT_PKTS+i) = (uint16_t)0x00;
            }
        }

    /* else format for IPFix export */
    } else {
        /* loop through the SPLT lengths and store appropriately */
        for (i=0; i < num_of_pkts; ++i) {
            *(formatted_data+i) = (uint16_t)rec->pkt_len[i];
        }

        /* store how many entries we used since IPFix doesn't pad */
        entries_used = i;

        /* loop through the SPLT times and store appropriately */
        for (i=0; i < num_of_pkts; ++i) {
            if (i > 0) {
                joy_timer_sub(&rec->pkt_time[i], &rec->pkt_time[i-1], &ts);
            } else {
                joy_timer_sub(&rec->pkt_time[i], &rec->start, &ts);
            }
            *(formatted_data+entries_used+i) =
                 (uint16_t)joy_timeval_to_milliseconds(ts);
        }
    }

    /* return the formatted data */
    return data_len;
}

/*
 * Function: joy_salt_format_data
 *
 * Description: This function formats the SALT data from a flow
 *      record into a character string ready for use by an external
 *      entity. Typically the external entity can just grab the
 *      formatted data and send it along in an IPFix or NFv9 record.
 *
 * Parameters:
 *      rec - the flow record
 *      export_frmt - format of the exported data
 *      data - pointer to the formatted data memory buffer
 *
 * Returns:
 *      formatted data length is returned
 *
 */
static unsigned int joy_salt_format_data(flow_record_t *rec,
                                         joy_export_type_e export_frmt,
                                         unsigned char *data)
{
    unsigned int i = 0;
    unsigned int entries_used = 0;
    unsigned int num_of_pkts = 0;
    unsigned int data_len = 0;
    struct timeval ts;
    uint16_t *formatted_data = (uint16_t*)data;

    /* sanity check SALT structure */
    if (rec->salt == NULL) {
        joy_log_debug("No SALT data in the flow record!");
        return data_len;
    }

    /* see how many packets we have to process - max is MAX_NFV9_SPLT_SALT_PKTS */
    num_of_pkts = (rec->salt->op < MAX_NFV9_SPLT_SALT_PKTS) ? rec->salt->op : MAX_NFV9_SPLT_SALT_PKTS;

    /* figure out the length of the data we are formatting */
    if (export_frmt == JOY_NFV9_EXPORT) {
        /* NFv9 is always 40 bytes */
        data_len = MAX_NFV9_SPLT_SALT_ARRAY_LENGTH;
    } else {
        /* IPFix is variable length */
        data_len = num_of_pkts * 4;
    }

    /* format for Netflow v9 export */
    if (export_frmt == JOY_NFV9_EXPORT) {
        /* loop through the SALT lengths and store appropriately */
        for (i=0; i < num_of_pkts; ++i) {
            *(formatted_data+i) = (uint16_t)rec->salt->pkt_len[i];
        }

        /* see if we need to pad the length array */
        if (num_of_pkts < MAX_NFV9_SPLT_SALT_PKTS) {
            /* padding needs to occur */
            for (;i < MAX_NFV9_SPLT_SALT_PKTS; ++i) {
               *(formatted_data+i) = (uint16_t)0x00;
            }
        }

        /* loop through the SALT times and store appropriately */
        for (i=0; i < num_of_pkts; ++i) {
            if (i > 0) {
                joy_timer_sub(&rec->salt->pkt_time[i], &rec->salt->pkt_time[i-1], &ts);
            } else {
                joy_timer_sub(&rec->salt->pkt_time[i], &rec->start, &ts);
            }
            *(formatted_data+MAX_NFV9_SPLT_SALT_PKTS+i) =
                 (uint16_t)joy_timeval_to_milliseconds(ts);
        }

        /* see if we need to pad the time array */
        if (num_of_pkts < MAX_NFV9_SPLT_SALT_PKTS) {
            /* padding needs to occur */
            for (;i < MAX_NFV9_SPLT_SALT_PKTS; ++ i) {
               *(formatted_data+MAX_NFV9_SPLT_SALT_PKTS+i) = (uint16_t)0x00;
            }
        }

    /* format for IPFIX export */
    } else {
        /* loop through the SALT lengths and store appropriately */
        for (i=0; i < num_of_pkts; ++i) {
            *(formatted_data+i) = (uint16_t)rec->salt->pkt_len[i];
        }

        /* store how many entries we used since IPFix doesn't pad */
        entries_used = i;

        /* loop through the SALT times and store appropriately */
        for (i=0; i < num_of_pkts; ++i) {
            if (i > 0) {
                joy_timer_sub(&rec->salt->pkt_time[i], &rec->salt->pkt_time[i-1], &ts);
            } else {
                joy_timer_sub(&rec->salt->pkt_time[i], &rec->start, &ts);
            }
            *(formatted_data+entries_used+i) =
                 (uint16_t)joy_timeval_to_milliseconds(ts);
        }
    }

    /* return the formatted data */
    return data_len;
}

/*
 * Function: joy_bd_format_data
 *
 * Description: This function formats the BD data from a flow
 *      record into a character string ready for use by an external
 *      entity. Typically the external entity can just grab the
 *      formatted data and send it along in an IPFix or NFv9 record.
 *
 * Parameters:
 *      rec - the flow record
 *      data - pointer to the formatted data buffer
 *
 * Returns:
 *      formatted data length is returned
 *
 */
static unsigned int joy_bd_format_data(flow_record_t *rec, unsigned char *data)
{
    int i;
    unsigned int data_len = 0;
    uint16_t *formatted_data = (uint16_t*)data;

    /* 256 values at 16 bits each = 512 bytes */
    data_len = (MAX_BYTE_COUNT_ARRAY_LENGTH * 2);

    /* store the byte counts into the data buffer */
    for (i=0; i < MAX_BYTE_COUNT_ARRAY_LENGTH; ++i) {
        *(formatted_data+i) = (uint16_t)rec->byte_count[i];
    }

    return data_len;
}

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
        const char *output_dir, const char *output_file, const char *logfile)
{
    unsigned int i = 0;
    char output_dirname[MAX_DIRNAME_LEN];
    char output_filename[MAX_FILENAME_LEN];

    /* clear out the configuration structure */
    memset(&active_config, 0x00, sizeof(struct configuration));
    glb_config = &active_config;

    /* set 'info' to stderr as a precaution */
    info = stderr;

    /* setup the logfile */
    if (logfile != NULL) {
        info = fopen(logfile, "a");
        if (info == NULL) {
            joy_log_err("could not open log file %s (%s)", logfile, strerror(errno));
            return failure;
        }
        glb_config->logfile = strdup(logfile);
    } else {
        glb_config->logfile = strdup("stderr");
    }

    /* sanity check the context information */
    if (init_data->contexts < 1) {
        init_data->contexts = 1; /* default to 1 context thread */
    }

    /* allocate the context memory */
    JOY_API_ALLOC_CONTEXT(ctx_data, init_data->contexts)
    joy_num_contexts = init_data->contexts;

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

    glb_config->verbosity = init_data->verbosity;
    glb_config->flow_key_match_method = EXACT_MATCH;
    glb_config->num_pkts = DEFAULT_NUM_PKT_LEN;
    if ((init_data->num_pkts > 0) && (init_data->num_pkts < MAX_NUM_PKT_LEN)) {
        glb_config->num_pkts = init_data->num_pkts;
    }

    /* setup the inactive and active timeouts for a flow record */
    flow_record_update_timeouts(init_data->inact_timeout, init_data->act_timeout);

    /* setup joy with the output options */
    glb_config->outputdir = strdup(output_dirname);
    if (output_file)
        glb_config->filename = strdup(output_file);
    else
        glb_config->filename = strdup("joy-output");

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
    glb_config->report_ppi = ((init_data->bitmask & JOY_PPI_ON) ? 1 : 0);
    glb_config->report_salt = ((init_data->bitmask & JOY_SALT_ON) ? 1 : 0);

    /* check if IDP option is set */
    if (init_data->bitmask & JOY_IDP_ON) {
        glb_config->ipfix_export_template = strdup("idp");
        if (init_data->idp > 0) {
            glb_config->idp = init_data->idp;
        } else {
            glb_config->idp = DEFAULT_IDP_SIZE;
        }
    } else {
        glb_config->ipfix_export_template = strdup("simple");
        glb_config->idp = 0;
    }

    /* setup the IPFix exporter configuration */
    if (init_data->bitmask & JOY_IPFIX_EXPORT_ON) {
        if (init_data->ipfix_host != NULL) {
            glb_config->ipfix_export_remote_host =  strdup(init_data->ipfix_host);
        } else {
            /* default to the loopback address */
            glb_config->ipfix_export_remote_host = strdup("127.0.0.1");
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
        JOY_API_FREE_CONTEXT(ctx_data);
        return failure;
    }

    /* initialize all the data context structures */
    for (i=0; i < JOY_MAX_CTX_INDEX(ctx_data); ++i) {
        struct joy_ctx_data *this = JOY_CTX_AT_INDEX(ctx_data,i);

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
void joy_print_config(uint8_t index, uint8_t format)
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
    ctx = JOY_CTX_AT_INDEX(ctx_data,index);

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
int joy_anon_subnets(const char *anon_file)
{
    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return failure;
    }

    if (anon_file != NULL) {
        glb_config->anon_addrs_file = strdup(anon_file);
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
int joy_anon_http_usernames(const char *anon_http_file)
{
    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return failure;
    }

    if (anon_http_file != NULL) {
        glb_config->anon_http_file = strdup(anon_http_file);
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
int joy_update_splt_bd_params(const char *splt_filename, const char *bd_filename)
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
int joy_update_compact_bd(const char *filename)
{
    FILE *fp;
    int count = 0;
    uint16_t b_value, map_b_value;

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
		if (count >= MAX_BYTE_COUNT_ARRAY_LENGTH) {
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
int joy_label_subnets(const char *label, uint8_t type, const char *subnet_str)
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
void joy_update_ctx_global_time(uint8_t ctx_index,
                                struct timeval *new_time) {
    joy_ctx_data *ctx = NULL;

    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return;
    }

    /* sanity check the new_time */
    if (new_time == NULL) {
        joy_log_err("New Time passed in is NULL, nothing to do!");
        return;
    }

    if (ctx_index >= joy_num_contexts ) {
        joy_log_crit("Joy Library invalid context (%d) for packet processing!", ctx_index);
        return;
    }

    ctx = JOY_CTX_AT_INDEX(ctx_data,ctx_index);

    /* update the context global time */
    ctx->global_time.tv_sec = new_time->tv_sec;
    ctx->global_time.tv_usec = new_time->tv_usec;
}

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
 *
 * Returns:
 *      context - the context number the packet belongs to for JOY processing.
 *          This algorithms keeps bidirectional flows in the same context.
 *
 */
uint8_t joy_packet_to_context(const unsigned char *packet) {
    uint8_t rc = 0;
    uint8_t context = 0;
    unsigned int sum = 0;
    flow_key_t key;

    /* clear the key buffer */
    memset(&key, 0x00, sizeof(flow_key_t));

    /* get the 5-tuple key for this packet */
    rc = get_packet_5tuple_key(packet, &key);
    if (rc == 0) {
        joy_log_err("Failed to retrieve the 5-tuple key, using default context 0");
        return 0;
    }

    /* generate a nice hash to use for the 5-tuple. This calcualtion is essentially
     * a mod 257 on the sum of the 5-tuple. This algortihm also keeps client->server and
     * server->client flows in the same context.
     */
    sum += (unsigned int)key.sa.s_addr;
    sum += (unsigned int)key.da.s_addr;
    sum += (unsigned int)key.sp;
    sum += (unsigned int)key.dp;
    sum += (unsigned int)key.prot;
    sum *= 0x6B;
    sum -= (sum >> 8);
    sum &= 0xff;

    /* fit the mod 257 hash into the number of contexts configured */
    context = sum % joy_num_contexts;

    joy_log_debug("Packet goes into context (%d)", context);
    return context;
}

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
void* joy_process_packet(unsigned char *ctx_index,
                        const struct pcap_pkthdr *header,
                        const unsigned char *packet,
                        unsigned int app_data_len,
                        const unsigned char *app_data)
{
    uint64_t index = 0;
    joy_ctx_data *ctx = NULL;
    flow_record_t *record = NULL;

    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return NULL;
    }

    /* ctx_index has the int value of the data context
     * This number is between 0 and max configured contexts
     */
    index = (uint64_t)ctx_index;

    /* sanity check the index being used */
    if (index >= joy_num_contexts ) {
        joy_log_crit("Joy Library invalid context (%d) for packet processing!", (uint8_t)index);
        return NULL;
    }

    /* process the packet */
    ctx = JOY_CTX_AT_INDEX(ctx_data,index);
    record = process_packet((unsigned char*)ctx, header, packet);

    /* see if there is any app data to store */
    if ((app_data_len == 0) || (app_data == NULL)) {
        /* no data, we are done */
        return record;
    }

    /* only allow the app to store at most 100 bytes of app data in the flow record */
    if (app_data_len > 100) {
        record->joy_app_data_len = 0;
        joy_log_err("App Specific data is too large(%d bytes), not storing the information",app_data_len);
        return record;
    }

    /* now store the app data in the flow record */
    record->joy_app_data = calloc(1,app_data_len);
    if (record->joy_app_data != NULL) {
        record->joy_app_data_len = app_data_len;
        memcpy(record->joy_app_data, app_data, app_data_len);
    } else {
        record->joy_app_data_len = 0;
        joy_log_err("Couldn't allocate memory, can't store app data");
    }

    return record;
}

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
void joy_libpcap_process_packet(unsigned char *ctx_index,
                        const struct pcap_pkthdr *header,
                        const unsigned char *packet)
{
    uint64_t index = 0;
    joy_ctx_data *ctx = NULL;

    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return;
    }

    /* ctx_index has the int value of the data context
     * This number is between 0 and max configured contexts
     */
    index = (uint64_t)ctx_index;

    /* sanity check the index being used */
    if (index >= joy_num_contexts ) {
        joy_log_crit("Joy Library invalid context (%d) for packet processing!", (uint8_t)index);
        return;
    }

    ctx = JOY_CTX_AT_INDEX(ctx_data,index);
    process_packet((unsigned char*)ctx, header, packet);
}


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
void joy_print_flow_data(uint8_t index, joy_flow_type_e type)
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

    ctx = JOY_CTX_AT_INDEX(ctx_data,index);

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
void joy_export_flows_ipfix(uint8_t index, joy_flow_type_e type)
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
    ctx = JOY_CTX_AT_INDEX(ctx_data,index);
    flow_record_export_as_ipfix(ctx, type);
}

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
void joy_get_feature_counts(uint8_t index, joy_ctx_feat_count_t *feat_counts)
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

    /* report back the record counts for various features */
    ctx = JOY_CTX_AT_INDEX(ctx_data,index);
    feat_counts->idp_recs_ready = ctx->idp_recs_ready;
    feat_counts->tls_recs_ready = ctx->tls_recs_ready;
    feat_counts->splt_recs_ready = ctx->splt_recs_ready;
    feat_counts->salt_recs_ready = ctx->salt_recs_ready;
    feat_counts->bd_recs_ready = ctx->bd_recs_ready;
}

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
void joy_idp_external_processing(uint8_t index,
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
    ctx = JOY_CTX_AT_INDEX(ctx_data,index);

    /* go through the records and let the callback function process */
    rec = ctx->flow_record_chrono_first;
    while (rec != NULL) {

        /* see if this record has IDP information or is expired */
        if ((rec->idp_ext_processed == 0) &&
            ((rec->idp_len > 0) || (flow_record_is_expired(ctx,rec)))) {

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
void joy_tls_external_processing(uint8_t index,
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
    ctx = JOY_CTX_AT_INDEX(ctx_data,index);

    /* go through the records and let the callback function process */
    rec = ctx->flow_record_chrono_first;
    while (rec != NULL) {

        /* see if this record has TLS information */
        if ((rec->tls_ext_processed == 0) && (rec->tls != NULL)) {
            if (rec->tls->done_handshake) {

                /* let the callback function process the flow record */
                /* TLS data is pulled directly from flow_record */
                callback_fn(rec, 0, NULL);

                /* mark the TLS data as being processed */
                rec->tls_ext_processed = 1;
            }
        }

        /* see if the record is expired */
        if ((rec->tls_ext_processed == 0) && (flow_record_is_expired(ctx,rec))) {

            /* TLS info isn't complete or present, but the record is expired
             * let the callback function process the flow record
             * even though there isn't complete or present TLS data.
             */
            callback_fn(rec, 0, NULL);

            /* mark the TLS data as being processed */
            rec->tls_ext_processed = 1;
        }

        /* go to next record */
        rec = rec->time_next;
    }
}

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
void joy_splt_external_processing(uint8_t index,
                                 joy_export_type_e export_frmt,
                                 unsigned int min_pkts,
                                 joy_flow_rec_callback callback_fn)
{
    unsigned data_len = 0;
    unsigned char data[MAX_NFV9_SPLT_SALT_ARRAY_LENGTH];
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
    ctx = JOY_CTX_AT_INDEX(ctx_data,index);

    /* go through the records and let the callback function process */
    rec = ctx->flow_record_chrono_first;
    while (rec != NULL) {

        /* clean up the formatted data structures */
        data_len = 0;
        memset(data, 0x00, MAX_NFV9_SPLT_SALT_ARRAY_LENGTH);

        /* see if this record has SPLT information or is expired */
        if ((rec->splt_ext_processed == 0) &&
            ((rec->op >= min_pkts) || (flow_record_is_expired(ctx,rec)))) {

            /* format the SPLT data for external processing */
            data_len = joy_splt_format_data(rec, export_frmt, data);

            /* let the callback function process the flow record */
            callback_fn(rec, data_len, data);

            /* mark the SPLT data as being processed */
            rec->splt_ext_processed = 1;
        }

        /* go to next record */
        rec = rec->time_next;
    }
}

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
void joy_salt_external_processing(uint8_t index,
                                 joy_export_type_e export_frmt,
                                 unsigned int min_pkts,
                                 joy_flow_rec_callback callback_fn)
{
    unsigned data_len = 0;
    unsigned char data[MAX_NFV9_SPLT_SALT_ARRAY_LENGTH];
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
    ctx = JOY_CTX_AT_INDEX(ctx_data,index);

    /* go through the records and let the callback function process */
    rec = ctx->flow_record_chrono_first;
    while (rec != NULL) {

        /* clean up the formatted data structures */
        data_len = 0;
        memset(data, 0x00, MAX_NFV9_SPLT_SALT_ARRAY_LENGTH);

        /* see if this record has SALT information */
        if ((rec->salt_ext_processed == 0) && (rec->salt != NULL)) {
            if (rec->salt->np >= min_pkts) {

                /* format the SALT data for external processing */
                data_len = joy_salt_format_data(rec, export_frmt, data);

                /* let the callback function process the flow record */
                callback_fn(rec, data_len, data);

                /* mark the SALT data as being processed */
                rec->salt_ext_processed = 1;
            }
        }

        /* see if the record is expired */
        if ((rec->salt_ext_processed == 0) && (flow_record_is_expired(ctx,rec))) {

            /* format the SALT data for external processing */
            data_len = joy_salt_format_data(rec, export_frmt, data);

            /* SALT info isn't complete, but the record is expired
             * let the callback function process the flow record
             * even though there isn't complete SALT data.
             */
            callback_fn(rec, data_len, data);

            /* mark the SALT data as being processed */
            rec->salt_ext_processed = 1;
        }

        /* go to next record */
        rec = rec->time_next;
    }
}

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
 *      min_octets - minimum number of octets processed before export occurs
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
 *      Once control returns from the callback function, the library will handle that
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
void joy_bd_external_processing(uint8_t index,
                                unsigned int min_octets,
                                joy_flow_rec_callback callback_fn)
{
    unsigned data_len = 0;
    unsigned char data[MAX_BYTE_COUNT_ARRAY_LENGTH*2];
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
    ctx = JOY_CTX_AT_INDEX(ctx_data,index);

    /* go through the records and let the callback function process */
    rec = ctx->flow_record_chrono_first;
    while (rec != NULL) {

        /* clean up the formatted data structures */
        data_len = 0;
        memset(data, 0x00, (MAX_BYTE_COUNT_ARRAY_LENGTH*2));

        /* see if this record has BD information or is expired */
        if ((rec->bd_ext_processed == 0) &&
            ((rec->ob >= min_octets) || (flow_record_is_expired(ctx,rec)))) {
            /* format the BD data for external processing */
            data_len = joy_bd_format_data(rec, data);

            /* let the callback function process the flow record */
            callback_fn(rec, data_len, data);

            /* mark the BD data as being processed */
            rec->bd_ext_processed = 1;
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
 *      cond_bitmask - bitmask of conditions on which records to delete
 *             (JOY_IDP_PROCESSED, JOY_TLS_PROCESSED, JOY_SALT_PROCESSED,
 *              JOY_SPLT_PROCESSED, JOY_BD_PROCESSED, JOY_ANY_PROCESSED)
 *
 * Returns:
 *      unsigned int - number of records deleted
 *
 */
unsigned int joy_delete_flow_records(uint8_t index,
                                     unsigned int cond_bitmask)
{
    uint8_t ok_to_delete = 0;
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
    ctx = JOY_CTX_AT_INDEX(ctx_data,index);

    /* go through the records */
    rec = ctx->flow_record_chrono_first;
    while (rec != NULL) {
        /* figure out what has been procssed in this record */
        ok_to_delete = 0;
        if (rec->idp_ext_processed == 1) {
            ok_to_delete |= JOY_IDP_PROCESSED;
        }
        if (rec->tls_ext_processed == 1) {
            ok_to_delete |= JOY_TLS_PROCESSED;
        }
        if (rec->salt_ext_processed == 1) {
            ok_to_delete |= JOY_SALT_PROCESSED;
        }
        if (rec->splt_ext_processed == 1) {
            ok_to_delete |= JOY_SPLT_PROCESSED;
        }
        if (rec->bd_ext_processed == 1) {
            ok_to_delete |= JOY_BD_PROCESSED;
        }

        /* remove the record and advance to next record */
        next_rec = rec->time_next;
        /* see if cond flags are set */
        if ((ok_to_delete & cond_bitmask) == cond_bitmask) {
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
extern unsigned int joy_purge_old_flow_records(uint8_t index,
                                               unsigned int rec_age)
{
    unsigned int ok_to_delete = 0;
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
    ctx = JOY_CTX_AT_INDEX(ctx_data,index);

    /* go through the records */
    rec = ctx->flow_record_chrono_first;
    while (rec != NULL) {

        /* Check the record only to see if it's expired (no new packet) */
        ok_to_delete = 0;
        if (rec->end.tv_sec > (rec->start.tv_sec + rec_age)) {
            if ((rec->twin == NULL) || (rec->end.tv_sec > (rec->twin->start.tv_sec + rec_age))) {
                ok_to_delete = 1;
            }
        }

        /* remove the record and advance to next record */
        next_rec = rec->time_next;
        /* see if cond flags are set */
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
void joy_context_cleanup(uint8_t index)
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
    ctx = JOY_CTX_AT_INDEX(ctx_data,index);

    /* Flush any unsent exporter messages in Ipfix module */
    if (glb_config->ipfix_export_port) {
        ipfix_export_flush_message(ctx);

        /* Cleanup any leftover memory, sockets, etc. in Ipfix module */
        ipfix_module_cleanup(ctx);
    }


    /* free up the flow records */
    flow_record_list_free(ctx);
 
    /* close the output file */
    if (ctx->output) {
        zclose(ctx->output);
        ctx->output = NULL;
    }
    if (ctx->output_file_basename) {
        free(ctx->output_file_basename);
        ctx->output_file_basename = NULL;
    }
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
    unsigned int i = 0;

    /* check library initialization */
    if (!joy_library_initialized) {
        joy_log_crit("Joy Library has not been initialized!");
        return;
    }

    /* clean up the protocol idenitfication dictionary */
    proto_identify_cleanup();

    /* cleanup all the data context structures */
    for (i=0; i < joy_num_contexts; ++i) {
        joy_context_cleanup(i);
    }

    /* free up the memory for the contexts */
    JOY_API_FREE_CONTEXT(ctx_data)

    /* free up the strings in the global config */
    if (glb_config->compact_byte_distribution) free((void*)glb_config->compact_byte_distribution);
    if (glb_config->intface) free((void*)glb_config->intface);
    if (glb_config->filename) free((void*)glb_config->filename);
    if (glb_config->outputdir) free((void*)glb_config->outputdir);
    if (glb_config->username) free((void*)glb_config->username);
    if (glb_config->logfile) free((void*)glb_config->logfile);
    if (glb_config->anon_addrs_file) free((void*)glb_config->anon_addrs_file);
    if (glb_config->anon_http_file) free((void*)glb_config->anon_http_file);
    if (glb_config->upload_servername) free((void*)glb_config->upload_servername);
    if (glb_config->upload_key) free((void*)glb_config->upload_key);
    if (glb_config->params_url) free((void*)glb_config->params_url);
    if (glb_config->params_file) free((void*)glb_config->params_file);
    if (glb_config->label_url) free((void*)glb_config->label_url);
    if (glb_config->bpf_filter_exp) free((void*)glb_config->bpf_filter_exp);
    if (glb_config->ipfix_export_remote_host) free((void*)glb_config->ipfix_export_remote_host);
    if (glb_config->ipfix_export_template) free((void*)glb_config->ipfix_export_template);
    if (glb_config->aux_resource_path) free((void*)glb_config->aux_resource_path);

    /* free up the subnet labels if we have any */
    for (i=0; i < glb_config->num_subnets; ++i)
    {
        if (glb_config->subnet[i])
            free((void*)glb_config->subnet[i]);
    }

    /* clean up the radix trie if present */
    if (glb_config->rt) radix_trie_free(glb_config->rt);

    /* clean up the anonymous username context if present */
    anon_http_ctx_cleanup();

    /* clear out the configuration structure */
    memset(&active_config, 0x00, sizeof(struct configuration));
    glb_config = NULL;

    /* reset the library initialized flag */
    joy_library_initialized = 0;
}

#ifdef HAVE_CONFIG_H
/*! @brief joy_get_version version for joy.
 *  @return joy version string.
 */
const char * joy_get_version(void) {
    return(PACKAGE_STRING);
}
#endif
