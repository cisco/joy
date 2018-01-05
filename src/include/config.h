/*
 *	
 * Copyright (c) 2016 Cisco Systems, Inc.
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
 * \file config.h
 *
 * \brief interface for configuration 
 *
 */

#ifndef CONFIG_H
#define CONFIG_H

#ifdef WIN32
#include "win_types.h"
#endif

#include "output.h"
#include "radix_trie.h"
#include "feature.h"

/** maximum line length */
#define LINEMAX 512

#define NULL_KEYWORD "none"

/** structure for the configuration parameters */
struct configuration {
    unsigned int bidir;
    unsigned int include_zeroes;
    unsigned int include_retrans;
    unsigned int byte_distribution;
    unsigned int report_entropy;
    unsigned int report_hd;
    unsigned int report_exe;
    unsigned int include_classifier;
    unsigned int idp;
    unsigned int promisc;
    unsigned int num_pkts;
    unsigned int type;           /*!< 1=SPLT, 2=SALT */
    unsigned int retain_local;
    unsigned int max_records;
    unsigned int nfv9_capture_port;
    unsigned int ipfix_collect_port;
    unsigned int ipfix_collect_online;
    unsigned int ipfix_export_port;
    unsigned int ipfix_export_remote_port;
    unsigned int flow_key_match_method;
    unsigned int preemptive_timeout;
    unsigned int verbosity;
    unsigned int show_config;
    unsigned int show_interfaces;
  
    declare_all_features_config_uint(feature_list) 
  
    char *compact_byte_distribution;
    char *intface;
    char *filename;              /*!< output file, if not NULL */
    char *outputdir;             /*!< directory to write output files */
    char *username;              /*!< username to become when dropping root */
    char *logfile; 
    char *anon_addrs_file;
    char *anon_http_file;
    char *upload_servername;
    char *upload_key;
    char *params_url;
    char *params_file;
    char *label_url;
    char *bpf_filter_exp;
    char *subnet[MAX_NUM_FLAGS]; /*!< max defined in radix_trie.h    */
    char *ipfix_export_remote_host;
    char *ipfix_export_template;
    char *aux_resource_path;
    unsigned int num_subnets;    /*!< counts entries in subnet array */
};


/** set the defaults for the joy open source */
void config_set_defaults(struct configuration *config);

/** set the configuration items from a file */
int config_set_from_file(struct configuration *config, const char *fname);

/** set the configuration items from command line arguments */
int config_set_from_argv(struct configuration *config, char *argv[], int argc);

/** print out the configuration */
void config_print(FILE *f, const struct configuration *c);

/** print out the configuration in JSON format */
void config_print_json(zfile f, const struct configuration *c);

#endif /* CONFIG_H */
