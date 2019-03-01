/*
 *	
 * Copyright (c) 2016-2019 Cisco Systems, Inc.
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

#include <stdbool.h>

#ifdef WIN32
#include "win_types.h"
#endif

#include "output.h"
#include "radix_trie.h"
#include "feature.h"

/** maximum line length */
#define LINEMAX 512
#define COMPACT_BD_MAP_MAX 16

#define NULL_KEYWORD "none"
#define NULL_KEYWORD_LEN 4
 
enum SALT_algorithm {
  raw = 0,
  aggregated = 1,
  defragmented = 2,
  rle = 3
};

/** structure for the configuration parameters */
typedef struct configuration {
    bool bidir;
    bool include_zeroes;
    bool include_retrans;
    bool byte_distribution;
    bool report_entropy;
    bool report_exe;
    bool include_classifier;
    bool promisc;

    bool retain_local;
    bool ipfix_collect_online;
    bool flow_key_match_method;
    bool show_config;
    bool show_interfaces;
    bool preemptive_timeout;
    enum SALT_algorithm salt_algo;

    uint8_t report_hd;
    uint8_t num_pkts;

    uint8_t verbosity;
    uint8_t num_subnets;               /*!< counts entries in subnet array */
    uint16_t ipfix_export_remote_port;


    uint16_t idp;
    uint16_t nfv9_capture_port;
    uint16_t ipfix_collect_port;
    uint16_t ipfix_export_port;

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
    char *params_file;
    char *bpf_filter_exp;
    char *subnet[MAX_NUM_FLAGS]; /*!< max defined in radix_trie.h    */
    char *ipfix_export_remote_host;
    char *ipfix_export_template;
    char *aux_resource_path;

    bool updater_on;
    uint8_t num_threads;
    uint32_t max_records;
    uint16_t compact_bd_mapping[COMPACT_BD_MAP_MAX];

    radix_trie_t rt;
} configuration_t;


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

extern struct configuration *glb_config;
#endif /* CONFIG_H */
