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

#ifndef CONFIG_H
#define CONFIG_H

#include "output.h"
#include "radix_trie.h"

#define LINEMAX 256

#define NULL_KEYWORD "none"


struct configuration {
  unsigned int bidir;
  unsigned int include_zeroes;
  unsigned int byte_distribution;
  unsigned int report_entropy;
  unsigned int report_wht;
  unsigned int report_hd;
  unsigned int report_exe;
  unsigned int include_tls;
  unsigned int include_classifier;
  unsigned int idp;
  unsigned int dns;
  unsigned int http;
  unsigned int promisc;
  unsigned int daemon;
  unsigned int num_pkts;
  unsigned int type;           /* 1=SPLT, 2=SALT */
  unsigned int retain_local;
  unsigned int max_records;
  unsigned int output_level;
  unsigned int nfv9_capture_port;
  unsigned int flow_key_match_method;
  char *compact_byte_distribution;
  char *interface;
  char *filename;              /* output file, if not NULL */
  char *outputdir;             /* directory to write output files */
  char *logfile; 
  char *anon_addrs_file;
  char *anon_http_file;
  char *upload_servername;
  char *upload_key;
  char *params_file;
  char *bpf_filter_exp;
  char *subnet[MAX_NUM_FLAGS]; /* max defined in radix_trie.h    */
  unsigned int num_subnets;    /* counts entries in subnet array */
};


void config_set_defaults(struct configuration *config);

int config_set_from_file(struct configuration *config, const char *fname);

int config_set_from_argv(struct configuration *config, char *argv[], int argc);

void config_print(FILE *f, const struct configuration *c);

void config_print_json(zfile f, const struct configuration *c);

#endif /* CONFIG_H */
