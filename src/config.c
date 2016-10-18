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
 * \file config.c
 *
 * \brief implementation for the configuration system
 *
 */
#include <stdlib.h>       
#include <limits.h>
#include <ctype.h> 
#include <string.h> 
#include "err.h"
#include "anon.h"
#include "config.h"
#include "radix_trie.h"
#include "hdr_dsc.h" 
#include "p2f.h" 

/** returns if two string are the same */
#define match(c, x) (!strncmp(c, x, strlen(x)))

/* parses an integer value */
static int parse_int (unsigned int *x, const char *arg, int num_arg, int min, int max) {
    const char *c = arg;

    if (x == NULL) {
        return failure;
    }

    if (num_arg == 2) {
        if (arg == NULL) {
            return failure;
        }
        while (*c != 0) {
            if (!isdigit(*c)) {
	              printf("error: argument %s must be a number ", arg);
	              return failure;
            }
            c++;
        }
        *x = atoi(arg);
        if (*x < min || *x > max) {
            printf("error: value must be between %d and %d ", min, max);
            return failure;
        }
    } else {
        return failure;
    }
    return ok;
}

/* parses a boolean value */
static int parse_bool (unsigned int *x, const char *arg, int num_arg) {
    if (num_arg == 1) {
        arg = "1";
        num_arg = 2;
    }
    return parse_int(x, arg, num_arg, 0, 1);
}

/*parses a string values */
static int parse_string (char **s, char *arg, int num_arg) {
    if (s == NULL || arg == NULL || num_arg != 2) {
        return failure;
    }
  
    if (strncmp(arg, NULL_KEYWORD, strlen(NULL_KEYWORD)) == 0) {
        *s = NULL;
    } else {
        *s = strdup(arg); /* note: must be freed later */
    }
    return ok;
}

/* parses mutliple part string values */
static int parse_string_multiple (char **s, char *arg, int num_arg, 
           unsigned int string_num, unsigned int string_num_max) {
    if (s == NULL) {
        return failure;
    }
    if (string_num >= string_num_max) {
        return failure;
    }
    return parse_string(&s[string_num], arg, num_arg);
}

/* see if parse checks are ok */
#define parse_check(s) if ((s)) {                   \
   fprintf(info, "error in command %s\n", command); \
   return failure;                                  \
  } else {                                          \
  return ok;                                        \
}


/* parse commands */
static int config_parse_command (struct configuration *config, 
			 const char *command, char *arg, int num) {  
    char *tmp;
  
    /* remove trailing whitespace from argument */
    tmp = arg + strnlen(arg, LINEMAX) - 1;
    while (isblank(*tmp)) {
        *tmp = 0;
        tmp--;
    }
  
    /*
     * note: because of the simplistic match function currently
     * implemented, each command name MUST NOT be a prefix of any other
     * command name; otherwise, the shorter name will be matched rather
     * than the longer one
     */

    if (match(command, "interface")) {
        parse_check(parse_string(&config->interface, arg, num));

    } else if (match(command, "promisc")) {
        parse_check(parse_bool(&config->promisc, arg, num));

    } else if (match(command, "daemon")) {
        parse_check(parse_bool(&config->daemon, arg, num));

    } else if (match(command, "output")) {
        parse_check(parse_string(&config->filename, arg, num));

    } else if (match(command, "outdir")) {
        parse_check(parse_string(&config->outputdir, arg, num));

    } else if (match(command, "log")) {
        parse_check(parse_string(&config->logfile, arg, num));

    } else if (match(command, "upload")) {
        parse_check(parse_string(&config->upload_servername, arg, num));

    } else if (match(command, "keyfile")) {
        parse_check(parse_string(&config->upload_key, arg, num));

    } else if (match(command, "model")) {
        parse_check(parse_string(&config->params_file, arg, num));

    } else if (match(command, "label")) {
        parse_check(parse_string_multiple(config->subnet, arg, num, config->num_subnets++, MAX_NUM_FLAGS));

    } else if (match(command, "retain")) {
        parse_check(parse_bool(&config->retain_local, arg, num));

    } else if (match(command, "zeros")) {
        parse_check(parse_bool(&config->include_zeroes, arg, num));

    } else if (match(command, "bidir")) {
        parse_check(parse_bool(&config->bidir, arg, num));

    } else if (match(command, "dist")) {
        parse_check(parse_bool(&config->byte_distribution, arg, num));

    } else if (match(command, "cdist")) {
        parse_check(parse_string(&config->compact_byte_distribution, arg, num));

    } else if (match(command, "entropy")) {
        parse_check(parse_bool(&config->report_entropy, arg, num));

    } else if (match(command, "hd")) {
        parse_check(parse_int(&config->report_hd, arg, num, 0, HDR_DSC_LEN));

    } else if (match(command, "tls")) {
        parse_check(parse_bool(&config->include_tls, arg, num));

    } else if (match(command, "classify")) {
        parse_check(parse_bool(&config->include_classifier, arg, num));

    } else if (match(command, "bpf")) {
        parse_check(parse_string(&config->bpf_filter_exp, arg, num));

    } else if (match(command, "verbosity")) {
        parse_check(parse_int(&config->output_level, arg, num, 0, 3));

    } else if (match(command, "num_pkts")) {
        parse_check(parse_int(&config->num_pkts, arg, num, 0, MAX_NUM_PKT_LEN));

    } else if (match(command, "type")) {
        parse_check(parse_int(&config->type, arg, num, 1, 2));
  
    } else if (match(command, "count")) {
        parse_check(parse_int(&config->max_records, arg, num, 1, INT_MAX));

    } else if (match(command, "idp")) {
        parse_check(parse_int(&config->idp, arg, num, 0, MAX_IDP));

    } else if (match(command, "nfv9_port")) {
        parse_check(parse_int(&config->nfv9_capture_port, arg, num, 0, 0xffff));

    } else if (match(command, "nat")) {
        parse_check(parse_bool(&config->flow_key_match_method, arg, num));

    } else if (match(command, "http")) {
        parse_check(parse_bool(&config->http, arg, num));

    } else if (match(command, "anon")) {
        parse_check(parse_string(&config->anon_addrs_file, arg, num));

    } else if (match(command, "useranon")) {
        parse_check(parse_string(&config->anon_http_file, arg, num));

    } else if (match(command, "exe")) {
        parse_check(parse_bool(&config->report_exe, arg, num));

    }

    config_all_features_bool(feature_list);

    return failure;
}

/**
 * \fn void config_set_defaults (struct configuration *config)
 * \param config pointer to configuration structure
 * \return none
 */
void config_set_defaults (struct configuration *config) {
    config->type = 1;
}

/**
 * \fn void config_set_from_file (struct configuration *config, const char *fname)
 * \param config pointer to configuration structure
 * \param fname file with configuration items in it
 * \return ok
 * \return failure
 */
int config_set_from_file (struct configuration *config, const char *fname) {
    FILE *f;
    char *line = NULL;
    size_t ignore;
    ssize_t len;
    unsigned int linecount = 0;
    char *c;

    f = fopen(fname, "r");
    if (f == NULL) {
        fprintf(info, "error: could not open file %s\n", fname);
        return failure;
    } 

    config_set_defaults(config);

    while ((len = getline(&line, &ignore, f)) != -1) {
        int num;
        char lhs[LINEMAX], rhs[LINEMAX];

        linecount++;
        if (len > LINEMAX) {
            fprintf(info, "error: line too long in file %s\n", fname);
            return failure;
        }

        /* ignore blank lines and comments */
        c = line;
        while (isblank(*c)) {
            c++;
        }
        if (*c == '#' || *c == '\n') {
            ;
        } else {
            /*
             * a valid command line consists of a LHS, possibly followed by
             * an "=" and a RHS.  The newline and # (start of comment) is
             * not part of the RHS.
             */
            num = sscanf(line, "%[^=] = %[^\n#]", lhs, rhs);
            if (num == 2 || num == 1) {
	               // printf("%s = %s ### %d ### %s", lhs, rhs, num, line);
	               if (config_parse_command(config, lhs, rhs, num) != ok) {
	                   fprintf(info, "error: unknown command (%s)\n", lhs);
	                   exit(EXIT_FAILURE);
	               }
            } else if (num == 1) {
	               printf("error: could not parse line %u in file %s (\"%s ...\")\n", 
		                      linecount, fname, lhs);
	               exit(EXIT_FAILURE);
            } else {
	               printf("error: could not parse line %s in file %s\n", line, fname);
	               fprintf(info, "error: could not parse line %s in file %s\n", 
		                             line, fname);
            }
        }
    }
    free(line);
    return ok;
}

/**
 * \fn int config_set_from_argv (struct configuration *config, char *argv[], int argc)
 * \param config pointer to configuration structure
 * \param argv arguments passed in
 * \param argc number of arguments
 * \return ok
 * \return failure
 */
int config_set_from_argv (struct configuration *config, char *argv[], int argc) {
    const char *line = NULL;
    ssize_t len;
    unsigned int i, linecount = 0;
    const char *c;

    config_set_defaults(config);

    for (i=1; i<argc; i++) {
        int num;
        char lhs[LINEMAX], rhs[LINEMAX];

        line = argv[i];
        len = strlen(line);

        linecount++;
        if (len > LINEMAX) {
            fprintf(info, "error: line too long in argument %s\n", argv[i]);
            return failure;
        }

        /* ignore blank lines and comments */
        c = line;
        while (isblank(*c)) {
            c++;
        }
        if (*c == '#' || *c == '\n') {
            ;
        } else {
            /*
             * a valid command line consists of a LHS, possibly followed by
             * an "=" and a RHS.  The newline and # (start of comment) is
             * not part of the RHS.
             */
            num = sscanf(line, "%[^=] = %[^\n#]", lhs, rhs);
            if (num == 2) {
	              // printf("%s = %s ### %d ### %s", lhs, rhs, num, line);
	              if (config_parse_command(config, lhs, rhs, num) != ok) {
	                  printf("error: did not understand command %s\n", lhs);
	                  exit(EXIT_FAILURE);
	                  //	  break;
	              }
            } else if (num == 1) {
	              /* 
	               * since there is no "=" in argument, we assume that it is a
	               * filename
	               */
	              break;	
            } else {
	              printf("error: could not parse argument %s\n", line);
            }
        }
    }
    return i-1;
}

/** determine if we have avlue or not */
#define val(x) x ? x : NULL_KEYWORD 

/**
 * \fn void config_print (FILE *f, const struct configuration *c)
 * \param f file to print configuration to
 * \param c pointer to the configuration structure
 * \return none
 */
void config_print (FILE *f, const struct configuration *c) {
    unsigned int i;

    fprintf(f, "interface = %s\n", val(c->interface));
    fprintf(f, "promisc = %u\n", c->promisc);
    fprintf(f, "daemon = %u\n", c->daemon);
    fprintf(f, "output = %s\n", val(c->filename));
    fprintf(f, "outputdir = %s\n", val(c->outputdir));
    fprintf(f, "count = %u\n", c->max_records); 
    fprintf(f, "upload = %s\n", val(c->upload_servername));
    fprintf(f, "keyfile = %s\n", val(c->upload_key));
    for (i=0; i<c->num_subnets; i++) {
        fprintf(f, "label=%s\n", c->subnet[i]);
    }
    fprintf(f, "retain = %u\n", c->retain_local);
    fprintf(f, "bidir = %u\n", c->bidir);
    fprintf(f, "num_pkts = %u\n", c->num_pkts);
    fprintf(f, "type = %u\n", c->type);
    fprintf(f, "zeros = %u\n", c->include_zeroes);
    fprintf(f, "dist = %u\n", c->byte_distribution);
    fprintf(f, "cdist = %s\n", val(c->compact_byte_distribution));
    fprintf(f, "entropy = %u\n", c->report_entropy);
    fprintf(f, "hd = %u\n", c->report_hd);
    fprintf(f, "tls = %u\n", c->include_tls);
    fprintf(f, "classify = %u\n", c->include_classifier);
    fprintf(f, "idp = %u\n", c->idp);
    fprintf(f, "exe = %u\n", c->report_exe);
    fprintf(f, "anon = %s\n", val(c->anon_addrs_file));
    fprintf(f, "useranon = %s\n", val(c->anon_http_file));
    fprintf(f, "bpf = %s\n", val(c->bpf_filter_exp));
    fprintf(f, "verbosity = %u\n", c->output_level);

    config_print_all_features_bool(feature_list);
  
    /* note: anon_print_subnets is silent when no subnets are configured */
    anon_print_subnets(f);
}

/**
 * \fn void config_print_json (zfile f, const struct configuration *c)
 * \param f file to print configuration to
 * \param c pointer to the configuration structure
 * \return none
 */
void config_print_json (zfile f, const struct configuration *c) {
    unsigned int i;

    zprintf(f, "{\"version\":\"%s\",", VERSION);
    zprintf(f, "\"interface\":\"%s\",", val(c->interface));
    zprintf(f, "\"promisc\":%u,", c->promisc);
    zprintf(f, "\"daemon\":%u,", c->daemon);
    zprintf(f, "\"output\":\"%s\",", val(c->filename));
    zprintf(f, "\"outputdir\":\"%s\",", val(c->outputdir));
    zprintf(f, "\"info\":\"%s\",", val(c->logfile));
    zprintf(f, "\"count\":%u,", c->max_records); 
    zprintf(f, "\"upload\":\"%s\",", val(c->upload_servername));
    zprintf(f, "\"keyfile\":\"%s\",", val(c->upload_key));
    for (i=0; i<c->num_subnets; i++) {
        zprintf(f, "\"label\":\"%s\",", c->subnet[i]);
    }
    zprintf(f, "\"retain\":%u,", c->retain_local);
    zprintf(f, "\"bidir\":%u,", c->bidir);
    zprintf(f, "\"num_pkts\":%u,", c->num_pkts);
    zprintf(f, "\"type\":%u,", c->type);
    zprintf(f, "\"zeros\":%u,", c->include_zeroes);
    zprintf(f, "\"dist\":%u,", c->byte_distribution);
    zprintf(f, "\"cdist\":\"%s\",", val(c->compact_byte_distribution));
    zprintf(f, "\"entropy\":%u,", c->report_entropy);
    zprintf(f, "\"hd\":%u,", c->report_hd);
    zprintf(f, "\"tls\":%u,", c->include_tls);
    zprintf(f, "\"classify\":%u,", c->include_classifier);
    zprintf(f, "\"idp\":%u,", c->idp);
    zprintf(f, "\"exe\":%u,", c->report_exe);
    zprintf(f, "\"anon\":\"%s\",", val(c->anon_addrs_file));
    zprintf(f, "\"useranon\":\"%s\",", val(c->anon_http_file));
    zprintf(f, "\"bpf\":\"%s\",", val(c->bpf_filter_exp));

    config_print_json_all_features_bool(feature_list);

    zprintf(f, "\"verbosity\":%u", c->output_level);

    zprintf(f, "}\n");  
}
