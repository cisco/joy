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
 * \file jfd-anon.c
 * 
 * \brief json flow data anonymization tool
 * 
 ** \verbatim
  jfd-anon [ -c | -r ] datafile [ -k <keyfile> ] [ -u <userfile> ] [ -s <subnetfile> ]
     datafile is the data to be (de)anonymized
     <keyfile> is the key to be used in (de)anonymization
     <userfile> is the set of usernames to be anonymized
     <subnetfile> is the set of subnets to be anonymized
 \endverbatim
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>  
#include "anon.h"
#include "radix_trie.h" 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern str_match_ctx  usernames_ctx;

static char *address_string_anonymize (char *addr_string) {
    struct in_addr addr;
    int l;

    l = strnlen(addr_string, 256);
    if (l >= 32) {
        return addr_string;  /* probably already anonymized */
    }

    if (inet_aton(addr_string, &addr) == 0) {
        return NULL;
    }
    if (ipv4_addr_needs_anonymization(&addr)) {
        return addr_get_anon_hexstring(&addr);
    }
    return addr_string;
}

static void anon_addresses (char *line) {
    char *addr;
    char addr_string[256];

    addr = strstr(line, "\"sa\":");
    if (addr) {
        sscanf(addr + 7, "%[a-fA-F0-9.]", addr_string);
        printf("\t\t\t\"sa\": \"%s\",\n", address_string_anonymize(addr_string));
        //      printf("%s", addr);
    } else {
        addr = strstr(line, "\"da\":");
        if (addr) {
            sscanf(addr + 7, "%[a-fA-F0-9.]", addr_string);
            printf("\t\t\t\"da\": \"%s\",\n", address_string_anonymize(addr_string));
            //      printf("%s", addr);
        } else {
            printf("%s", line);
        }
    }   
}

static void check_anon_addresses (char *line) {
    char *addr;
    char addr_string[256];
    char *retval;

    addr = strstr(line, "\"sa\":");
    if (addr) {
        sscanf(addr + 7, "%[a-fA-F0-9.]", addr_string);
    
        retval =  address_string_anonymize(addr_string);
        if (retval && retval != addr_string) {
            printf("sa needs anonymization: %s\t%s\n", addr_string, retval);
        }
    } else {
        addr = strstr(line, "\"da\":");
        if (addr) {
            sscanf(addr + 7, "%[a-fA-F0-9.]", addr_string);
            retval =  address_string_anonymize(addr_string);
            if (retval && retval != addr_string) {
	              printf("da needs anonymization: %s\t%s\n", addr_string, retval);
            }
        }   
    }
}

static void matches_print (struct matches *matches, char *text) {
    unsigned int i;
    char tmp[1024];

    // printf("matches->count: %d\n", matches->count);
    for (i=0; i < matches->count; i++) {
        size_t len = matches->stop[i] - matches->start[i] + 1;
        if (len > 1024) {
            return;
        }
        memcpy(tmp, text + matches->start[i], len);
        tmp[len] = 0;
        printf("\tmatch %d: %s\n", i, tmp);
    }
}


static int usage (char *name) {
    fprintf(stderr, "usage:\n%s [-c|-r] [<dfile>][-u <ufile>][-s <sfile>][-k <kfile>]\n", name);
    fprintf(stderr, "where:\n"
	        "   <dfile> contains the data to be (de)anonymized; if omitted,\n"
	        "   the data will be read from stdin\n\n"
	        "   <ufile> contains the set of usernames to be (de)anonymized,\n"
	        "   one username per line of the file\n\n"
	        "   <sfile> contains the set of subnets to be anonymized, one\n"
	        "   subnet per line in CIDR (W.X.Y.Z/M) notation\n\n"
	        "   <kfile> contains the key to be used in (de)anonymization; if\n"
	        "   omitted, the file %s will be used\n\n" 
	        "   -r causes anonymization to be removed\n\n"
	        "   -c checks to see if anonymization is needed (but does not perform it)\n\n",
	        ANON_KEYFILE_DEFAULT);
    return 1;
}

enum type {
    null_type = 0,
    addresses = 1,
    strings   = 2
};

/*
 * getopt() external variables
 */
extern char *optarg;
extern int optind, opterr, optopt;


/**
 \fn int main (int argc, char *argv[])
 \brief main entry point for jfd-anon
 \param argc command line argument count
 \param argv command line arguments
 \return 1 usage
 \return EXIT_FAILURE
 \return 0 success
 */
int main (int argc, char *argv[]) {
    ssize_t bytes_read;
    size_t len;
    char *line = NULL;  
    enum status err;
    char *keyfile = ANON_KEYFILE_DEFAULT;
    char *userfile = NULL;
    char *subnetfile = NULL;
    char *datafile = NULL;
    FILE *input;
    enum anon_mode mode = mode_anonymize;
    enum type type = null_type;
    int opt;
    unsigned int linenum = 0;

    /*
     * obtain options from command line
     */
    while ((opt = getopt(argc, argv, "crk:u:s:")) != -1) {
        switch (opt) {
            case 'c':
                mode = mode_check;
                break;
            case 'r':
                mode = mode_deanonymize;
                break;
            case 'k':
                keyfile = optarg;
                break;
            case 'u':
                userfile = optarg;
                type = strings;
                break;
            case 's':
                subnetfile = optarg;
                type = addresses;
                break;
            default: 
                return usage(argv[0]);
        }
    }

    if (mode == null_mode || type == null_type) {
        return usage(argv[0]);
    }

    if (argc > optind + 1) {
        fprintf(stderr, "error: too many non-option arguments\n");
        return usage(argv[0]);
    }
    if (optind < argc) {
        datafile = argv[optind];
    }

    if (subnetfile) {
        err = anon_init(subnetfile, stderr);
        if (err) {
            fprintf(stderr, "error: could not initialize address anonymization from file %s\n",
	              subnetfile);
            return EXIT_FAILURE;
        }
    }

    if (userfile) {
        err = anon_http_init(userfile, stderr, mode, keyfile);
        if (err) {
            fprintf(stderr, "error: could not initialize username anonymization from file %s\n",
	              userfile);
            return EXIT_FAILURE;
        }
    }

    if (datafile) {
        input = fopen(datafile, "r");
        if (input == NULL) {
            fprintf(stderr, "error: could not read from file %s\n", datafile);
            return EXIT_FAILURE;
        }
    } else {
        input = stdin;
    }

    //  printf("mode: %u\n", mode);

    /*
     * read and then process each line of input
     */
    while ((bytes_read = getline(&line, &len, input)) != -1) {
  
#if 0
        unsigned int i;
        char *text;
        char lhs[256];

        /* remove leading whitespace */
        i = 0;
        text = line;
        while (isblank(*text) && (i < len)) { 
            text++;
            i++;
        } 

#if 0
        if (*text == '{') {
            printf("{");
        } else if (*text == '}') {
            printf("}");
        }
#endif

        if (sscanf(text, "%[\"a-zA-Z_{}]", lhs) > 0) {
            printf("lhs: %s\n", lhs);
            if (strncmp(lhs, "flow", 5) == 0) {
	              printf("found flow\n");
            }
        }

#else 

        if (type == addresses) {
            if (mode == mode_anonymize) {
	              anon_addresses(line);
            } else {
	              /* mode == check */
	              check_anon_addresses(line);
            }
        } else if (type == strings) {
            struct matches matches;

            if (mode == mode_anonymize) {
	              str_match_ctx_find_all_longest(usernames_ctx, (unsigned char *)line, strlen(line), &matches);      	
	              anon_print_string(stdout, &matches, line, email_special_chars, anon_string);
      
            } else if (mode == mode_check) {
	              str_match_ctx_find_all_longest(usernames_ctx, (unsigned char *)line, strlen(line), &matches);      
	              if (matches.count > 0) {
	                  printf("username match(es) at line %u:\n", linenum);
	                  matches_print(&matches, line);
	              }

            } else if (mode == mode_deanonymize) {
	              str_match_ctx_find_all_longest(usernames_ctx, (unsigned char *)line, strlen(line), &matches);      
	              anon_print_string(stdout, &matches, line, email_special_chars, deanon_string);	

            }
        }
#endif    

        linenum++;

    }
      
    free(line);
 
    return 0;
}

