/*
 *      
 * Copyright (c) 2016-2018 Cisco Systems, Inc.
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
 * \file joy-anon.c
 * 
 * \brief address (de)anonymization tool
 * 
 ** \verbatim
  joy-anon [ -r ] [ -k <keyfile> ] <value> [ <value2> ... ]
     -r reverses (deanonymizes)
     <keyfile> is the key to be used in (de)anonymization
     <value> is the address to be (de)anonymized
 \endverbatim
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>  
#include "anon.h"
#include "radix_trie.h"
#include "safe_lib.h"

#ifdef WIN32
#include <Ws2tcpip.h>
#else 
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif



static char *addr_string_anonymize (char *addr_string) {
    struct in_addr addr;
    int l;

    l = strnlen_s(addr_string, 256);
    if (l >= 32) {
        return addr_string;  /* probably already anonymized */
    }

#ifdef WIN32
        if (inet_pton(AF_INET,addr_string, &addr) == 0) {
#else
        if (inet_aton(addr_string, &addr) == 0) {
#endif
        return NULL;
    }
    return addr_get_anon_hexstring(&addr);
}


char string[17];
static char *addr_string_deanonymize (const char *hexstring) {
    int l;

    l = strnlen_s(hexstring, 256);
    if (l != 32) {
        return NULL;  /* can't be anonymized value */
    }

    /* deanonymize */
    if (deanon_string (hexstring, 32, string, sizeof(string)) != ok) {
        return NULL;
    }
    return string;

}


static int usage (char *name) {
    fprintf(stderr, "usage:\n%s [-r][-k <kfile>] <value> [ <value2> ... ]\n", name);
    fprintf(stderr, "where:\n"
                "   <value> contains the value to be (de)anonymized\n\n"
                "   <kfile> contains the key to be used in (de)anonymization; if\n"
                "   omitted, the file %s will be used\n\n" 
                "   -r causes anonymization to be removed\n\n",
                ANON_KEYFILE_DEFAULT);
    return 1;
}

enum type {
    null_type = 0,
    addresses = 1,
    strings   = 2
};

/**
 \fn int main (int argc, char *argv[])
 \brief main entry point for joy-anon
 \param argc command line argument count
 \param argv command line arguments
 \return 1 usage
 \return EXIT_FAILURE
 \return 0 success
 */
int main (int argc, char *argv[]) {
    const char *keyfile = ANON_KEYFILE_DEFAULT;
    enum anon_mode mode = mode_anonymize;
    enum type type = addresses;    /* we don't handle userids for now */
    int i, opt;

    /*
     * obtain options from command line
     */
    while ((opt = getopt(argc, argv, "rk:")) != -1) {
        switch (opt) {
            case 'r':
                mode = mode_deanonymize;
                break;
            case 'k':
                keyfile = optarg;
                break;
            default: 
                return usage(argv[0]);
        }
    }

    if (key_init(keyfile) != ok) {
        fprintf(stderr, "error: could not initialize from keyfile %s\n", keyfile);
        return usage(argv[0]);
    }

    if (argc < 2) {
        return usage(argv[0]);
    }

    /*
     * we assume here that all non-option arguments are values to be
     * (de)anonymized
     */

  if (type == addresses) {
    for (i=optind; i<argc; i++) {
            if (mode == mode_anonymize) {
                char *anon = addr_string_anonymize(argv[i]);
                
                if (anon == NULL) {
                    fprintf(stderr, "error: %s cannot be converted into an IPv4 address\n", argv[i]);
                    return usage(argv[0]);
                }
                printf("%s: %s\n", argv[i], anon);

            } else if (mode == mode_deanonymize) {
                char *plain = addr_string_deanonymize(argv[i]);

                if (plain == NULL) {
                    fprintf(stderr, "error: %s cannot be deanonymized\n", argv[i]);
                    return usage(argv[0]);
                }
                printf("%s: %s\n", argv[i], plain);
                                
            }
        } 
    }

    
    return 0;
}

