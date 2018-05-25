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
 * \file str_match_test.c
 *
 * \brief unit test for multiple string matching functions
 */
#include <stdarg.h>
#include <string.h>

#if !defined(DARWIN) && !defined(WIN32)
#include <malloc.h>
#endif

#include "str_match.h"
#include "p2f.h"
#include "anon.h"
#include "config.h"
#include "joy_api.h"

zfile output = NULL;

static void matches_print (struct matches *matches, char *text) {
    unsigned int i;
    char tmp[1024];

    printf("no matches\n");
    for (i=0; i < matches->count; i++) {
        size_t len = matches->stop[i] - matches->start[i] + 1;
        if (len > 1024) {
            return;
        }
        memcpy(tmp, text + matches->start[i], len);
        tmp[len] = 0;
        printf("match %d: %s\n", i, tmp);
    }
}

static void anon_print (zfile f, struct matches *matches, char *text) {
    unsigned int i;

    if (matches->count == 0) {
        zprintf(f, "%s", text);
        return;
    }

    zprintf_nbytes(f, text, matches->start[0]);   /* nonmatching */
    for (i=0; i < matches->count; i++) {
        zprintf_anon_nbytes(f, text + matches->start[i], matches->stop[i] - matches->start[i] + 1);   /* matching */
        if (i < matches->count-1) {
            zprintf_nbytes(f, text + matches->stop[i] + 1, matches->start[i+1] - matches->stop[i] - 1); /* nonmatching */
        } else {
            zprintf(f, "%s", text + matches->stop[i] + 1);  /* nonmatching */
        }
    }
}


static void str_match_test (str_match_ctx ctx, char *search) {
    struct matches matches;

    str_match_ctx_find_all_longest(ctx, (const unsigned char *)search, strlen(search), &matches);
  
    matches_print(&matches, (char *)search);

    zprintf(output, "text being searched:   %s\n", search);  
    zprintf(output, "anonymized string:     ");
    anon_print(output, &matches, (char *)search);
    zprintf(output, "\n");
    zprintf(output, "anonymized uri string: ");
    anon_print_uri(output, &matches, (char *)search);
    zprintf(output, "anonymized string: ");
    anon_print_uri_pseudonym(output, &matches, (char *)search);
    zprintf(output, "\n");
    zprintf_usernames(output, &matches, (char *)search, is_special, NULL);
    zprintf(output, "\n");
    zprintf_usernames(output, &matches, (char *)search, is_special, anon_string);
    zprintf(output, "\n");
}

static char *text = "prefix middle suffix prefixmiddle middlesuffix prefixmiddlesuffix frogers2 velmad vdinkey";

static char *text2 = "EXAMPLE TEXT WITH prefix AND middle BUT NOT suffix HAS prefixmiddle THIS middlesuffix TEST TEST prefixmiddlesuffix, IPSO FACTO frogers2 BLAHvelmadBLAH BLAHvdinkey EXCELSIOR";

static char *text3 = "/root/shaggy/blahvelmablah/query?username=fred;subject=daphne;docname=blahscooby;alt=scoobyblah;path=velma";

//static char *text4 = "/pca3.crl";
static char *text4 = "/bg/api/Pickup.ashx?c={%22c%22:%225a9760de94b24d3c806a6400e76571fe%22,%22s%22:%2210.241.40.128%22}&m=[]&_=1458318857011";

/**
 * \fn int main (int argc, char* argv[])
 * \brief main entry point for string matching tests
 * \param argc command line argument count
 * \param argv command line arguments
 * \return -1 error
 * \return EXIT_FAILURE
 * \return 0
 */
int main (int argc, char* argv[]) {
    str_match_ctx ctx;
    int rc = 0;
    struct joy_init init_data;

    /* setup the joy options we want */
    memset(&init_data, 0x00, sizeof(struct joy_init));

   /* this setup is for general processing */
    init_data.type = 1;
    init_data.verbosity = 4;

    /* intialize joy */
    rc = joy_initialize(&init_data, NULL, NULL, NULL);
    if (rc != 0) {
        printf(" -= Joy Initialized Failed =-\n");
        return -1;
    }

    /* set output to stdout */
    output = zattach(stdout, "w");

#if !defined(DARWIN) && !defined(WIN32)
    struct mallinfo mem_info;

    mem_info = mallinfo();
    printf ("allocated space before loading context:  %d bytes\n", mem_info.uordblks);
#endif
  
    ctx = str_match_ctx_alloc();
    if (ctx == NULL) {
        fprintf(stderr, "error: could not allocate string matching context\n");
        return -1;
    }
    if (str_match_ctx_init_from_file(ctx, "test/misc/userid-example.txt", NULL) != 0) {
        fprintf(stderr, "error: could not init string matching context from file\n");
        exit(EXIT_FAILURE);
    }
  
#if !defined(DARWIN) && !defined(WIN32)
	mem_info = mallinfo();
    printf ("allocated space after loading context:  %d bytes\n", mem_info.uordblks);
#endif

    if (key_init(ANON_KEYFILE_DEFAULT) != ok) {
        fprintf(stderr, "error: could not init anonymization key\n");
    }

    str_match_test(ctx, text);
    str_match_test(ctx, text2);
    str_match_test(ctx, text3);
    str_match_test(ctx, text4);

    str_match_ctx_free(ctx);
  
    joy_cleanup(0);
    return 0;
}

