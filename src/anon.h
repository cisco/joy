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

/*
 * anon.h
 *
 * address anonymization
 */

#ifndef ANON_H
#define ANON_H 

/*
 * The anonymization key is generated via calls to /dev/random, and is
 * stored in the file ANON_KEYFILE in encrypted form, with the
 * decryption key being stored inside the executable.  A user who can
 * access ANON_KEYFILE and the executable will be able to determine
 * the anonymization key; it is essential to provide strong access
 * control on ANON_KEYFILE in particular.
 */

#include <stdio.h>          /* for FILE */
#include <netinet/in.h>     /* for struct in_addr */
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/aes.h>
#include "err.h"
#include "output.h"

//struct subnet {
//  struct in_addr addr;
//  struct in_addr mask;
//};

#define MAX_ANON_SUBNETS 256

/*
 * anon_init(subnetfile, logfile) initializes anonymization using the
 * subnets in the file subnetfile and sets the secondary output to
 * logfile
 */
enum status anon_init(const char *pathname, FILE *logfile);

enum status anon_subnet_add_from_string(char *addr);

int anon_print_subnets(FILE *f);

char *addr_get_anon_hexstring(const struct in_addr *a);

unsigned int ipv4_addr_needs_anonymization(const struct in_addr *a);


/* END address anonymization  */

#include "str_match.h"

enum status anon_http_init(const char *pathname, FILE *logfile);

void zprintf_anon_nbytes(zfile f, char *s, size_t len);

void zprintf_nbytes(zfile f, char *s, size_t len);

void anon_print_uri(zfile f, struct matches *matches, char *text);

#endif /* ANON_H */
