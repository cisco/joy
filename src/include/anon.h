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
 * \file anon.h
 *
 * \brief address anonymization interface
 *
 ** The anonymization key is generated via calls to /dev/random, and is
 * stored in the file ANON_KEYFILE in encrypted form, with the
 * decryption key being stored inside the executable.  A user who can
 * access ANON_KEYFILE and the executable will be able to determine
 * the anonymization key; it is essential to provide strong access
 * control on ANON_KEYFILE in particular.
 */

#ifndef ANON_H
#define ANON_H 

#include <stdio.h> 

#ifdef WIN32
#include "Ws2tcpip.h"
#else
#include <netinet/in.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/aes.h>
#include "err.h"
#include "output.h"
#include "str_match.h"

/** modes of anonymization */
enum anon_mode {
  null_mode        = 0,
  mode_anonymize   = 1,
  mode_check       = 2,
  mode_deanonymize = 3
};

/** default key file name */
#define ANON_KEYFILE_DEFAULT "joy.bin"

/** maximum number of subnets that can be anonymized */
#define MAX_ANON_SUBNETS 256

/** prototype for character operations */
typedef int (*char_selector)(char *ptr);

/** stucture used for anonimzed subnets */
typedef struct {
  struct in_addr addr;
  struct in_addr mask;
} anon_subnet_t;

/**
 * \brief initializes anonymization using the subnets in the
 * file subnetfile and sets the secondary output to logfile
 */
joy_status_e anon_init(const char *pathname, FILE *logfile);

/** \brief prints the subnets that have been anonymized to output file */
int anon_print_subnets(FILE *f);

/** \brief converts an address into an anonymized string */
char *addr_get_anon_hexstring(const struct in_addr *a);

/** \brief determines if address is to be anonymized */
unsigned int ipv4_addr_needs_anonymization(const struct in_addr *a);

/** \brief initialize the http anonymization */
joy_status_e anon_http_init(const char *pathname, FILE *logfile, enum anon_mode mode, const char *anon_keyfile);

/** \brief prints out '*' for length */
void zprintf_anon_nbytes(zfile f, size_t len);

/** \brief prints out number of bytes specified */
void zprintf_nbytes(zfile f, char *s, size_t len);

/** \brief prints out URI with or without anonymization depending on URI status */
void anon_print_uri(zfile f, struct matches *matches, char *text);

/** \brief finds special characters in email addresses */
int email_special_chars(char *ptr);

/** \brief determines if characters are special or not */
int is_special(char *ptr);

/** \brief prints out a string with or without anonymization depending on matching criteria */
void anon_print_string(zfile f, 
		       struct matches *matches, 
		       char *text, 
		       char_selector selector, 
		       string_transform transform);

/** \brief anonumizes a string */
joy_status_e anon_string(const char *s, unsigned int len, char *hex, unsigned int outlen);

/** \brief deanonymizes a string */
joy_status_e deanon_string(const char *hexinput, unsigned int len, char *s, unsigned int outlen);

/** \brief prints a URI anonymized if applicable */
void anon_print_uri_pseudonym(zfile f, struct matches *matches, char *text);

/** \brief prints usersnames anonymized if applicable */
void zprintf_usernames(zfile f, struct matches *matches, char *text, char_selector selector, string_transform transform);

/** \brief initializes the key used for anonymization routines */
joy_status_e key_init(const char *ANON_KEYFILE);

/** \brief anonymization unit test main entry point */
int anon_unit_test(void);

#endif /* ANON_H */
