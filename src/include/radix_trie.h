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
 * \file radix_trie.h
 *
 * \brief interface to radix_trie implementation for fast address lookup
 *
 ** This implementation is designed to quickly search over addresses
 *  (currently IPv4 only) and determine if an address matches one or
 *  more subnets that have been inserted into the trie.  Each subnet is
 *  associated with a label, and there can be up to MAX_NUM_FLAGS
 *  labels (as they are interally represented as bit flags).  
 *
 */

#ifndef RADIX_TRIE_H 
#define RADIX_TRIE_H 

#ifdef WIN32
#include "Ws2tcpip.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "err.h" 
#include "addr_attr.h"
#include "output.h"

/** Maximum number of flags possible */
#define MAX_NUM_FLAGS (sizeof(attr_flags)*8)

/** radix_trie_t is a pointer to a radix_trie structure
 *
 ** the details of that structure are intentionally opaque, and are defined in
 * the file radix_trie.c
 */
typedef struct radix_trie *radix_trie_t;

/** allocates a radix_trie and returns a pointer */
radix_trie_t radix_trie_alloc(void);

/** does a deep free of radix_trie memory */
joy_status_e radix_trie_free(struct radix_trie *rt);

/** initializes the radix_trie structure at the location rt.
 *
 ** This function does not allocate any memory.
 */
joy_status_e radix_trie_init(struct radix_trie *rt);

joy_status_e radix_trie_add_subnet_from_string(struct radix_trie *rt, char *addr, attr_flags attr, FILE *loginfo);

/** reads the file, parsing each line to find subnet (address/netmask) */
joy_status_e radix_trie_add_subnets_from_file(struct radix_trie *rt,
     const char *pathname, attr_flags attr, FILE *logfile);

/** inserts the subnet and an attribute flags variable into the
 * radix_trie, and associates that subnet with the flags
 */
joy_status_e radix_trie_add_subnet(struct radix_trie *trie, 
			  struct in_addr addr, unsigned int netmasklen, attr_flags flags);

/** writes a json-encoded form of the labels associated with the flags */
void attr_flags_json_print_labels(const struct radix_trie *rt, 
			  attr_flags f, const char *prefix, zfile file);

/*
 * the function call radix_trie_lookup_addr(rt, addr) checks for
 * matches between the address addr and all of the subnets associated
 * with the radix_trie rt.  It returns an unsigned integer that
 * consists of the bitwise-OR of all of the flags associated with the
 * address addr.
 */
attr_flags radix_trie_lookup_addr(struct radix_trie *trie, struct in_addr addr);

/** adds a labeled flag with the name "label" to a radix_trie */
attr_flags radix_trie_add_attr_label(struct radix_trie *rt, const char *label);

/** unit test function */
int radix_trie_unit_test(void);

#endif /* RADIX_TRIE_H  */
