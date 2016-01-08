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
 * radix_trie.h
 *
 * interface to radix_trie implementation for fast address lookup
 *
 * This implementation is designed to quickly search over addresses
 * (currently IPv4 only) and determine if an address matches one or
 * more subnets that have been inserted into the trie.  Each subnet is
 * associated with a label, and there can be up to MAX_NUM_FLAGS
 * labels (as they are interally represented as bit flags).  
 *
 */

#ifndef RADIX_TRIE_H 
#define RADIX_TRIE_H 

#include <sys/socket.h>  /* for sockaddr_in, inet_ntoa() */
#include <netinet/in.h>  /* for sockaddr_in, inet_ntoa() */
#include <arpa/inet.h>   /* for sockaddr_in, inet_ntoa() */
#include "err.h"         /* for enum status              */
#include "addr_attr.h"   /* for typedef attr_flags       */


#define MAX_NUM_FLAGS (sizeof(attr_flags)*8)


/*
 * radix_trie_t is a pointer to a radix_trie structure - this details
 * of that structure are intentionally opaque, and are defined in
 * the file radix_trie.c
 */
typedef struct radix_trie *radix_trie_t;


/*
 * radix_trie_alloc() allocates a radix_trie and return a pointer to
 * it
 */
radix_trie_t radix_trie_alloc();

/*
 * the function call radix_trie_init(rt) initializes the radix_trie
 * structure at the location rt.  On success, it returns ok;
 * otherwise, failure is returned.  This function does not allocate
 * any memory.
 * 
 */
enum status radix_trie_init(struct radix_trie *rt);


/*
 * radix_trie_add_subnets_from_file(rt, f, attr, logfile) reads the
 * file f, parsing each line to find subnet (address/netmask), then
 * adds each subnet to the radix_trie, associating it with the flag
 * attr, and writing errors to logfile
 */
enum status radix_trie_add_subnets_from_file(struct radix_trie *rt,
					     const char *pathname, 
					     attr_flags attr,
					     FILE *logfile);

/*
 * the function call radix_trie_add_subnet(rt, addr, len, flags)
 * inserts the subnet and an attribute flags variable into the
 * radix_trie, and associates that subnet with the flags
 *
 */
enum status radix_trie_add_subnet(struct radix_trie *trie, 
				  struct in_addr addr, 
				  unsigned int netmasklen, 
				  attr_flags flags);

/*
 * attr_flags_json_print_labels(rt, f, prefix, file) writes a
 * json-encoded form of the labels associated with the flags in f
 */
void attr_flags_json_print_labels(const struct radix_trie *rt, 
				  attr_flags f, 
				  char *prefix, 
				  FILE *file);


/*
 * get_rt_mem_usage() returns the number of bytes allocated by (all
 * of) the radix_trie(s) in use
 */
unsigned int get_rt_mem_usage();


/*
 * internal functions
 */

/*
 * the function call radix_trie_lookup_addr(rt, addr) checks for
 * matches between the address addr and all of the subnets associated
 * with the radix_trie rt.  It returns an unsigned integer that
 * consists of the bitwise-OR of all of the flags associated with the
 * address addr.
 */
unsigned int radix_trie_lookup_addr(struct radix_trie *trie, struct in_addr addr);



/*
 * radix_trie_add_attr(rt, label) adds a labeled flag with the name
 * "label" to a radix_trie, and returns the attribute flag
 * corresponding to that label if successful.  If unsuccessful, zero
 * is returned.
 */
attr_flags radix_trie_add_attr_label(struct radix_trie *rt, const char *label);


char *radix_trie_attr_get_label(const struct radix_trie *rt, attr_flags a);


char *radix_trie_attr_get_next_label(const struct radix_trie *rt, 
				     attr_flags a);

/*
 * unit test function
 */
int radix_trie_unit_test();

#endif /* RADIX_TRIE_H  */
