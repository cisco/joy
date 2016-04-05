/*
 * dns.c
 */
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

#include <stdlib.h>
#include <string.h>
#include "pkt.h"     /* for CPU_IS_BIG_ENDIAN */
#include "dns.h"

/*
 * implementation strategy: store and print out DNS responses,
 * including NAME, RCODE, and addresses.  Queries need not be
 * stored/printed, since the responses repeat the "question" before
 * giving the "answer".
 *
 * IPv4 addresses are read from the RR fields that appear in RDATA; 
 * they are indicated by RR.TYPE == A (1) and RR.CLASS == IN (1).
 */

/*
 * DNS packet formats (from RFC 1035)
 *
 *                      DNS Header
 * 
 *                                   1  1  1  1  1  1
 *     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                      ID                       |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    QDCOUNT                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    ANCOUNT                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    NSCOUNT                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                    ARCOUNT                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 *
 *                    Resource Records
 * 
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                                               |
 *   /                                               /
 *   /                      NAME                     /
 *   |                                               |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                      TYPE                     |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                     CLASS                     |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                      TTL                      |
 *   |                                               |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                   RDLENGTH                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 *   /                     RDATA                     /
 *   /                                               /
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 *
 * 
 */

#if CPU_IS_BIG_ENDIAN

struct dns_hdr {
  unsigned short id;
  unsigned char qr:1;
  unsigned char opcode:4;
  unsigned char aa:1;
  unsigned char tc:1;
  unsigned char rd:1;
  unsigned char ra:1;
  unsigned char z:3;
  unsigned char rcode:4;
  unsigned short qdcount;
  unsigned short ancount;
  unsigned short nscount;
  unsigned short arcount;
};

#else

struct dns_hdr {
  unsigned short id;
  unsigned char rd:1;
  unsigned char tc:1;
  unsigned char aa:1;
  unsigned char opcode:4;
  unsigned char qr:1;
  unsigned char rcode:4;
  unsigned char z:3;
  unsigned char ra:1;
  unsigned short qdcount;
  unsigned short ancount;
  unsigned short nscount;
  unsigned short arcount;
};

#endif





/*
 * num_pkt_len can be set on command line, and it controls the maximum
 * number of DNS packets that will be captured
 */
extern unsigned int num_pkt_len;

void dns_query_to_string(char *q, unsigned int len) {
  unsigned int i;

  /* 
   * question: what should this function do if a null character
   *  appears before the end of the string?
   */ 

  for (i=1; i<len; i++) {
    if (q[i] == 0) {
      break;
    }
    if (q[i] < 32) {
      q[i] = '.';
    }
  }
}

enum status process_dns(const struct pcap_pkthdr *h, const void *start, int len, struct flow_record *r) {
  const char *name = start + 13;
  // unsigned char rcode = *((unsigned char *)(start + 3)) & 0x0f;
  // unsigned char qr = *((unsigned char *)(start + 2)) >> 7;

  if (r->op >= num_pkt_len) {
    return failure;  /* no more room */
  }  

  if (len < 13) {
    return failure;  /* not long enough to be a proper DNS packet */
  }

  // printf("dns len: %u name: %s qr: %u rcode: %u\n", len-14, name, qr, rcode);
  if (!r->dns_name[r->op]) {
    r->dns_name[r->op] = malloc(len-13);
    strncpy(r->dns_name[r->op], name, len-13);
    dns_query_to_string(r->dns_name[r->op], len-13);
  }

  return ok;
}


void dns_printf(char * const dns_name[], const unsigned short pkt_len[], 
		char * const twin_dns_name[], const unsigned short twin_pkt_len[], 
		unsigned int count, zfile output) {
  unsigned int i;

  zprintf(output, ",\"dns\":[");
  
  if (twin_dns_name) {
    char *q, *r;
    
    for (i=0; i<count; i++) {
      if (i) {
	zprintf(output, ",");
      }
      if (dns_name[i]) {
	q = dns_name[i];
	convert_string_to_printable(q, pkt_len[i] - 13);
      } else {
	q = "";
      }
      if (twin_dns_name[i]) {
	r = twin_dns_name[i];
	convert_string_to_printable(r, twin_pkt_len[i] - 13);
      } else {
	r = "";
      }
      zprintf(output, "{\"qn\":\"%s\",\"rn\":\"%s\"}", q, r);
    }
    
  } else { /* unidirectional flow, with no twin */
    
    for (i=0; i<count; i++) {
      if (i) {
	zprintf(output, ",");
      }
      if (dns_name[i]) {
	convert_string_to_printable(dns_name[i], pkt_len[i] - 13);
	zprintf(output, "{\"qn\":\"%s\"}", dns_name[i]);
      }
    }
  }
  
  zprintf(output, "]");
}
