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
#include <stdint.h>
#include <ctype.h>   /* for isprint()         */
#include "pkt.h"     /* for CPU_IS_BIG_ENDIAN */
#include "dns.h"
#include "anon.h"
#include "err.h"
#include "p2f.h"

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
  uint16_t id;
  unsigned char qr:1;
  unsigned char opcode:4;
  unsigned char aa:1;
  unsigned char tc:1;
  unsigned char rd:1;
  unsigned char ra:1;
  unsigned char z:3;
  unsigned char rcode:4;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} __attribute__((__packed__));

#else

struct dns_hdr {
  uint16_t id;
  unsigned char rd:1;
  unsigned char tc:1;
  unsigned char aa:1;
  unsigned char opcode:4;
  unsigned char qr:1;
  unsigned char rcode:4;
  unsigned char z:3;
  unsigned char ra:1;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} __attribute__((__packed__));

#endif

/*
 * RCODE        Response code - this 4 bit field is set as part of
 *              responses.  The values have the following
 *              interpretation:
 *
 *              0               No error condition
 *
 *              1               Format error - The name server was
 *                              unable to interpret the query.
 *
 *              2               Server failure - The name server was
 *                              unable to process this query due to a
 *                              problem with the name server.
 *
 *              3               Name Error - Meaningful only for
 *                              responses from an authoritative name
 *                              server, this code signifies that the
 *                              domain name referenced in the query does
 *                              not exist.
 *
 *              4               Not Implemented - The name server does
 *                              not support the requested kind of query.
 *
 *              5               Refused - The name server refuses to
 *                              perform the specified operation for
 *                              policy reasons.  For example, a name
 *                              server may not wish to provide the
 *                              information to the particular requester,
 *                              or a name server may not wish to perform
 *                              a particular operation (e.g., zone
 */

struct dns_question {
  uint16_t qtype;
  uint16_t qclass;
} __attribute__((__packed__));

struct dns_rr {
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rdlength;
} __attribute__((__packed__));

void *dns_rr_get_rdata(struct dns_rr *rr) {
  void *location = rr;
  return location + sizeof(struct dns_rr);
}

void *dns_question_get_rr(struct dns_question *q) {
  void *location = q;
  return location + sizeof(struct dns_question);
}

enum dns_type {
  type_A     = 1, // a host address
  type_NS    = 2, // an authoritative name server
  type_MD    = 3, //a mail destination (Obsolete - use MX)
  type_MF    = 4, //a mail forwarder (Obsolete - use MX)
  type_CNAME = 5, // the canonical name for an alias
  type_SOA   = 6, // marks the start of a zone of authority
  type_MB    = 7, // a mailbox domain name (EXPERIMENTAL)
  type_MG    = 8, // a mail group member (EXPERIMENTAL)
  type_MR    = 9, // a mail rename domain name (EXPERIMENTAL)
  type_NULL  = 10, // a null RR (EXPERIMENTAL)
  type_WKS   = 11, // a well known service description
  type_PTR   = 12, // a domain name pointer
  type_HINFO = 13, // host information
  type_MINFO = 14, // mailbox or mail list information
  type_MX    = 15, // mail exchange
  type_TXT   = 16  // text strings
};

enum dns_class {
  class_IN = 1, // the Internet
  class_CS = 2, // the CSNET class (Obsolete)
  class_CH = 3, // the CHAOS class
  class_HS = 4  // Hesiod [Dyer 87]
};

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

#define char_is_label(c)  (((c) & 0xC0) == 0)
#define char_is_offset(c) (((c) & 0xC0) == 0xC0)

enum dns_err {
  dns_ok                  = 0,
  dns_err                 = 1,
  dns_err_label_too_long  = 2,
  dns_err_offset_too_long = 3,
  dns_err_malformed       = 4,
  dns_err_label_malformed = 5,
  dns_err_bad_rdlength    = 6,
  dns_err_unprintable     = 7,
  dns_err_too_many        = 8,
  dns_err_unterminated    = 9,
  dns_err_rdata_too_long  = 10
};

enum dns_err data_advance(void **data, int *len, unsigned int size) {
  if (*len < size) {
    return dns_err_malformed;
  } 
  *data += size;
  *len -= size;  
  return dns_ok;
}

enum dns_err dns_question_parse(const struct dns_question **q, void **data, int *len) {
  if (*len < sizeof(struct dns_question)) {
    return dns_err_malformed;
  } 
  *q = *data;
  *data += sizeof(struct dns_question);
  *len -= sizeof(struct dns_question);  
  return dns_ok;
}

enum dns_err dns_rr_parse(const struct dns_rr **r, void **data, int *len, int *rdlength) {
  if (*len < sizeof(struct dns_rr)) {
    return dns_err_malformed;
  } 
  *r = *data;
  if (*len < ntohs((*r)->rdlength)) {
    return dns_err_rdata_too_long;
  }
  *rdlength = ntohs((*r)->rdlength);
  *data += sizeof(struct dns_rr);  
  *len -= sizeof(struct dns_rr);  
  return dns_ok;
}

enum dns_err dns_addr_parse(const struct in_addr **a, void **data, int *len, unsigned short int rdlength) {
  if (*len < sizeof(struct in_addr)) {
    return dns_err_malformed;
  } 
  if (rdlength != sizeof(struct in_addr)) {
    return dns_err_bad_rdlength;
  }
  *a = *data;
  *data += sizeof(struct in_addr);
  *len -= sizeof(struct in_addr);  
  return dns_ok;
}

enum dns_err uint16_parse(uint16_t **x, void **data, int *len) {
  if (*len < sizeof(uint16_t)) {
    return dns_err_malformed;
  } 
  *x = *data;
  *data += sizeof(uint16_t);  
  *len -= sizeof(uint16_t);  
  return dns_ok;
}

int string_is_not_printable(char *s, unsigned int len) {
  int i;

  for (i=0; i<len; i++) {
    if (!isprint(s[i])) {
      return 1;
    } 
  }
  return 0;
}

static inline char printable(char c) {
  if (isprint(c)) {
    return c;
  }
  return '*';
}

enum dns_err dns_header_parse_name(const struct dns_hdr *hdr, void **name, int *len, char *outname, unsigned int outname_len) {
  char *terminus = outname + outname_len;
  char *c = *name;
  unsigned char jump;
  int i;
  int offsetlen = (*name - (const void *)hdr) + *len; /* num bytes available after offset pointer */
  const void *offsetname;
  enum dns_err err;

  /*
   * A DNS name is a sequence of zero or more labels, possibly
   * followed by an offset.  A label consists of an 8-bit number L
   * that is less than 64 followed by L characters.  An offset is
   * 16-bit number, with the first two bits set to one.  A name is
   * either a sequence of two or more labels, with the last label
   * being NULL (L=0), or a sequence of one or more labels followed by
   * an offset, or just an offset.
   *
   * An offset is a pointer to (part of) a second name in another
   * location of the same DNS packet.  Importantly, note that there
   * may be an offset in the second name; this function must follow
   * each offset that appears and copy the names to outputname.
   */
  outname[1] = 0;         /* set output to "", in case of error */
  while (*len > 0 && outname < terminus) {
    if (char_is_label(*c)) {
      if (*c < 64 && *len > *c) {
	if (*c == 0) {
	  *name = c+1; 
	  *outname = 0;
	  return dns_ok;  /* got NULL label       */
	}
	jump = *c + 1;
	/* 
	 * make (printable) copy of string
	 */
	*outname++ = '.';
	for (i=1; i<jump; i++) {
	  *outname++ = printable(c[i]);
	}
	/* advance pointers, decrease lengths */
	outname_len -= jump;
	*len -= jump;
	c += jump;
	*name += jump;
      } else {
	return dns_err_label_too_long;
      }
    } else if (char_is_offset(*c)) {
      uint16_t *offset;

      err = uint16_parse(&offset, name, len);
      if (err != dns_ok) {
	return dns_err_offset_too_long;
      }
      offsetname = (const void *)hdr + (ntohs(*offset) & 0x3FFF);
      offsetlen -= (ntohs(*offset) & 0x3FFF);
      return dns_header_parse_name(hdr, (void *)&offsetname, &offsetlen, outname, outname_len);

    } else {
      return dns_err_label_malformed;
    }
  } 

  return dns_err_unterminated;
}

/*
 * dns_rdata_print(rh, rr, r, len, output) prints the RDATA field at
 * location *r
 *
 * note: if this function returns a value other than dns_ok, then it
 * has not printed any output; this fact is important to ensure
 * correct JSON formatting
 */
enum dns_err
dns_rdata_print(const struct dns_hdr *rh, const struct dns_rr *rr, void **r, int *len, zfile output) {
  enum dns_err err;
  uint16_t class = ntohs(rr->class);
  uint16_t type = ntohs(rr->type);
  char name[256];

  if (class == class_IN) {    
    if (type == type_A) {
      const struct in_addr *addr;;
      
      err = dns_addr_parse(&addr, r, len, ntohs(rr->rdlength));
      if (err != dns_ok) {
	return err;
      }
      if (ipv4_addr_needs_anonymization(addr)) {
	zprintf(output, "\"a\":\"%s\"", addr_get_anon_hexstring(addr));
      } else {
	zprintf(output, "\"a\":\"%s\"", inet_ntoa(*addr));
      }
    } else if (type == type_SOA  || type == type_PTR || type == type_CNAME) {
      char *typename;

      err = dns_header_parse_name(rh, r, len, name, sizeof(name)); /* note: does not check rdlength */
      if (err != dns_ok) { 
	return err; 
      }
      switch (type) {
      case type_SOA:
	typename = "soa";
	break;
      case type_PTR:
	typename = "ptr";
	break;
      case type_CNAME:
	typename = "cname";
	break;
      default:
	typename = "unknown";
      }
      zprintf(output, "\"%s\":\"%s\"", typename, name + 1);
      
    } else if (type == type_TXT) {
      zprintf(output, "\"txt\":\"%s\"", "NYI");

    } else {
      err = data_advance(r, len, ntohs(rr->rdlength));
      if (err != dns_ok) {
	return err;
      }
      zprintf(output, "\"type\":\"%x\",\"class\":\"%x\",\"rdlength\":%u", type, class, rr->rdlength);
      
      /*
       * several DNS types are not explicitly supported here, and more
       * types may be added in the future, if deemed important.  see
       * http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
       */
    }
  } else {
    err = data_advance(r, len, ntohs(rr->rdlength));
    if (err != dns_ok) {
      return err;
    }
    zprintf(output, "\"type\":\"%x\",\"class\":\"%x\",\"rdlength\":%u", type, class, rr->rdlength);
  }

  return dns_ok;
}

enum status process_dns(const struct pcap_pkthdr *h, const void *start, int len, struct flow_record *r) {
  // const char *name = start + 13;
  // unsigned char rcode = *((unsigned char *)(start + 3)) & 0x0f;
  // unsigned char qr = *((unsigned char *)(start + 2)) >> 7;

  if (r->op >= num_pkt_len) {
    return failure;  /* no more room */
  }  

  if (len < 13) {
    return failure;  /* not long enough to be a proper DNS packet */
  }

  // printf("dns len: %u name: %s qr: %u rcode: %u\n", len-14, name, qr, rcode);
  if (!r->dns.dns_name[r->op]) {
    r->dns.dns_name[r->op] = malloc(len);
    if (r->dns.dns_name[r->op] == NULL) {
      return failure;
    }
    // strncpy(r->dns_name[r->op], name, len-13);
    memcpy(r->dns.dns_name[r->op], start, len);
    // dns_query_to_string(r->dns_name[r->op] + 13, len-13);
  }

  return ok;
}


void dns_print_packet(char *dns_name, unsigned int pkt_len, zfile output) {
  char name[256];
  enum dns_err err;
  void *r;
  const struct dns_hdr *rh;
  const struct dns_question *question;
  const struct dns_rr *rr;
  int len;
  char qr;
  uint16_t qdcount, ancount;
  int rdlength;
  unsigned comma = 0;
  
  /*
   * DNS packet format:
   * 
   *   one struct dns_hdr
   *   one (question) name 
   *   one struct dns_question 
   *   zero or more (resource record) name
   *                struct dns_rr
   *                rr_data   
   */
  zprintf(output, "{");
    
  len = pkt_len;
  r = dns_name;
  rh = r;
  if (rh->qr == 0) {
    qr = 'q';
  } else {
    qr = 'r';
  }
  /* check length > 12 ! */
  len -= 12;
  r += 12;
  
  qdcount = ntohs(rh->qdcount);
  if (qdcount > 1) {
    err = dns_err_too_many;
    zprintf(output, "\"malformed\":%d", len);
    zprintf_debug("qdcount=%u; err=%u\"}", qdcount, err);
    return;
  }
  while (qdcount-- > 0) {
    /* parse question name and struct */
    err = dns_header_parse_name(rh, &r, &len, name, sizeof(name));
    if (err != dns_ok) { 
      zprintf(output, "\"malformed\":%d", len);
      zprintf_debug("question name err=%u; len=%u\"}]}", err, len);
      return;
    }
    err = dns_question_parse(&question, &r, &len);
    if (err != dns_ok) {
      zprintf(output, "\"malformed\":%d", len);
      zprintf_debug("question err=%u; len=%u\"]}]", err, len);
      return;
    }
    zprintf(output, "\"%cn\":\"%s\"", qr, name + 1);
  }
  zprintf(output, ",\"rc\":%u,\"rr\":[", rh->rcode);

  ancount = ntohs(rh->ancount); 
  comma = 0;
  while (ancount-- > 0) {
    if (comma++) {
      zprintf(output, ",");
    }
    zprintf(output, "{");
    /* parse rr name, struct, and rdata */
    err = dns_header_parse_name(rh, &r, &len, name, sizeof(name));
    if (err != dns_ok) { 
      unsigned char *d = r;
      zprintf(output, "\"malformed\":%d", len);
      zprintf_debug("rr name ancount=%u; err=%u; len=%u; data=0x%02x%02x%02x%02x\"}]}", ancount, err, len, d[0], d[1], d[2], d[3]);
      return;
    }
    // zprintf(output, "\"name\":\"%s\"", name);
    err = dns_rr_parse(&rr, &r, &len, &rdlength);
    if (err) {
      zprintf(output, "\"malformed\":%d", len);
      zprintf_debug("rr ancount=%u; err=%u; len=%u\"}]}", ancount, err, len);
      return;
    }
    err = dns_rdata_print(rh, rr, &r, &rdlength, output);
    if (err) {
      zprintf(output, "\"malformed\":%d}]}", len);
      return;
    }
    len -= rdlength;
    zprintf(output, ",\"ttl\":%u}", ntohl(rr->ttl));
  }
  zprintf(output, "]}");
 
  return;
}

void dns_printf(char * const dns_name[], const unsigned short pkt_len[], 
		char * const twin_dns_name[], const unsigned short twin_pkt_len[], 
		unsigned int count, zfile output) {
  unsigned int i, j;

  zprintf(output, ",\"dns\":[");
  
  if (twin_dns_name) { /* bidirectional flow */
    // struct dns_hdr *qh;
    
    i = j = 0;
    while ((i < count) && (j < count)) {
      if (dns_name[i]) {
	// qh = (struct dns_hdr *)dns_name[i];
      }
      if (twin_dns_name[i]) {
	if (i || j) {
	  zprintf(output, ",");
	}
	dns_print_packet(twin_dns_name[i], twin_pkt_len[i], output);
      } 
      i++;
    }
    
  } else { /* unidirectional flow, with no twin */
    
    for (i=0; i<count; i++) {
      if (i) {
	zprintf(output, ",");
      }
      if (dns_name[i]) {
	dns_print_packet(dns_name[i], pkt_len[i], output);
      }
    }
  }
  
  zprintf(output, "]");
}

/*
 * START of dns feature functions
 */


#define MAX_DNS_NAME_LEN 256

#include <assert.h>

void dns_unit_test() {
  enum dns_err err;
  struct dns_hdr hdr;
  char name[MAX_DNS_NAME_LEN] = { 
    0x03, 0x77, 0x77, 0x77, 0x06, 0x6F, 0x72, 0x77, 
    0x65, 0x6C, 0x6C, 0x02, 0x72, 0x75, 0x00
  };
  char name2[MAX_DNS_NAME_LEN];
  void *c = &name;
  int len = 15;

  assert(sizeof(struct dns_hdr) == 12);
  assert(sizeof(struct dns_question) == 4);
  assert(sizeof(struct dns_rr) == 10);
  
  err = dns_header_parse_name(&hdr, &c, &len, name2, sizeof(name2));

  printf("name: %s\tlen: %u\terr: %u\n", name2, len, err);
}


void dns_init(struct dns *dns) {
  memset(dns->dns_name, 0, sizeof(dns->dns_name));
  memset(dns->pkt_len, 0, sizeof(dns->pkt_len));
  dns->pkt_count = 0;
}

void dns_delete(struct dns *dns) {
  unsigned int i;

  for (i=0; i<dns->pkt_count; i++) {
    if (dns->dns_name[i]) {
      free(dns->dns_name[i]);
    }
  }
}

void dns_update(struct dns *dns, const void *start, unsigned int len, unsigned int report_dns) {
  // const char *name = start + 13;
  // unsigned char rcode = *((unsigned char *)(start + 3)) & 0x0f;
  // unsigned char qr = *((unsigned char *)(start + 2)) >> 7;

  if (report_dns == 0) {
    return;  /* we are not configured to report DNS information */
  }

  if (dns->pkt_count >= num_pkt_len) {
    return;  /* no more room */
  }  

  if (len < 13) {
    return;  /* not long enough to be a proper DNS packet */
  }

  // printf("dns len: %u name: %s qr: %u rcode: %u\n", len-14, name, qr, rcode);
  if (!dns->dns_name[dns->pkt_count]) {
    dns->dns_name[dns->pkt_count] = malloc(len);
    if (dns->dns_name[dns->pkt_count] == NULL) {
      return; /* failure */
    }
    // strncpy(r->dns_name[dns->pkt_count], name, len-13);
    memcpy(dns->dns_name[dns->pkt_count], start, len);
    dns->pkt_len[dns->pkt_count] = len;
    dns->pkt_count++;
    // dns_query_to_string(r->dns_name[dns->pkt_count] + 13, len-13);
  }

  return;  /* ok */
}

void dns_print_json(const struct dns *dns1, const struct dns *dns2, zfile f) {
  unsigned int count;
  char * const *twin_dns_name = NULL;
  const unsigned short *twin_pkt_len = NULL;
  
  count = dns1->pkt_count > MAX_NUM_DNS_PKT ? MAX_NUM_DNS_PKT : dns1->pkt_count;
  if (dns2) {
    count = dns2->pkt_count > count ? dns2->pkt_count : count;
    twin_dns_name = dns2->dns_name;
    twin_pkt_len = dns2->pkt_len;
  }

  if (count == 0) {
    return;  /* no DNS data to report */
  }
 
  dns_printf(dns1->dns_name, dns1->pkt_len, twin_dns_name, twin_pkt_len, count, f);  
}


/*
 * END of dns feature functions
 */
