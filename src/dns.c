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
 * \file dns.c
 *
 * \brief implementation for the DNS code
 *
 * \remarks
 * \verbatim
 * implementation strategy: store and print out DNS responses,
 * including NAME, RCODE, and addresses.  Queries need not be
 * stored/printed, since the responses repeat the "question" before
 * giving the "answer".
 *
 * IPv4 addresses are read from the RR fields that appear in RDATA; 
 * they are indicated by RR.TYPE == A (1) and RR.CLASS == IN (1).
 *
 *
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
 *   |                                               |
 *   |                      NAME                     |
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
 *   |                     RDATA                     |
 *   |                                               |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * \endverbatim
 */
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h> 
#include <assert.h> 
#include "safe_lib.h"
#include "pkt.h"  
#include "dns.h"
#include "anon.h"
#include "err.h"
#include "p2f.h"

/**
 * \remarks
 * \verbatim
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
 * \endverbatim
 */

#if CPU_IS_BIG_ENDIAN

#ifdef WIN32

#define PACKED
#pragma pack(push,1)

 /** DNS header structure */
typedef struct {
        uint16_t id;
        uint16_t flags;
        uint16_t qdcount;
        uint16_t ancount;
        uint16_t nscount;
        uint16_t arcount;
} PACKED dns_hdr;

#pragma pack(pop)
#undef PACKED

#else

/** DNS header structure */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((__packed__)) dns_hdr;

#endif

#else

/** DNS header structure */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((__packed__)) dns_hdr;

#endif

#ifdef WIN32

#define PACKED
#pragma pack(push,1)

typedef struct {
        uint16_t qtype;
        uint16_t qclass;
} PACKED dns_question;

typedef struct {
        uint16_t type;
        uint16_t class;
        uint32_t ttl;
        uint16_t rdlength;
} PACKED dns_rr;

#pragma pack(pop)
#undef PACKED

#else 

typedef struct {
    uint16_t qtype;
    uint16_t qclass;
} __attribute__((__packed__)) dns_question;

typedef struct {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
} __attribute__((__packed__)) dns_rr;

#endif

/** DNS Type */
enum dns_type {
    type_A     = 1, /*!< a host address */
    type_NS    = 2, /*!< an authoritative name server */
    type_MD    = 3, /*!< a mail destination (Obsolete - use MX) */
    type_MF    = 4, /*!< a mail forwarder (Obsolete - use MX) */
    type_CNAME = 5, /*!< the canonical name for an alias */
    type_SOA   = 6, /*!< marks the start of a zone of authority */
    type_MB    = 7, /*!< a mailbox domain name (EXPERIMENTAL) */
    type_MG    = 8, /*!< a mail group member (EXPERIMENTAL) */
    type_MR    = 9, /*!< a mail rename domain name (EXPERIMENTAL) */
    type_NULL  = 10, /*!< a null RR (EXPERIMENTAL) */
    type_WKS   = 11, /*!< a well known service description */
    type_PTR   = 12, /*!< a domain name pointer */
    type_HINFO = 13, /*!< host information */
    type_MINFO = 14, /*!< mailbox or mail list information */
    type_MX    = 15, /*!< mail exchange */
    type_TXT   = 16, /*!< text strings */
    type_AAAA  = 28  /*!< a IPv6 host address */
};

/** DNS classes */
enum dns_class {
    class_IN = 1, /*!< the Internet */
    class_CS = 2, /*!< the CSNET class (Obsolete) */
    class_CH = 3, /*!< the CHAOS class */
    class_HS = 4  /*!< Hesiod [Dyer 87] */
};

/** determine if its a label */
#define char_is_label(c)  (((c) & 0xC0) == 0)

/** determine if its an offset */
#define char_is_offset(c) (((c) & 0xC0) == 0xC0)

/** DNS Output Name Length */
#define DNS_OUTNAME_LEN 256

/** DNS error codes */
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

/* advance the data position */
static enum dns_err data_advance (char **data, int *len, unsigned int size) {
    unsigned int tlen = (unsigned int)*len;

    if (tlen < size) {
        return dns_err_malformed;
    } 
    *data += size;
    *len -= size;  
    return dns_ok;
}

/* parse DNS question */
static enum dns_err dns_question_parse (const dns_question **q, char **data, int *len) {
    if (*len < (int)sizeof(dns_question)) {
        return dns_err_malformed;
    } 
        *q = (const dns_question*)*data;
    *data += sizeof(dns_question);
    *len -= sizeof(dns_question);  
    return dns_ok;
}

/* parse DNS rr */
static enum dns_err dns_rr_parse (const dns_rr **r, char **data, int *len, int *rdlength) {

    if (*len < (int)sizeof(dns_rr)) {
        return dns_err_malformed;
    } 

    *r = (const dns_rr*)*data;
    if (*len < ntohs((*r)->rdlength)) {
        return dns_err_rdata_too_long;
    }

    *rdlength = ntohs((*r)->rdlength);
    *data += sizeof(dns_rr);  
    *len -= sizeof(dns_rr);  
    return dns_ok;
}

/* parse DNS address */
static enum dns_err dns_addr_parse (const struct in_addr **a, char **data, int *len, unsigned short int rdlength) {
    if (*len < (int)sizeof(struct in_addr)) {
        return dns_err_malformed;
    } 
    if (rdlength != sizeof(struct in_addr)) {
        return dns_err_bad_rdlength;
    }
    *a = (const struct in_addr*)*data;
    *data += sizeof(struct in_addr);
    *len -= sizeof(struct in_addr);  
    return dns_ok;
}

/* parse DNS IPV6 address */
static enum dns_err dns_ipv6_addr_parse (const struct in6_addr **a, char **data, int *len, unsigned short int rdlength) {
    if (*len < (int)sizeof(struct in6_addr)) {
        return dns_err_malformed;
    }
    if (rdlength != sizeof(struct in6_addr)) {
        return dns_err_bad_rdlength;
    }
    *a = (const struct in6_addr*)*data;
    *data += sizeof(struct in6_addr);
    *len -= sizeof(struct in6_addr);
    return dns_ok;
}

/* parse 16 bit value */
static enum dns_err uint16_parse (uint16_t **x, char **data, int *len) {
    if (*len < (int)sizeof(uint16_t)) {
        return dns_err_malformed;
    } 
    *x = (uint16_t*)*data;
    *data += sizeof(uint16_t);  
    *len -= sizeof(uint16_t);  
    return dns_ok;
}

static inline char printable(char c) {
    if (isprint(c)) {
        return c;
    }
    return '*';
}

static enum dns_err dns_header_parse_name (const dns_hdr *hdr, char **name, int *len,
                                           char *outname, unsigned int outname_len) {
    char *terminus = outname + outname_len;
    char *c = *name;
    unsigned char jump;
    int i;
    int offsetlen = (*name - (const char *)hdr) + *len; /* num bytes available after offset pointer */
    const char *offsetname;
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

    /* robustness check */
    if (*len <= 0 || outname > terminus || outname_len < 2) {
      return dns_err_unterminated;
    }
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
            offsetname = (const void *)((char *)hdr + (ntohs(*offset) & 0x3FFF));
            offsetlen -= (ntohs(*offset) & 0x3FFF);
            return dns_header_parse_name(hdr, (void *)&offsetname, &offsetlen, outname, outname_len);
        } else {
            return dns_err_label_malformed;
        }
    } 
    return dns_err_unterminated;
}

static enum dns_err dns_header_parse_mxname (const dns_hdr *hdr, char **name, int *len,
                                             char *outname, unsigned int outname_len) {
    char *terminus = outname + outname_len;
    char *c = *name;
    unsigned char jump;
    int i;
    int processed_preference = 0;
    int offsetlen = (*name - (const char *)hdr) + *len; /* num bytes available after offset pointer */
    const char *offsetname;
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

    /* robustness check */
    if (*len <= 0 || outname > terminus || outname_len < 2) {
      return dns_err_unterminated;
    }
    outname[1] = 0;         /* set output to "", in case of error */
    while (*len > 0 && outname < terminus) {
        if (char_is_label(*c)) {
            /* first 2 bytes of the MX label is the preference */
            if (!processed_preference) {
                c += 2;
                *len -= 2;
                processed_preference = 1;
            }
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
            offsetname = (const void *)((char *)hdr + (ntohs(*offset) & 0x3FFF));
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
static enum dns_err
dns_rdata_print (const dns_hdr *rh, const dns_rr *rr, char **r, int *len, zfile output) {
    enum dns_err err;
    uint16_t class = ntohs(rr->class);
    uint16_t type = ntohs(rr->type);
    char ipv4_addr[INET_ADDRSTRLEN];
    char ipv6_addr[INET6_ADDRSTRLEN];
    char name[DNS_OUTNAME_LEN];

    if (class == class_IN) {    
        if (type == type_A) {
            const struct in_addr *addr;;
      
            err = dns_addr_parse(&addr, r, len, ntohs(rr->rdlength));
            if (err != dns_ok) {
                return err;
            }
            if (ipv4_addr_needs_anonymization(addr)) {
                char buffer[IPV4_ANON_LEN];
                addr_get_anon_hexstring(addr, (char*)buffer, IPV4_ANON_LEN);
                zprintf(output, "\"a\":\"%s\"", buffer);
            } else {
                inet_ntop(AF_INET, addr, ipv4_addr, INET_ADDRSTRLEN);
                zprintf(output, "\"a\":\"%s\"", ipv4_addr);
            }
        } else if (type == type_AAAA) {
            const struct in6_addr *addr;;

            err = dns_ipv6_addr_parse(&addr, r, len, ntohs(rr->rdlength));
            if (err != dns_ok) {
                return err;
            }
            inet_ntop(AF_INET6, addr, ipv6_addr, INET6_ADDRSTRLEN);
            zprintf(output, "\"aaaa\":\"%s\"", ipv6_addr);
        } else if (type == type_SOA  || type == type_PTR || type == type_CNAME || type == type_NS || type == type_MX) {
            const char *typename;

            /* mail exchange has a 2-byte preference before the name */
            if (type == type_MX) {
                err = dns_header_parse_mxname(rh, r, len, name, (DNS_OUTNAME_LEN-1)); /* note: does not check rdlength */
            } else {
                err = dns_header_parse_name(rh, r, len, name, (DNS_OUTNAME_LEN-1)); /* note: does not check rdlength */
            }
            if (err != dns_ok) { 
                return err; 
            }

            /* get the typename */
            if (type == type_SOA) {
                typename = "soa";
            } else if (type == type_PTR) {
                typename = "ptr";
            } else if (type == type_NS) {
                typename = "ns";
            } else if (type == type_MX) {
                typename = "mx";
            } else {
                typename = "cname";
            }
            zprintf(output, "\"%s\":\"%s\"", typename, name + 1);

            /* advance to end of the resource record */
            if (*len-1 > 0) {
                err = data_advance(r, len, *len-1);
                if (err != dns_ok) {
                    return err;
                }
            }

        } else if (type == type_TXT) {
            zprintf(output, "\"txt\":\"%s\"", "NYI");

        } else {
            err = data_advance(r, len, ntohs(rr->rdlength));
            if (err != dns_ok) {
                return err;
            }
            zprintf(output, "\"type\":\"%x\",\"class\":\"%x\",\"rdlength\":%u", type, class, ntohs(rr->rdlength));
      
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
        zprintf(output, "\"type\":\"%x\",\"class\":\"%x\",\"rdlength\":%u", type, class, ntohs(rr->rdlength));
    }
    return dns_ok;
}

static void dns_print_packet (char *dns_name, unsigned int pkt_len, zfile output) {
    enum dns_err err = 0;
    char *r = NULL;
    const dns_hdr *rh = NULL;
    const dns_question *question = NULL;
    const dns_rr *rr;
    int len = 0;
    uint8_t flags_rcode = 0;
    uint8_t flags_qr = 0;
    char qr = 0;
    uint16_t qdcount = 0, ancount = 0, nscount = 0, arcount = 0;
    int rdlength = 0;
    unsigned comma = 0;
    char name[DNS_OUTNAME_LEN];
  
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

    if (pkt_len < sizeof(dns_hdr)) {
      zprintf(output, "\"malformed\":%d", len);
      return;
    }
    
    len = pkt_len;
    r = dns_name;
    rh = (const dns_hdr*)r;
    flags_rcode = ntohs(rh->flags) & 0x000f;
    flags_qr = ntohs(rh->flags) >> 15;
    if (flags_qr == 0) {
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
        zprintf_debug(output, "qdcount=%u; err=%u\"}", qdcount, err);
      return;
    }

    memset_s(name, DNS_OUTNAME_LEN, 0x00, DNS_OUTNAME_LEN);
    while (qdcount-- > 0) {
        /* parse question name and struct */
        err = dns_header_parse_name(rh, &r, &len, name, (DNS_OUTNAME_LEN-1));
        if (err != dns_ok) { 
            zprintf(output, "\"malformed\":%d", len);
            zprintf_debug(output, "question name err=%u; len=%u\"}", err, len);
            return;
        }
        err = dns_question_parse(&question, &r, &len);
        if (err != dns_ok) {
            zprintf(output, "\"malformed\":%d", len);
            zprintf_debug(output, "question err=%u; len=%u\"}", err, len);
            return;
        }
        zprintf(output, "\"%cn\":\"%s\",", qr, name + 1);
    }
    zprintf(output, "\"rc\":%u,\"rr\":[", flags_rcode);

    ancount = ntohs(rh->ancount); 
    comma = 0;
    memset_s(name, DNS_OUTNAME_LEN, 0x00, DNS_OUTNAME_LEN);
    while (ancount-- > 0) {
        if (comma++) {
            zprintf(output, ",");
        }
        zprintf(output, "{");
        /* parse rr name, struct, and rdata */
        err = dns_header_parse_name(rh, &r, &len, name, (DNS_OUTNAME_LEN-1));
        if (err != dns_ok) { 
            zprintf(output, "\"malformed\":%d", len);
            zprintf_debug(output, "rr name ancount=%u; err=%u; len=%u\"}]}", ancount, err, len);
            return;
        }
        err = dns_rr_parse(&rr, &r, &len, &rdlength);
        if (err) {
            zprintf(output, "\"malformed\":%d", len);
            zprintf_debug(output, "rr ancount=%u; err=%u; len=%u\"}]}", ancount, err, len);
            return;
        }
        err = dns_rdata_print(rh, rr, &r, &rdlength, output);
        if (err) {
            zprintf(output, "\"malformed\":%d}]}", len);
            return;
        }
        len -= rdlength;
        if (rdlength > 1) {
            r += (rdlength - 1);
            rdlength = 1;
        }
        zprintf(output, ",\"ttl\":%u}", ntohl(rr->ttl));
    }

    nscount = ntohs(rh->nscount);
    if (rdlength > 1) {
        r += (rdlength - 1);
    }
    memset_s(name, DNS_OUTNAME_LEN, 0x00, DNS_OUTNAME_LEN);
    while (nscount-- > 0) {
        if (comma++) {
            zprintf(output, ",");
        }
        zprintf(output, "{");
        /* parse rr name, struct, and rdata */
        err = dns_header_parse_name(rh, &r, &len, name, (DNS_OUTNAME_LEN-1));
        if (err != dns_ok) {
            zprintf(output, "\"malformed\":%d", len);
            zprintf_debug(output, "rr name nscount=%u; err=%u; len=%u\"}]}", nscount, err, len);
            return;
        }
        err = dns_rr_parse(&rr, &r, &len, &rdlength);
        if (err) {
            zprintf(output, "\"malformed\":%d", len);
            zprintf_debug(output, "rr nscount=%u; err=%u; len=%u\"}]}", nscount, err, len);
            return;
        }
        err = dns_rdata_print(rh, rr, &r, &rdlength, output);
        if (err) {
            zprintf(output, "\"malformed\":%d}]}", len);
            return;
        }
        len -= rdlength;
        if (rdlength > 1) {
            r += (rdlength - 1);
            rdlength = 1;
        }
        zprintf(output, ",\"ttl\":%u}", ntohl(rr->ttl));
    }

    arcount = ntohs(rh->arcount);
    if (rdlength > 1) {
        r += (rdlength - 1);
    }
    memset_s(name, DNS_OUTNAME_LEN, 0x00, DNS_OUTNAME_LEN);
    while (arcount-- > 0) {
        if (comma++) {
            zprintf(output, ",");
        }
        zprintf(output, "{");
        /* parse rr name, struct, and rdata */
        err = dns_header_parse_name(rh, &r, &len, name, (DNS_OUTNAME_LEN-1));
        if (err != dns_ok) {
            zprintf(output, "\"malformed\":%d", len);
            zprintf_debug(output, "rr name arcount=%u; err=%u; len=%u\"}]}", arcount, err, len);
            return;
        }
        err = dns_rr_parse(&rr, &r, &len, &rdlength);
        if (err) {
            zprintf(output, "\"malformed\":%d", len);
            zprintf_debug(output, "rr arcount=%u; err=%u; len=%u\"}]}", arcount, err, len);
            return;
        }
        err = dns_rdata_print(rh, rr, &r, &rdlength, output);
        if (err) {
            zprintf(output, "\"malformed\":%d}]}", len);
            return;
        }
        len -= rdlength;
        if (rdlength > 1) {
            r += (rdlength - 1);
            rdlength = 1;
        }
        zprintf(output, ",\"ttl\":%u}", ntohl(rr->ttl));
    }
    zprintf(output, "]}");
    return;
}

static void dns_printf (char * const dns_name[], const unsigned short pkt_len[], 
                char * const twin_dns_name[], const unsigned short twin_pkt_len[], 
                unsigned int count, zfile output) {
    unsigned int i = 0;

    zprintf(output, ",\"dns\":[");
  
    /* if a twin exists, print out that data */
    if (twin_dns_name) { /* bidirectional flow */
        for (i=0; i<count; i++) {
            zprintf(output, ",");
            if (twin_dns_name[i]) {
                dns_print_packet(twin_dns_name[i], twin_pkt_len[i], output);
            }
        }
    } else {
        /* unidirectional flow */
        /* print out the data from the primary record */
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


/**
 * \fn void dns_unit_test ()
 * \param none
 * \return none
 */
void dns_unit_test () {
    enum dns_err err;
    dns_hdr hdr;
    char name[MAX_DNS_NAME_LEN] = { 
        0x03, 0x77, 0x77, 0x77, 0x06, 0x6F, 0x72, 0x77, 
        0x65, 0x6C, 0x6C, 0x02, 0x72, 0x75, 0x00
    };
    char name2[MAX_DNS_NAME_LEN];
    void *c = &name;
    int len = 15;

    assert(sizeof(dns_hdr) == 12);
    assert(sizeof(dns_question) == 4);
    assert(sizeof(dns_rr) == 10);
  
    err = dns_header_parse_name(&hdr, (char**)&c, &len, name2, sizeof(name2));
  
    printf("name: %s\tlen: %u\terr: %u\n", name2, len, err);
}


/**
 * \brief Initialize the memory of DNS struct.
 *
 * \param dns_handle contains dns structure to initialize
 *
 * \return none
 */
void dns_init (dns_t **dns_handle) {
    if (*dns_handle != NULL) {
        dns_delete(dns_handle);
    }

    *dns_handle = calloc(1, sizeof(dns_t));
    if (*dns_handle == NULL) {
        /* Allocation failed */
        joy_log_err("malloc failed");
        return;
    }
}

/**
 * \brief Delete the memory of DNS struct.
 *
 * \param dns_handle contains dns structure to delete
 *
 * \return none
 */
void dns_delete (dns_t **dns_handle) {
    unsigned int i;
    dns_t *dns = *dns_handle;

    if (dns == NULL) {
        return;
    }

    for (i=0; i<dns->pkt_count; i++) {
        if (dns->dns_name[i]) {
            free(dns->dns_name[i]);
        }
    }

    /* Free the memory and set to NULL */
    free(dns);
    *dns_handle = NULL;
}

/**
 * \fn void dns_update (dns_t *dns,
 *                      const struct pcap_pkthdr *header,
                        const void *start,
                        unsigned int len,
                        unsigned int report_dns)
 * \param dns DNS structure pointer
 * \param header pointer to the pcap packet header
 * \param start pointer to the update data
 * \param len length of the update data
 * \param report_dns determine if we can report DNS info
 * \return none
 */
void dns_update (dns_t *dns, const struct pcap_pkthdr *header, const void *start, unsigned int len, unsigned int report_dns) {
    if (report_dns == 0) {
        return;  /* we are not configured to report DNS information */
    }

    /* sanity check */
    if (dns == NULL) {
        return;
    }

    joy_log_debug("dns[%p],header[%p],data[%p],len[%d],report[%d]",
            dns,header,start,len,report_dns);

    if (dns->pkt_count >= MAX_NUM_DNS_PKT) {
        return;  /* no more room */
    }  

    if (len < 13) {
        return;  /* not long enough to be a proper DNS packet */
    }

    if (!dns->dns_name[dns->pkt_count]) {
        dns->dns_name[dns->pkt_count] = calloc(1, len);
        if (dns->dns_name[dns->pkt_count] == NULL) {
            return; /* failure */
        }
        memcpy_s(dns->dns_name[dns->pkt_count], len, start, len);
        dns->pkt_len[dns->pkt_count] = len;
        dns->pkt_count++;
    }

    return;  /* ok */
}

/**
 * \fn void dns_print_json (const dns_t *dns1, const dns_t *dns2, zfile f)
 * \param dns1 pointer to DNS structure
 * \param dn2 pointer to DNS structure
 * \param f output file
 * \return none
 */
void dns_print_json (const dns_t *dns1, const dns_t *dns2, zfile f) {
    unsigned int count = 0;
  
    /* should never get called with null dns1 handle*/
    if (dns1 == NULL)
        return;

    count = dns1->pkt_count > MAX_NUM_DNS_PKT ? MAX_NUM_DNS_PKT : dns1->pkt_count;

    if (dns2) {
        count = dns2->pkt_count > MAX_NUM_DNS_PKT ? MAX_NUM_DNS_PKT : dns2->pkt_count;
    }

    if ((count == 0) || (count > MAX_NUM_DNS_PKT)) {
        joy_log_info("DNS count out of bounds (%d)", count);
        return;  /* no DNS data to report */
    }
 
    if (dns2) {
        dns_printf(dns1->dns_name, dns1->pkt_len, dns2->dns_name, dns2->pkt_len, count, f);
    } else {
        dns_printf(dns1->dns_name, dns1->pkt_len, NULL, NULL, count, f);
    }
}


/*
 * END of dns feature functions
 */
