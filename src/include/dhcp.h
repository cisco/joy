/*
 *
 * Copyright (c) 2017 Cisco Systems, Inc.
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
 * \file dhcp.h
 *
 * \brief Dynamic Host Configuration Protocol (DHCP) protocol awareness
 *
 */

#ifndef DHCP_H
#define DHCP_H

#include <stdio.h>   /* for FILE* */
#include <stdint.h>
#include <pcap.h>
#include "output.h"
#include "utils.h"

#ifdef WIN32
# include <Winsock2.h>
#else
# include <netinet/in.h>
#endif

#define dhcp_usage "  dhcp=1                     report dhcp information\n"

#define dhcp_filter(record) \
    ((record->key.prot == 17) && \
     (record->app == 68 || \
      ((record->key.sp == 68 && record->key.dp == 67) || (record->key.sp == 67 && record->key.dp == 68)) \
     ) \
    )

#define MAX_DHCP_LEN 16
#define MAX_DHCP_CHADDR 16
#define MAX_DHCP_SNAME 64
#define MAX_DHCP_FILE 128
#define MAX_DHCP_OPTIONS 16
#define MAX_DHCP_OPTIONS_LEN 512

typedef struct dhcp_option_ {
    unsigned char code; /**< Typecode */
    unsigned char len; /**< Length (octets) of value */
    unsigned char *value; /**< Data value, if the string repr is found, this should not be used */
    const char *value_str; /**< String repr of value (IANA), should point to lookup table */
} dhcp_option_t;

typedef struct dhcp_message_ {
    unsigned char op; /**< Message type; 1=bootrequest, 2=bootreply */
    unsigned char htype; /**< Hardware address type */
    unsigned char hlen; /**< Hardware address length */
    unsigned char hops; /**< Number of relay hops */
    uint32_t xid; /**< Transaction ID */
    uint16_t secs; /**< Seconds since client began exchange */
    uint16_t flags; /**< Flags */
    struct in_addr ciaddr; /**< Client IP address */
    struct in_addr yiaddr; /**< IP address offered to client */
    struct in_addr siaddr; /**< Server IP address */
    struct in_addr giaddr; /**< Gateway IP address */
    unsigned char chaddr[MAX_DHCP_CHADDR]; /**< Client hardware (MAC) address */
    char *sname; /**< Optional server host name string */
    char *file; /**< Boot file name string */
    dhcp_option_t options[MAX_DHCP_OPTIONS]; /**< Optional paramaters RFC 2132 */
    uint16_t options_count;
    uint16_t options_length;
} dhcp_message_t;

typedef struct dhcp_ {
    joy_role_e role;
    dhcp_message_t messages[MAX_DHCP_LEN];
    uint16_t message_count;
} dhcp_t;

void dhcp_init(dhcp_t **dhcp_handle);

void dhcp_update(dhcp_t *dhcp,
                 const struct pcap_pkthdr *header,
                 const void *data,
                 unsigned int data_len,
                 unsigned int report_dhcp);

void dhcp_print_json(const dhcp_t *d1,
                     const dhcp_t *d2,
                     zfile f);

void dhcp_delete(dhcp_t **dhcp_handle);

void dhcp_unit_test(void);

#endif /* DHCP_H */

