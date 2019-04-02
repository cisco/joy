/*
 *
 * Copyright (c) 2019 Cisco Systems, Inc.
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
 * \file dhcpv6.h
 *
 * \brief Dynamic Host Configuration Protocol (DHCP) IPv6 awareness
 *
 */

#ifndef DHCPV6_H
#define DHCPV6_H

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

#define dhcpv6_usage "  dhcp=1                     report dhcp information\n"

#define dhcpv6_filter(record) \
    ((record->key.prot == 17) && \
      ((record->key.sp == 547 && record->key.dp == 546) || (record->key.sp == 546 && record->key.dp == 547)) \
    )

#define MAX_DHCP_V6_MSGS 10
#define MAX_DHCP_V6_MSG_LEN 64

typedef struct dhcp_v6_message_ {
    uint8_t msg_type;
    uint32_t trans_id;
    uint8_t data[MAX_DHCP_V6_MSG_LEN];
} dhcp_v6_message_t;

typedef struct dhcp_v6_ {
    joy_role_e role;
    dhcp_v6_message_t messages[MAX_DHCP_V6_MSGS];
    uint16_t message_count;
} dhcpv6_t;

void dhcpv6_init(dhcpv6_t **dhcp_v6_handle);

void dhcpv6_update(dhcpv6_t *dhcp_v6,
                   const struct pcap_pkthdr *header,
                   const void *data,
                   unsigned int data_len,
                   unsigned int report_dhcp);

void dhcpv6_print_json(const dhcpv6_t *d1,
                       const dhcpv6_t *d2,
                       zfile f);

void dhcpv6_delete(dhcpv6_t **dhcp_v6_handle);

void dhcpv6_unit_test(void);

#endif /* DHCPV6_H */

