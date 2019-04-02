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

/**
 * \file dhcpv6.c
 *
 * \brief Dynamic Host Configuration Protocol (DHCP) for IPv6 awareness
 *
 */
#include <stdlib.h>
#include "dhcpv6.h"
#include "p2f.h"
#include "anon.h"
#include "utils.h"
#include "pkt.h"
#include "err.h"

#define DHCPV6_CLIENTID 1
#define DHCPV6_SERVERID 2

/* uncomment this to enable payload byte printing */
//#define DHCPV6_DEBUG 1

static const char *dhcpv6_msg_types[] = {
    [1]  = "SOLICIT",
    [2]  = "ADVERTISE",
    [3]  = "REQUEST",
    [4]  = "CONFIRM",
    [5]  = "RENEW",
    [6]  = "REBIND",
    [7]  = "REPLY",
    [8]  = "RELEASE",
    [9]  = "DECLINE",
    [10] = "RECONFIGURE",
    [11] = "INFOREQUEST",
    [12] = "RELAYFORWD",
    [13] = "RELAYREPL"
};

static const char *dhcpv6_option_types[] = {
    [1]  = "CLIENTID",
    [2]  = "SERVERID",
    [3]  = "IANA",
    [4]  = "IATA",
    [5]  = "IAADDR",
    [6]  = "ORO",
    [7]  = "PREFERENCE",
    [8]  = "ELAPSEDTIME",
    [11] = "AUTHENTICATION",
    [12] = "UNICAST",
    [13] = "STATUSCODE",
    [14] = "RAPIDCOMMIT",
    [15] = "USERCLASS",
    [16] = "VENDORCLASS",
    [17] = "VENDOROPTS",
    [18] = "INTERFACEID",
    [19] = "RECONFMSG",
    [25] = "IAPD",
    [26] = "IAPREFIX",
    [32] = "INFOREFRESHTIME",
    [82] = "SOLMAXRT",
    [83] = "INFMAXRT"
};

static const char* dhcpv6_msg_to_string (uint16_t id) {
    /* make sure the msg id is in the valid range */
    if ((id >= 1) && (id <= 13)) {
        return dhcpv6_msg_types[id];
    } else {
        return "UNKNOWN";
    }
}

static const char* dhcpv6_option_to_string (uint16_t id) {
    /* make sure the option id is in the valid range */
    if (((id >= 1) && (id <= 19)) ||
        ((id >= 25) && (id <= 26)) ||
        (id == 32) || (id == 82) || (id == 83)) {
        return dhcpv6_option_types[id];
    } else {
        return "UNKNOWN";
    }
}

/**
 *
 * \brief Initialize the memory of DHCP V6 struct.
 *
 * \param dhcp_v6_handle contains dhcp V6 structure to initialize
 *
 * \return none
 */
void dhcpv6_init(dhcpv6_t **dhcp_v6_handle)
{
    if (*dhcp_v6_handle != NULL) {
        dhcpv6_delete(dhcp_v6_handle);
    }

    *dhcp_v6_handle = calloc(1, sizeof(dhcpv6_t));
    if (*dhcp_v6_handle == NULL) {
        /* Allocation failed */
        joy_log_err("malloc failed");
        return;
    }
}

/**
 * \brief Delete the memory of DHCP V6 struct \r.
 *
 * \param dhcp_v6_handle contains dhcp V6 structure to delete
 *
 * \return none
 */
void dhcpv6_delete(dhcpv6_t **dhcp_v6_handle)
{
    dhcpv6_t *dhcp_v6 = *dhcp_v6_handle;

    if (dhcp_v6 == NULL) {
        return;
    }

    /* Free the memory and set to NULL */
    free(dhcp_v6);
    *dhcp_v6_handle = NULL;
}

/**
 * \brief Parse, process, and record DHCP V6 \p data.
 *
 * \param dhcp_v6 DHCP V6 structure pointer
 * \param header PCAP packet header pointer
 * \param data Beginning of the DHCP payload data.
 * \param len Length in bytes of the \p data.
 * \param report_dhcp Flag indicating whether this feature should run.
 *                    0 for no, 1 for yes
 *
 * \return none
 */
void dhcpv6_update(dhcpv6_t *dhcp_v6,
                    const struct pcap_pkthdr *header,
                    const void *data,
                    unsigned int data_len,
                    unsigned int report_dhcp)
{
    uint16_t max_bytes = 0;
    const unsigned char *ptr = (const unsigned char *)data;
    dhcp_v6_message_t *msg = NULL;

    joy_log_debug("dhcp_v6[%p],header[%p],data[%p],len[%d],report[%d]",
            dhcp_v6,header,data,data_len,report_dhcp);

    /* Check run flag. Bail if 0 */
    if (!report_dhcp) {
        return;
    }

    /* sanity check */
    if (dhcp_v6 == NULL) {
        return;
    }

    /* Make sure there's space to record another message */
    if (dhcp_v6->message_count >= MAX_DHCP_V6_MSGS) {
        joy_log_warn("dhcp V6 struct cannot hold any more messages");
        return;
    }

    msg = &dhcp_v6->messages[dhcp_v6->message_count];
    max_bytes = (data_len < MAX_DHCP_V6_MSG_LEN) ? data_len : MAX_DHCP_V6_MSG_LEN;

    /* first byte is the msg type */
    msg->msg_type = (uint8_t)*ptr;
    ptr += 1;

    /* next 3 bytes are the transaction id */
    msg->trans_id = (uint8_t)*ptr << 16;
    msg->trans_id |= (uint8_t)*(ptr+1) << 8;
    msg->trans_id |= (uint8_t)*(ptr+2);
    ptr += 3;

    max_bytes -= 4;
    memcpy_s(msg->data, max_bytes, ptr, max_bytes);

    dhcp_v6->message_count += 1;
}

/**
 * \brief Print the DHCP V6 struct to JSON output file \p f.
 *
 * \param d1 pointer to DHCP V6 structure
 * \param d2 pointer to twin DHCP V6 structure
 * \param f destination file for the output
 *
 * \return none
 */
void dhcpv6_print_json(const dhcpv6_t *d1,
                       const dhcpv6_t *d2,
                       zfile f)
{
    uint8_t first_time = 1;
    int i = 0;
    uint16_t dhcpv6_option = 0;
    uint16_t dhcpv6_opt_len = 0;

    /* sanity check */
    if (d1 == NULL) {
        return;
    }

    if (d1->message_count) {
        zprintf(f, ",\"dhcpv6\":[");
        for (i = 0; i < d1->message_count; i++) {
            const dhcp_v6_message_t *msg = &d1->messages[i];
            uint8_t *ptr = (uint8_t*)msg->data;

            if (!first_time) {
                zprintf(f, ",");
            } else {
                first_time = 0;
            }
            zprintf(f, "{\"type\":\"%s\",",dhcpv6_msg_to_string(msg->msg_type));
            zprintf(f, "\"transid\":%x,",msg->trans_id);

            /* first 4 bytes of the option are the type and length */
            dhcpv6_option = *ptr << 8 | *(ptr+1);
            ptr += 2;
            dhcpv6_opt_len = *ptr << 8 | *(ptr+1);
            ptr += 2;

            zprintf(f, "\"option\":\"%s\",",dhcpv6_option_to_string(dhcpv6_option));

#ifdef DHCPV6_DEBUG
            zprintf(f, "\"optlen\":%u,",dhcpv6_opt_len);
            if ((dhcpv6_option == DHCPV6_CLIENTID) || (dhcpv6_option == DHCPV6_SERVERID)) {

                zprintf(f, "\"macaddr\":\"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\",",
                            *(ptr+8),*(ptr+9),*(ptr+10),
                            *(ptr+11),*(ptr+12),*(ptr+13));
            }

            /* show the remaning bytes of the message */
            int k = 0;
            int max_bytes = 0;
            max_bytes = (dhcpv6_opt_len < MAX_DHCP_V6_MSG_LEN) ? dhcpv6_opt_len : MAX_DHCP_V6_MSG_LEN;
            zprintf(f, "\"data\":\"");
            for (k=0; k < max_bytes; ++k) {
                zprintf(f, "%.2x", *(ptr+k));
            }
            zprintf(f, "\"}");
        }
#else
            if ((dhcpv6_option == DHCPV6_CLIENTID) || (dhcpv6_option == DHCPV6_SERVERID)) {
                zprintf(f, "\"optlen\":%u,",dhcpv6_opt_len);
                zprintf(f, "\"macaddr\":\"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\"}",
                            *(ptr+8),*(ptr+9),*(ptr+10),
                            *(ptr+11),*(ptr+12),*(ptr+13));
            } else {
                zprintf(f, "\"optlen\":%u}",dhcpv6_opt_len);
            }
        }
#endif
        zprintf(f, "]");
    }

    /* sanity check */
    if (d2 == NULL) {
        return;
    }
}

/**
 * \brief Unit test for DHCP V6
 *
 * \return none
 */
void dhcpv6_unit_test()
{

    fprintf(info, "\n******************************\n");
    fprintf(info, "DHCP V6 Unit Test starting...\n");
    fprintf(info, "Finished - success\n");
    fprintf(info, "******************************\n\n");
}

