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

/**
 * \file dhcp.c
 *
 * \brief Dynamic Host Configuration Protocol (DHCP) awareness
 * 
 */
#include <stdlib.h>
#include <string.h>   /* for memset()    */
#include <netinet/in.h>
#include "dhcp.h"
#include "p2f.h"
#include "utils.h"


/********************************************
 *********
 * LOGGING
 *********
 ********************************************/
/** select destination for printing out information
 *
 ** TO_SCREEN = 0 for 'info' file
 *
 **  TO_SCREEN = 1 for 'stderr'
 */
#define TO_SCREEN 1

/** used to print out information during tls execution
 *
 ** print_dest will either be assigned to 'stderr' or 'info' file
 *  depending on the TO_SCREEN setting.
 */
static FILE *print_dest = NULL;
extern FILE *info;

/** sends information to the destination output device */
#define loginfo(...) { \
        if (TO_SCREEN) print_dest = stderr; else print_dest = info; \
        fprintf(print_dest,"%s: ", __FUNCTION__); \
        fprintf(print_dest, __VA_ARGS__); \
        fprintf(print_dest, "\n"); }

/**
 * 
 * \brief Initialize the memory of DHCP struct \r.
 *
 * \param dhcp structure to initialize
 *
 * \return none
 */
void dhcp_init(struct dhcp *dhcp)
{
    if (dhcp == NULL) {
        loginfo("api-error: dhcp is null");
        return;
    }

    memset(dhcp, 0, sizeof(struct dhcp));
}

/**
 * \brief Clear and free memory of DHCP struct \r.
 *
 * \param dhcp pointer to dhcp stucture
 *
 * \return none
 */
void dhcp_delete(struct dhcp *dhcp)
{
    int i = 0;

    if (dhcp == NULL) {
        loginfo("api-error: dhcp is null");
        return;
    }

    for (i = 0; i < dhcp->message_count; i++) {
        int k = 0;

        if (dhcp->messages[i].sname) {
            free(dhcp->messages[i].sname);
        }
        
        if (dhcp->messages[i].file) {
            free(dhcp->messages[i].file);
        }

        for (k = 0; k < dhcp->messages[i].options_count; k++) {
            /* Free up memory in the options */
            if (dhcp->messages[i].options[k].value) {
                free(dhcp->messages[i].options[k].value);
            }
        }
    }

    memset(dhcp, 0, sizeof(struct dhcp));
    //free(dhcp);
    //dhcp = NULL;
}

void dhcp_update(struct dhcp *dhcp,
                 const struct pcap_pkthdr *header,
                 const void *data,
                 unsigned int data_len,
                 unsigned int report_dhcp)
{
    const unsigned char *ptr = (unsigned char *)data;
    struct dhcp_message *msg = NULL;
    const unsigned char magic_cookie[] = {0x63, 0x82, 0x53, 0x63};

    /* Check run flag. Bail if 0 */
    if (!report_dhcp) {
        return;
    }

    /* Allocate struct if needed and initialize */
    if (dhcp == NULL) {
        dhcp = malloc(sizeof(struct dhcp));
        if (dhcp != NULL) {
            dhcp_init(dhcp);
        }
    }

    /* Make sure there's space to record another message */
    if (dhcp->message_count >= MAX_DHCP_LEN) {
        loginfo("error: dhcp struct cannot hold any more messages");
        return;
    }

    msg = &dhcp->messages[dhcp->message_count];

    /* op */
    msg->op = *ptr; 
    ptr += 1;

    msg->htype = *ptr;
    ptr += 1;

    msg->hlen = *ptr;
    ptr += 1;

    msg->hops = *ptr;
    ptr += 1;

    msg->xid = ntohl(*(const uint32_t *)ptr);
    ptr += sizeof(uint32_t);

    msg->secs = ntohs(*(const uint16_t *)ptr);
    ptr += sizeof(uint16_t);

    msg->flags = ntohs(*(const uint16_t *)ptr);
    ptr += sizeof(uint16_t);

    msg->ciaddr = ntohl(*(const uint32_t *)ptr);
    ptr += sizeof(uint32_t);

    msg->yiaddr = ntohl(*(const uint32_t *)ptr);
    ptr += sizeof(uint32_t);

    msg->siaddr = ntohl(*(const uint32_t *)ptr);
    ptr += sizeof(uint32_t);

    msg->giaddr = ntohl(*(const uint32_t *)ptr);
    ptr += sizeof(uint32_t);

    memcpy(msg->chaddr, ptr, MAX_DHCP_CHADDR);
    ptr += MAX_DHCP_CHADDR;

    if (*ptr != 0) {
        /* Server host name exists so alloc and copy it */
        msg->sname = malloc(MAX_DHCP_SNAME);
        memset(msg->sname, 0, MAX_DHCP_SNAME);
        strncpy(msg->sname, (const char *)ptr, MAX_DHCP_SNAME);
        msg->sname[MAX_DHCP_SNAME - 1] = '\0';
    }
    ptr += MAX_DHCP_SNAME;

    if (*ptr != 0) {
        /* Boot file name exists so alloc and copy it */
        msg->file = malloc(MAX_DHCP_FILE);
        memset(msg->file, 0, MAX_DHCP_FILE);
        strncpy(msg->file, (const char *)ptr, MAX_DHCP_FILE);
        msg->file[MAX_DHCP_FILE - 1] = '\0';
    }
    ptr += MAX_DHCP_FILE;

    /* Verify magic cookie */
    if (memcmp(ptr, &magic_cookie, sizeof(magic_cookie)) != 0) {
        //loginfo("error: bad magic cookie");
        return;
    }
    ptr += 4;

    /* Loop until "end" option is encountered */
    while (*ptr != 255) {
        unsigned int index = msg->options_count;
        unsigned char opt_len = 0;

        if (msg->options_length >= MAX_DHCP_OPTIONS_LEN || index >= MAX_DHCP_OPTIONS) {
            /* Exceeded the max allowed options length or count */
            break;
        }

        if (*ptr == 0) {
            /* Skip padding option */
            ptr += 1;
            continue;
        }

        /* Get the option code */
        msg->options[index].code = *ptr;
        msg->options_length += 1;
        ptr += 1;

        /* Get the option length */
        opt_len = *ptr;
        msg->options[index].len = opt_len;
        msg->options_length += 1;
        ptr += 1;

        if (opt_len != 0) {
            /* Allocate memory for the option data */
            msg->options[index].value = malloc(opt_len);

            memcpy(msg->options[index].value, ptr, opt_len);

            ptr += opt_len;
            msg->options_length += opt_len;
        }

        msg->options_count += 1; 
    }

    dhcp->message_count += 1;
}

void dhcp_print_json(const struct dhcp *d1,
                     const struct dhcp *d2,
                     zfile f)
{
    int i = 0;

    if (d1->message_count) {
        zprintf(f, ",\"dhcp\":[");
        for (i = 0; i < d1->message_count; i++) {
            const struct dhcp_message *msg = &d1->messages[i];
            int k = 0;

            zprintf(f, "{");
            zprintf(f, "\"op\":\"%u\"", msg->op);
            zprintf(f, ",\"htype\":\"%u\"", msg->htype);
            zprintf(f, ",\"hlen\":\"%u\"", msg->hlen);
            zprintf(f, ",\"hops\":\"%u\"", msg->hops);
            zprintf(f, ",\"xid\":\"%u\"", msg->xid);
            zprintf(f, ",\"secs\":\"%u\"", msg->secs);
            zprintf(f, ",\"flags\":\"%u\"", msg->flags);
            zprintf(f, ",\"ciaddr\":\"%u\"", msg->ciaddr);
            zprintf(f, ",\"yiaddr\":\"%u\"", msg->yiaddr);
            zprintf(f, ",\"siaddr\":\"%u\"", msg->siaddr);
            zprintf(f, ",\"giaddr\":\"%u\"", msg->giaddr);
            zprintf(f, ",\"chaddr\":");
            zprintf_raw_as_hex(f, msg->chaddr, sizeof(msg->chaddr));
            if (msg->sname != NULL) {
                zprintf(f, ",\"sname\":\"%s\"", msg->sname);
            }
            if (msg->file != NULL) {
                zprintf(f, ",\"file\":\"%s\"", msg->file);
            }

            if (msg->options_count) {
                zprintf(f, ",\"options\":[");
                for (k = 0; k < msg->options_count; k++) {
                    const struct dhcp_option *opt = &msg->options[k];
                    zprintf(f, "{");

                    zprintf(f, "\"code\":\"%u\"", opt->code);
                    zprintf(f, ",\"len\":\"%u\"", opt->len);
                    if (opt->value != NULL && opt->len != 0) {
                        zprintf(f, ",\"value\":");
                        zprintf_raw_as_hex(f, opt->value, opt->len);
                    }

                    if (k == (msg->options_count - 1)) {
                        zprintf(f, "}");
                    } else {
                        zprintf(f, "},");
                    }
                }
                zprintf(f, "]");
            }

            if (i == (d1->message_count - 1)) {
                zprintf(f, "}");
            } else {
                zprintf(f, "},");
            }
        }
        zprintf(f, "]");
    }
}

/**
 * \brief Unit test for DHCP
 * \param none
 * \return none
 */
void dhcp_unit_test()
{
    /* NYI */
}

