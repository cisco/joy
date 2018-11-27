/*
 *
 * Copyright (c) 2017-2018 Cisco Systems, Inc.
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
#include "dhcp.h"
#include "p2f.h"
#include "anon.h"
#include "utils.h"
#include "pkt.h"
#include "err.h"

/**
 * \brief Table storing IANA DHCP option name strings
 *
 * The string values in this table have been adapted from:
 * https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
 */
static const char *dhcp_option_types[] = {
    [0]="pad", [1]="subnet_mask", [2]="time_offset", [3]="router",
    [4]="time_server", [5]="name_server", [6]="domain_server", [7]="log_server",
    [8]="quotes_server", [9]="lpr_server", [10]="impress_server", [11]="rlp_server",
    [12]="hostname", [13]="boot_file_size", [14]="merit_dump_file", [15]="domain_name",
    [16]="swap_server", [17]="root_path", [18]="extension_file", [19]="forward_on_off",
    [20]="src_rte_on_off", [21]="policy_filter", [22]="max_dg_assembly", [23]="default_ipttl",
    [24]="mtu_timeout", [25]="mtu_plateau", [26]="mtu_interface", [27]="mtu_subnet",
    [28]="broadcast_address", [29]="mask_discovery", [30]="mask_supplier", [31]="router_discovery",
    [32]="router_request", [33]="static_route", [34]="trailers", [35]="arp_timeout",
    [36]="ethernet", [37]="default_tcpttl", [38]="keepalive_time", [39]="keepalive_data",
    [40]="nis_domain", [41]="nis_servers", [42]="ntp_servers", [43]="vendor_specific",
    [44]="netbios_name_srv", [45]="netbios_dist_srv", [46]="netbios_node_type", [47]="netbios_scope",
    [48]="xwindow_font", [49]="xwindow_manager", [50]="address_request", [51]="address_time",
    [52]="overload", [53]="msg_type", [54]="server_id", [55]="parameter_list",
    [56]="message", [57]="max_msg_size", [58]="renewal_time", [59]="rebinding_time",
    [60]="class_id", [61]="client_id", [62]="netWare_ip_domain", [63]="netware_ip_option",
    [64]="nis_domain_name", [65]="nis_server_addr", [66]="server_name", [67]="bootfile_name",
    [68]="home_agent_addrs", [69]="smtp_server", [70]="pop3_server", [71]="nntp_server",
    [72]="www_server", [73]="finger_server", [74]="irc_server", [75]="street_talk_server",
    [76]="stda_server", [77]="user_class", [78]="directory_agent", [79]="service_scope",
    [80]="rapid_commit", [81]="client_fqdn", [82]="relay_agent_information", [83]="isns",
    [85]="nds_servers", [86]="nds_tree_name", [87]="nds_context",
    [88]="bcmcs_controller_domain_name_list", [89]="bcmcs_controller_ipv4_address",
    [90]="authentication", [91]="client_last_transaction_time",
    [92]="associated_ip", [93]="client_system", [94]="client_ndi", [95]="ldap",
    [97]="uuid_guid", [98]="user_auth", [99]="geoconf_civic",
    [100]="pcode", [101]="tcode",
    [112]="netinfo_address", [113]="netinfo_tag", [114]="url",
    [116]="auto_config", [117]="name_service_search", [118]="subnet_selection",
    [119]="domain_search", [120]="sip_servers", [121]="classless_static_route", [122]="ccc",
    [123]="geo_conf", [124]="vendor_class", [125]="vendor_specific_information",
    [136]="option_pana_agent", [137]="option_v4_lost", [138]="option_capwap_ac_v4",
    [139]="option_ipv4_address_mos",
    [140]="option_ipv4_fqdn_mos", [141]="sip_ua_configuration_service_domains",
    [142]="option_ipv4_address_andsf",
    [144]="geo_loc", [145]="forcerenew_nonce_capable", [146]="rdnss_selection",
    [150]="tftp_server_address|etherboot|grub_configuration_path_name", [151]="status_code",
    [152]="base_time", [153]="start_time_of_state",
    [154]="query_start_time", [155]="query_end_time",
    [156]="dhcp_state", [157]="data_source",
    [158]="option_v4_pcp_server", [159]="option_v4_portparams",
    [160]="captive_portal", [161]="option_mud_url_v4",
    [175]="etherboot",
    [176]="ip_telephone", [177]="etherboot|packetcable_cablehome",
    [208]="pxelinux_magic", [209]="configuration_file", [210]="path_prefix", [211]="reboot_time",
    [212]="option_6rd", [213]="option_v4_access_domain",
    [220]="subnet_allocation", [221]="virtual_subnet_selection",
    [255]="end"
};

#define MAX_DHCP_MSG_TYPE_STR 24

/**
 * \brief Table storing IANA DHCP message type value string representations
 *
 * https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml#message-type-53
 *
 */
static const char *dhcp_option_message_types[] = {
    [1]="DHCPDISCOVER", [2]="DHCPOFFER", [3]="DHCPREQUEST",
    [4]="DHCPDECLINE", [5]="DHCPACK", [6]="DHCPNAK",
    [7]="DHCPRELEASE", [8]="DHCPINFORM", [9]="DHCPFORCERENEW",
    [10]="DHCPLEASEQUERY", [11]="DHCPLEASEUNASSIGNED", [12]="DHCPLEASEUNKNOWN",
    [13]="DHCPLEASEACTIVE", [14]="DHCPBULKLEASEQUERY", [15]="DHCPLEASEQUERYDONE",
    [16]="DHCPACTIVELEASEQUERY", [17]="DHCPLEASEQUERYSTATUS", [18]="DHCPTLS"
};

/**
 *
 * \brief Initialize the memory of DHCP struct.
 *
 * \param dhcp_handle contains dhcp structure to initialize
 *
 * \return none
 */
void dhcp_init(dhcp_t **dhcp_handle)
{
    if (*dhcp_handle != NULL) {
        dhcp_delete(dhcp_handle);
    }

    *dhcp_handle = calloc(1, sizeof(dhcp_t));
    if (*dhcp_handle == NULL) {
        /* Allocation failed */
        joy_log_err("malloc failed");
        return;
    }
}

/**
 * \brief Delete the memory of DHCP struct \r.
 *
 * \param dhcp_handle contains dhcp structure to delete
 *
 * \return none
 */
void dhcp_delete(dhcp_t **dhcp_handle)
{
    int i = 0;
    dhcp_t *dhcp = *dhcp_handle;

    if (dhcp == NULL) {
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

    /* Free the memory and set to NULL */
    free(dhcp);
    *dhcp_handle = NULL;
}

/**
 * \brief Try to resolve DHCP option type to an IANA string.
 *
 * \param code Numerical code of the option
 *
 * \return pointer to string representing option
 */
static const char *dhcp_option_lookup(const unsigned char code)
{
    if ((code <= 83) || (code >= 85 && code <= 95) ||
        (code >= 97 && code <= 101) || (code >= 112 && code <= 125) ||
        (code >= 136 && code <= 142) || (code >= 144 && code <= 146) ||
        (code >= 150 && code <= 161) || (code >= 150 && code <= 161) ||
        (code >= 175 && code <= 177) || (code >= 208 && code <= 213) ||
        code == 220 || code == 221 || code == 255)
    {
        /* Make sure the code is within accepted bounds */
        return dhcp_option_types[code];
    }

    /* Invalid code */
    return NULL;
}

/**
 * \brief Try to resolve the message type option value to an IANA string.
 *
 * \param data pointer to message type data
 *
 * \return pointer to string representing the message
 */
static const char *dhcp_option_message_lookup(const unsigned char *data)
{
    if (*data >= 1 && *data <= 18) {
        /* Make sure the data value is within accepted bounds */
        return dhcp_option_message_types[*data];
    }

    /* Invalid data value */
    return NULL;
}

/**
 * \brief Try to convert the DHCP option value into an IANA string.
 *
 * \param opt dhcp_option
 * \param data pointer to option data
 *
 * \return 1 if found, 0 otherwise
 */
static int dhcp_option_value_to_string(dhcp_option_t *opt,
                                       const unsigned char *data)
{
    if (opt == NULL || data == NULL) {
        return 0;
    }

    if (opt->code == 53) {
        opt->value_str = dhcp_option_message_lookup(data);
        return 1;
    }

    return 0;
}

/**
 * \brief Get the DHCP option value.
 *
 * If the value at \p data_ptr has a string representation, use that.
 * Otherwise, allocate memory to store the data and copy in.
 *
 * \param opt dhcp_option
 * \param opt_len length of the option data
 * \param data_ptr pointer to the option data
 *
 * \return none
 */
static void dhcp_get_option_value(dhcp_option_t *opt,
                                  unsigned char opt_len,
                                  const unsigned char *data_ptr) {
    /*
     * Try to convert the option value into a human-readable string.
     * If none are found, then copy in the raw bytes.
     */
    if (!dhcp_option_value_to_string(opt, data_ptr)) {
        /* Allocate memory for the option data */
        opt->value = calloc(1, opt_len);
	if (!opt->value) {
	    joy_log_err("malloc failed");
	    return;
	}
        memcpy(opt->value, data_ptr, opt_len);
    }
}

/**
 * \brief Parse, process, and record DHCP \p data.
 *
 * \param dhcp DHCP structure pointer
 * \param header PCAP packet header pointer
 * \param data Beginning of the DHCP payload data.
 * \param len Length in bytes of the \p data.
 * \param report_dhcp Flag indicating whether this feature should run.
 *                    0 for no, 1 for yes
 *
 * \return none
 */
void dhcp_update(dhcp_t *dhcp,
                 const struct pcap_pkthdr *header,
                 const void *data,
                 unsigned int data_len,
                 unsigned int report_dhcp)
{
    const unsigned char *ptr = (const unsigned char *)data;
    dhcp_message_t *msg = NULL;
    const unsigned char magic_cookie[] = {0x63, 0x82, 0x53, 0x63};

    joy_log_debug("dhcp[%p],header[%p],data[%p],len[%d],report[%d]",
            dhcp,header,data,data_len,report_dhcp);

    /* Check run flag. Bail if 0 */
    if (!report_dhcp) {
        return;
    }

    /* sanity check */
    if (dhcp == NULL) {
        return;
    }

    /* Make sure there's space to record another message */
    if (dhcp->message_count >= MAX_DHCP_LEN) {
        joy_log_warn("dhcp struct cannot hold any more messages");
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

    msg->ciaddr.s_addr = *(const uint32_t *)ptr;
    ptr += sizeof(uint32_t);

    msg->yiaddr.s_addr = *(const uint32_t *)ptr;
    ptr += sizeof(uint32_t);

    msg->siaddr.s_addr = *(const uint32_t *)ptr;
    ptr += sizeof(uint32_t);

    msg->giaddr.s_addr = *(const uint32_t *)ptr;
    ptr += sizeof(uint32_t);

    memcpy(msg->chaddr, ptr, MAX_DHCP_CHADDR);
    ptr += MAX_DHCP_CHADDR;

    if (*ptr != 0) {
        /* Server host name exists so alloc and copy it */
        msg->sname = calloc(1, MAX_DHCP_SNAME);
	if (!msg->sname) {
	    joy_log_err("malloc failed");
	    return;
	}

        strncpy(msg->sname, (const char *)ptr, MAX_DHCP_SNAME);
        msg->sname[MAX_DHCP_SNAME - 1] = '\0';
    }
    ptr += MAX_DHCP_SNAME;

    if (*ptr != 0) {
        /* Boot file name exists so alloc and copy it */
        msg->file = calloc(1, MAX_DHCP_FILE);
	if (!msg->file) {
	    joy_log_err("malloc failed");
	    return;

	}
         strncpy(msg->file, (const char *)ptr, MAX_DHCP_FILE);
        msg->file[MAX_DHCP_FILE - 1] = '\0';
    }
    ptr += MAX_DHCP_FILE;

    /* Verify magic cookie */
    if (memcmp(ptr, &magic_cookie, sizeof(magic_cookie)) != 0) {
        joy_log_err("bad magic cookie");
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
            dhcp_get_option_value(&msg->options[index], opt_len, ptr);

            ptr += opt_len;
            msg->options_length += opt_len;
        }

        msg->options_count += 1;
    }

    dhcp->message_count += 1;
}

static void dhcp_print_options(const dhcp_option_t *options,
                               unsigned short int count,
                               zfile f) {
    int i = 0;

    zprintf(f, ",\"options\":[");

    for (i = 0; i < count; i++) {
        const char *opt_str = NULL;
        const dhcp_option_t *opt = &options[i];
        opt_str = dhcp_option_lookup(opt->code);

        if (opt_str) {
            if (opt->value_str != NULL) {
                zprintf(f, "{\"%s\":\"%s\"", opt_str, opt->value_str);
            } else if (opt->value != NULL && opt->len != 0) {
                zprintf(f, "{\"%s\":", opt_str);
                zprintf_raw_as_hex(f, opt->value, opt->len);
            }
            zprintf(f, "}");
        } else {
            /* The option is unknown, so print the code */
            zprintf(f, "{\"kind\":%u", opt->code);
            if (opt->value_str != NULL) {
                zprintf(f, ",\"data\":\"%s\"", opt->value_str);
            } else if (opt->value != NULL && opt->len != 0) {
                zprintf(f, ",\"data\":");
                zprintf_raw_as_hex(f, opt->value, opt->len);
            }
            zprintf(f, "}");
        }

        if (i == (count - 1)) {
            zprintf(f, "]");
        } else {
            zprintf(f, ",");
        }
    }
}

/**
 * \brief Print the DHCP struct to JSON output file \p f.
 *
 * \param d1 pointer to DHCP structure
 * \param d2 pointer to twin DHCP structure
 * \param f destination file for the output
 *
 * \return none
 */
void dhcp_print_json(const dhcp_t *d1,
                     const dhcp_t *d2,
                     zfile f)
{
    int i = 0;

    /* sanity check */
    if (d1 == NULL) {
        return;
    }

    if (d1->message_count) {
        char ipv4_addr[INET_ADDRSTRLEN];
        zprintf(f, ",\"dhcp\":[");
        for (i = 0; i < d1->message_count; i++) {
            const dhcp_message_t *msg = &d1->messages[i];

            zprintf(f, "{");
            zprintf(f, "\"op\":\"%u\"", msg->op);
            zprintf(f, ",\"htype\":\"%u\"", msg->htype);
            zprintf(f, ",\"hlen\":\"%u\"", msg->hlen);
            zprintf(f, ",\"hops\":\"%u\"", msg->hops);
            zprintf(f, ",\"xid\":\"%u\"", msg->xid);
            zprintf(f, ",\"secs\":\"%u\"", msg->secs);
            zprintf(f, ",\"flags\":\"%u\"", msg->flags);

            if (ipv4_addr_needs_anonymization(&msg->ciaddr)) {
                zprintf(f, ",\"ciaddr\":\"%s\"", addr_get_anon_hexstring(&msg->ciaddr));
            } else {
                inet_ntop(AF_INET, &msg->ciaddr, ipv4_addr, INET_ADDRSTRLEN);
                zprintf(f, ",\"ciaddr\":\"%s\"", ipv4_addr);
            }
            if (ipv4_addr_needs_anonymization(&msg->yiaddr)) {
                zprintf(f, ",\"yiaddr\":\"%s\"", addr_get_anon_hexstring(&msg->yiaddr));
            } else {
                inet_ntop(AF_INET, &msg->yiaddr, ipv4_addr, INET_ADDRSTRLEN);
                zprintf(f, ",\"yiaddr\":\"%s\"", ipv4_addr);
            }
            if (ipv4_addr_needs_anonymization(&msg->siaddr)) {
                zprintf(f, ",\"siaddr\":\"%s\"", addr_get_anon_hexstring(&msg->siaddr));
            } else {
                inet_ntop(AF_INET, &msg->siaddr, ipv4_addr, INET_ADDRSTRLEN);
                zprintf(f, ",\"siaddr\":\"%s\"", ipv4_addr);
            }
            if (ipv4_addr_needs_anonymization(&msg->giaddr)) {
                zprintf(f, ",\"giaddr\":\"%s\"", addr_get_anon_hexstring(&msg->giaddr));
            } else {
                inet_ntop(AF_INET, &msg->giaddr, ipv4_addr, INET_ADDRSTRLEN);
                zprintf(f, ",\"giaddr\":\"%s\"", ipv4_addr);
            }

            zprintf(f, ",\"chaddr\":");
            zprintf_raw_as_hex(f, msg->chaddr, sizeof(msg->chaddr));
            if (msg->sname != NULL) {
                joy_utils_convert_to_json_string(msg->sname, MAX_DHCP_SNAME);
                zprintf(f, ",\"sname\":\"%s\"", msg->sname);
            }
            if (msg->file != NULL) {
                joy_utils_convert_to_json_string(msg->file, MAX_DHCP_FILE);
                zprintf(f, ",\"file\":\"%s\"", msg->file);
            }

            if (msg->options_count) {
               dhcp_print_options(msg->options, msg->options_count, f);
            }

            if (i == (d1->message_count - 1)) {
                zprintf(f, "}");
            } else {
                zprintf(f, "},");
            }
        }
        zprintf(f, "]");
    }

    /* sanity check */
    if (d2 == NULL) {
        return;
    }
}

/**
 * \brief Skip over the L1/L2/L3 header of packet containing DHCP data.
 *
 * \param packet_data[in] pointer to beginning of packet
 * \param packet_len[in] length in bytes of the packet
 * \param size_payload[out] length of the DHCP payload stored here
 *
 * \return pointer to the beginning of DHCP message data, NULL if fail
 */
static const unsigned char* dhcp_skip_packet_udp_header(const unsigned char *packet_data,
                                                  unsigned int packet_len,
                                                  unsigned int *size_payload) {
    const struct ip_hdr *ip = NULL;
    unsigned int ip_hdr_len = 0;
    unsigned int udp_hdr_len = 8;
    const unsigned char *payload = NULL;

    /* define/compute ip header offset */
    ip = (const struct ip_hdr*)(packet_data + ETHERNET_HDR_LEN);
    ip_hdr_len = ip_hdr_length(ip);
    if (ip_hdr_len < 20) {
        joy_log_err("invalid ip header of len %d", ip_hdr_len);
        return NULL;
    }

    if (ntohs(ip->ip_len) < sizeof(struct ip_hdr)) {
        /* IP packet is malformed (shorter than a complete IP header) */
        joy_log_err("ip packet malformed, ip_len: %d", ntohs(ip->ip_len));
        return NULL;
    }

    /* define/compute udp payload (segment) offset */
    payload = (const unsigned char *)(packet_data + ETHERNET_HDR_LEN + ip_hdr_len + udp_hdr_len);

    /* compute udp payload (segment) size */
    *size_payload = packet_len - ETHERNET_HDR_LEN - ip_hdr_len - udp_hdr_len;

    return payload;
}

/**
 * \brief Compare two dhcp_messages to see if they are equal.
 *
 * \param m1 pointer to first dhcp_message struct
 * \param m2 pointer to second dhcp_message struct
 *
 * \return 0 for no, 1 for yes
 */
static int dhcp_test_message_equality(dhcp_message_t *m1,
                                      dhcp_message_t *m2) {
    int i = 0;

    if (m1 == NULL || m2 == NULL) {
        joy_log_err("api parameter is null");
        return 0;
    }

    if (m1->op != m2->op) {
        joy_log_err("bad op");
        return 0;
    }

    if (m1->htype != m2->htype) {
        joy_log_err("bad htype");
        return 0;
    }

    if (m1->hlen != m2->hlen) {
        joy_log_err("bad hlen");
        return 0;
    }

    if (m1->hops != m2->hops) {
        joy_log_err("bad hops");
        return 0;
    }

    if (m1->xid != m2->xid) {
        joy_log_err("bad xid");
        return 0;
    }

    if (m1->secs != m2->secs) {
        joy_log_err("bad secs");
        return 0;
    }

    if (m1->flags != m2->flags) {
        joy_log_err("bad flags");
        return 0;
    }

    if (m1->ciaddr.s_addr != m2->ciaddr.s_addr) {
        joy_log_err("bad ciaddr");
        return 0;
    }

    if (m1->yiaddr.s_addr != m2->yiaddr.s_addr) {
        joy_log_err("bad yiaddr");
        return 0;
    }

    if (m1->siaddr.s_addr != m2->siaddr.s_addr) {
        joy_log_err("bad siaddr");
        return 0;
    }

    if (m1->giaddr.s_addr != m2->giaddr.s_addr) {
        joy_log_err("bad giaddr");
        return 0;
    }

    if (memcmp(m1->chaddr, m2->chaddr, MAX_DHCP_CHADDR) != 0) {
        joy_log_err("bad chaddr");
        return 0;
    }

    if (m1->sname != NULL || m2->sname != NULL) {
        if (m1->sname == NULL || m2->sname == NULL) {
            /* One of the messages has sname memory while the other does not */
            joy_log_err("one of sname is null");
            return 0;
        } else {
            /* Compare the sname */
            if (strncmp(m1->sname, m2->sname, MAX_DHCP_SNAME) != 0) {
                joy_log_err("sname not equal");
                return 0;
            }
        }
    }

    if (m1->file != NULL || m2->file != NULL) {
        if (m1->file == NULL || m2->file == NULL) {
            /* One of the messages has bootfile memory while the other does not */
            joy_log_err("one of file is null");
            return 0;
        } else {
            /* Compare the file */
            if (strncmp(m1->file, m2->file, MAX_DHCP_FILE) != 0) {
                joy_log_err("file not equal");
                return 0;
            }
        }
    }

    /* Compare options */
    if (m1->options_count != m2->options_count) {
        joy_log_err("bad options_count");
        return 0;
    }

    if (m1->options_length != m2->options_length) {
        joy_log_err("bad options_length");
        return 0;
    }

    /* Iterate over each option */
    for (i = 0; i < m1->options_count; i++) {
        if (m1->options[i].code != m2->options[i].code) {
            joy_log_err("bad options[%d] code", i);
            return 0;
        }

        if (m1->options[i].len != m2->options[i].len) {
            joy_log_err("bad options[%d] len", i);
            return 0;
        }

        if (m1->options[i].value != NULL || m2->options[i].value != NULL) {
            /* One of the options has raw value */
            if (m1->options[i].value == NULL || m2->options[i].value == NULL) {
                /* One of the messages has value memory while the other does not */
                joy_log_err("one of options[%d] value is null", i);
                return 0;
            } else {
                /* Compare the option values */
                if (memcmp(m1->options[i].value, m2->options[i].value, m1->options[i].len) != 0) {
                    joy_log_err("options[%d] value not equal", i);
                    return 0;
                }
            }
        } else if (m1->options[i].value_str != NULL || m2->options[i].value_str != NULL) {
            /* One of the options is pointing to a string repr */
            if (m1->options[i].value_str == NULL || m2->options[i].value_str == NULL) {
                /* One of the messages has value_str while the other does not */
                joy_log_err("one of options[%d] value_str is null", i);
                return 0;
            } else {
                /* Compare the option value strings */
                if (strncmp(m1->options[i].value_str,
                            m2->options[i].value_str,
                            MAX_DHCP_MSG_TYPE_STR) != 0) {
                    joy_log_err("options[%d] value_str not equal", i);
                    return 0;
                }
            }
        }
    }

    return 1;
}

/**
 * \brief Test the dhcp_update function by comparing KAT values against data extracted from PCAP.
 *
 * This only looks at the discover and offer messages for sake of readability.
 *
 * \return 0 for success, otherwise number of fails
 */
static int dhcp_test_vanilla_parsing(void) {
    dhcp_t *d = NULL;
    pcap_t *pcap_handle = NULL;
    struct pcap_pkthdr header;
    const unsigned char *pkt_ptr = NULL;
    const unsigned char *payload_ptr = NULL;
    unsigned int payload_len = 0;
    const char *filename = "dhcp.pcap";
    dhcp_t *known_dhcp = NULL;
    dhcp_message_t *msg = NULL;
    int num_fails = 0;

    unsigned char kat_chaddr[] = {0x08, 0x00, 0x27, 0x83, 0xf4, 0x42, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    dhcp_init(&d);
    dhcp_init(&known_dhcp);

    /*
     * Known answers
     */

    /*
     * KAT Ack
     */
    msg = &known_dhcp->messages[0];
    msg->op = 0x02;
    msg->htype = 0x01;
    msg->hlen = 0x06;
    msg->hops = 0x00;
    msg->xid = 0x89d92613;
    msg->secs = 0x0000;
    msg->flags = 0x0000;
    msg->ciaddr.s_addr = ntohl(0x0a00020f);
    msg->yiaddr.s_addr = ntohl(0x0a00020f);
    msg->siaddr.s_addr = ntohl(0x0a000204);
    msg->giaddr.s_addr = ntohl(0x00000000);
    memcpy(msg->chaddr, kat_chaddr, MAX_DHCP_CHADDR);

    msg->file = calloc(1, MAX_DHCP_FILE);
    if (!msg->file) {
	joy_log_err("malloc failed");
	num_fails++;
	goto end;
    }

    strncpy(msg->file, "Pythagoras.pxe", MAX_DHCP_FILE);

    {
        /* Offer Options */
        unsigned char opt_len = 0;
        unsigned char opt_val_0[] = {0x05}; /* Ack */
        unsigned char opt_val_1[] = {0xff, 0xff, 0xff, 0x00}; /* Subnet mask */
        unsigned char opt_val_2[] = {0x0a, 0x00, 0x02, 0x02}; /* Router */
        unsigned char opt_val_3[] = {0xd1, 0x12, 0x2f, 0x3e, 0xd1, 0x12, 0x2f, 0x3d}; /* Domain Name Server */
        unsigned char opt_val_4[] = {0x6e, 0x63, 0x2e, 0x72, 0x72, 0x2e, 0x63, 0x6f, 0x6d}; /* Domain Name */
        unsigned char opt_val_5[] = {0x00, 0x01, 0x51, 0x80}; /* IP address lease time */
        unsigned char opt_val_6[] = {0x0a, 0x00, 0x02, 0x02}; /* DHCP server id */

        /* Opt 0 */
        msg->options[0].code = 53; /* Message type */
        msg->options_length += 1;

        opt_len = 1;
        msg->options[0].len = opt_len;
        msg->options_length += 1;

        dhcp_get_option_value(&msg->options[0], opt_len, opt_val_0);

        msg->options_length += opt_len;
        msg->options_count += 1;

        /* Opt 1 */
        msg->options[1].code = 1; /* Subnet mask */
        msg->options_length += 1;

        opt_len = 4;
        msg->options[1].len = opt_len;
        msg->options_length += 1;

        dhcp_get_option_value(&msg->options[1], opt_len, opt_val_1);

        msg->options_length += opt_len;
        msg->options_count += 1;

        /* Opt 2 */
        msg->options[2].code = 3; /* Renewal time */
        msg->options_length += 1;

        opt_len = 4;
        msg->options[2].len = opt_len;
        msg->options_length += 1;

        dhcp_get_option_value(&msg->options[2], opt_len, opt_val_2);

        msg->options_length += opt_len;
        msg->options_count += 1;

        /* Opt 3 */
        msg->options[3].code = 6; /* DNS */
        msg->options_length += 1;

        opt_len = 8;
        msg->options[3].len = opt_len;
        msg->options_length += 1;

        dhcp_get_option_value(&msg->options[3], opt_len, opt_val_3);

        msg->options_length += opt_len;
        msg->options_count += 1;

        /* Opt 4 */
        msg->options[4].code = 15; /* Domain Name */
        msg->options_length += 1;

        opt_len = 9;
        msg->options[4].len = opt_len;
        msg->options_length += 1;

        dhcp_get_option_value(&msg->options[4], opt_len, opt_val_4);

        msg->options_length += opt_len;
        msg->options_count += 1;

        /* Opt 5 */
        msg->options[5].code = 51; /* IP address lease time */
        msg->options_length += 1;

        opt_len = 4;
        msg->options[5].len = opt_len;
        msg->options_length += 1;

        dhcp_get_option_value(&msg->options[5], opt_len, opt_val_5);

        msg->options_length += opt_len;
        msg->options_count += 1;

        /* Opt 6 */
        msg->options[6].code = 54; /* DHCP server identifier */
        msg->options_length += 1;

        opt_len = 4;
        msg->options[6].len = opt_len;
        msg->options_length += 1;

        dhcp_get_option_value(&msg->options[6], opt_len, opt_val_6);

        msg->options_length += opt_len;
        msg->options_count += 1;
    }
    /* Increment the message count */
    known_dhcp->message_count += 1;


    /*
     * Test dhcp_update parsing with pcap
     */
    pcap_handle = joy_utils_open_test_pcap(filename);
    if (!pcap_handle) {
        joy_log_err("unable to open %s", filename);
        num_fails++;
        goto end;
    }

    /* Request (skip this) */
    pkt_ptr = pcap_next(pcap_handle, &header);

    /* Ack */
    pkt_ptr = pcap_next(pcap_handle, &header);
    payload_ptr = dhcp_skip_packet_udp_header(pkt_ptr, header.len, &payload_len);
    dhcp_update(d, &header, payload_ptr, payload_len, 1);

    if (! dhcp_test_message_equality(&d->messages[d->message_count-1], &known_dhcp->messages[0])) {
        joy_log_err("incorrect ack parsing");
        num_fails++;
    }

end:
    if (pcap_handle) {
        pcap_close(pcap_handle);
    }
    dhcp_delete(&d);
    dhcp_delete(&known_dhcp);

    return num_fails;
}

/**
 * \brief Unit test for DHCP
 *
 * \return none
 */
void dhcp_unit_test()
{
    int num_fails = 0;

    fprintf(info, "\n******************************\n");
    fprintf(info, "DHCP Unit Test starting...\n");

    num_fails += dhcp_test_vanilla_parsing();

    if (num_fails) {
        fprintf(info, "Finished - # of failures: %d\n", num_fails);
    } else {
        fprintf(info, "Finished - success\n");
    }
    fprintf(info, "******************************\n\n");
}

