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
#include "anon.h"
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
 * \brief Table storing IANA DHCP option name strings
 *
 * The string values in this table have been adapted from:
 * https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
 *
 * The strings within have been changed in some instances to eliminate redundant words
 * such as "options" or "DHCP" and standardized the capitalization for names that have
 * the same meaning such as REMOVED/removed. Otherwise the strings have only had the
 * whitespace deleted.
 */
static const char *dhcp_options_str_table[] = {
    [0]="Pad", [1]="SubnetMask", [2]="TimeOffset", [3]="Router",
    [4]="TimeServer", [5]="NameServer", [6]="DomainServer", [7]="LogServer",
    [8]="QuotesServer", [9]="LPRServer", [10]="ImpressServer", [11]="RLPServer",
    [12]="Hostname", [13]="BootFileSize", [14]="MeritDumpFile", [15]="DomainName",
    [16]="SwapServer", [17]="RootPath", [18]="ExtensionFile", [19]="ForwardOn/Off",
    [20]="SrcRteOn/Off", [21]="PolicyFilter", [22]="MaxDGAssembly", [23]="DefaultIPTTL",
    [24]="MTUTimeout", [25]="MTUPlateau", [26]="MTUInterface", [27]="MTUSubnet",
    [28]="BroadcastAddress", [29]="MaskDiscovery", [30]="MaskSupplier", [31]="RouterDiscovery",
    [32]="RouterRequest", [33]="StaticRoute", [34]="Trailers", [35]="ARPTimeout",
    [36]="Ethernet", [37]="DefaultTCPTTL", [38]="KeepaliveTime", [39]="KeepaliveData",
    [40]="NISDomain", [41]="NISServers", [42]="NTPServers", [43]="VendorSpecific",
    [44]="NETBIOSNameSrv", [45]="NETBIOSDistSrv", [46]="NETBIOSNodeType", [47]="NETBIOSScope",
    [48]="XWindowFont", [49]="XWindowManager", [50]="AddressRequest", [51]="AddressTime",
    [52]="Overload", [53]="MsgType", [54]="ServerId", [55]="ParameterList",
    [56]="Message", [57]="MaxMsgSize", [58]="RenewalTime", [59]="RebindingTime",
    [60]="ClassId", [61]="ClientId", [62]="NetWare/IPDomain", [63]="NetWare/IPOption",
    [64]="NIS-Domain-Name", [65]="NIS-Server-Addr", [66]="Server-Name", [67]="Bootfile-Name",
    [68]="Home-Agent-Addrs", [69]="SMTP-Server", [70]="POP3-Server", [71]="NNTP-Server",
    [72]="WWW-Server", [73]="Finger-Server", [74]="IRC-Server", [75]="StreetTalk-Server",
    [76]="STDA-Server", [77]="User-Class", [78]="DirectoryAgent", [79]="ServiceScope",
    [80]="RapidCommit", [81]="ClientFQDN", [82]="RelayAgentInformation", [83]="iSNS",
    [84]="Removed/Unassigned", [85]="NDSServers", [86]="NDSTreeName", [87]="NDSContext",
    [88]="BCMCSControllerDomainNamelist", [89]="BCMCSControllerIPv4address",
    [90]="Authentication", [91]="client-last-transaction-time",
    [92]="associated-ip", [93]="ClientSystem", [94]="ClientNDI", [95]="LDAP",
    [96]="Removed/Unassigned", [97]="UUID/GUID", [98]="User-Auth", [99]="GEOCONF_CIVIC",
    [100]="PCode", [101]="TCode", [102]="Removed/Unassigned", [103]="Removed/Unassigned",
    [104]="Removed/Unassigned", [105]="Removed/Unassigned", [106]="Removed/Unassigned",
    [107]="Removed/Unassigned",
    [108]="Removed/Unassigned", [109]="Unassigned", [110]="Removed/Unassigned", [111]="Unassigned",
    [112]="NetinfoAddress", [113]="NetinfoTag", [114]="URL", [115]="Removed/Unassigned",
    [116]="Auto-Config", [117]="NameServiceSearch", [118]="SubnetSelection",
    [119]="DomainSearch", [120]="SIPServers", [121]="ClasslessStaticRoute", [122]="CCC",
    [123]="GeoConf", [124]="V-IVendorClass", [125]="dor-SpecificInformation",
    [126]="Removed/Unassigned", [127]="Removed/Unassigned",
    [128]="PXE-undefined|Etherbootsignature|DOCSIS\"fullsecurity\"serverIPaddress|TFTPServerIPaddress",
    [129]="PXE-undefined|Kerneloptions|CallServerIPaddress",
    [130]="PXE-undefined|Ethernetinterface|Discriminationstring",
    [131]="PXE-undefined|RemotestatisticsserverIPaddress", [132]="PXE-undefined|IEEE802.1QVLANID",
    [133]="PXE-undefined|IEEE802.1D/pLayer2Priority",
    [134]="PXE-undefined|DiffservCodePoint(DSCP)forVoIPsignallingandmediastreams",
    [135]="PXE-undefined|HTTPProxyforphone-specificapplications",
    [136]="OPTION_PANA_AGENT", [137]="OPTION_V4_LOST", [138]="OPTION_CAPWAP_AC_V4",
    [139]="OPTION-IPv4_Address-MoS",
    [140]="OPTION-IPv4_FQDN-MoS", [141]="SIPUAConfigurationServiceDomains",
    [142]="OPTION-IPv4_Address-ANDSF", [143]="Unassigned",
    [144]="GeoLoc", [145]="FORCERENEW_NONCE_CAPABLE", [146]="RDNSSSelection",
    [147]="Unassigned", [148]="Unassigned", [149]="Unassigned",
    [150]="TFTPserveraddress|Etherboot|GRUBconfigurationpathname", [151]="status-code",
    [152]="base-time", [153]="start-time-of-state",
    [154]="query-start-time", [155]="query-end-time",
    [156]="dhcp-state", [157]="data-source",
    [158]="OPTION_V4_PCP_SERVER", [159]="OPTION_V4_PORTPARAMS",
    [160]="Captive-Portal", [161]="OPTION_MUD_URL_V4",
    [162]="Unassigned", [163]="Unassigned",
    [164]="Unassigned", [165]="Unassigned", [166]="Unassigned", [167]="Unassigned",
    [168]="Unassigned", [169]="Unassigned", [170]="Unassigned", [171]="Unassigned",
    [172]="Unassigned", [173]="Unassigned", [174]="Unassigned", [175]="Etherboot",
    [176]="IPTelephone", [177]="Etherboot|PacketCableandCableHome",
    [178]="Unassigned", [179]="Unassigned",
    [180]="Unassigned", [181]="Unassigned", [182]="Unassigned", [183]="Unassigned",
    [184]="Unassigned", [185]="Unassigned", [186]="Unassigned", [187]="Unassigned",
    [188]="Unassigned", [189]="Unassigned", [190]="Unassigned", [191]="Unassigned",
    [192]="Unassigned", [193]="Unassigned", [194]="Unassigned", [195]="Unassigned",
    [196]="Unassigned", [197]="Unassigned", [198]="Unassigned", [199]="Unassigned",
    [200]="Unassigned", [201]="Unassigned", [202]="Unassigned", [203]="Unassigned",
    [204]="Unassigned", [205]="Unassigned", [206]="Unassigned", [207]="Unassigned",
    [208]="PXELINUXMagic", [209]="ConfigurationFile", [210]="PathPrefix", [211]="RebootTime",
    [212]="OPTION_6RD", [213]="OPTION_V4_ACCESS_DOMAIN", [214]="Unassigned", [215]="Unassigned",
    [216]="Unassigned", [217]="Unassigned", [218]="Unassigned", [219]="Unassigned",
    [220]="SubnetAllocation", [221]="VirtualSubnetSelection",
    [222]="Unassigned", [223]="Unassigned",
    [224]="Reserved", [225]="Reserved", [226]="Reserved", [227]="Reserved",
    [228]="Reserved", [229]="Reserved", [230]="Reserved", [231]="Reserved",
    [232]="Reserved", [233]="Reserved", [234]="Reserved", [235]="Reserved",
    [236]="Reserved", [237]="Reserved", [238]="Reserved", [239]="Reserved",
    [240]="Reserved", [241]="Reserved", [242]="Reserved", [243]="Reserved",
    [244]="Reserved", [245]="Reserved", [246]="Reserved", [247]="Reserved",
    [248]="Reserved", [249]="Reserved", [250]="Reserved", [251]="Reserved",
    [252]="Reserved", [253]="Reserved", [254]="Reserved", [255]="End"
};

/**
 * \brief Table storing IANA DHCP message type value string representations
 *
 * https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml#message-type-53
 *
 */
static const char *dhcp_option_msg_types[] = {
    [1]="DHCPDISCOVER", [2]="DHCPOFFER", [3]="DHCPREQUEST",
    [4]="DHCPDECLINE", [5]="DHCPACK", [6]="DHCPNAK",
    [7]="DHCPRELEASE", [8]="DHCPINFORM", [9]="DHCPFORCERENEW",
    [10]="DHCPLEASEQUERY", [11]="DHCPLEASEUNASSIGNED", [12]="DHCPLEASEUNKNOWN",
    [13]="DHCPLEASEACTIVE", [14]="DHCPBULKLEASEQUERY", [15]="DHCPLEASEQUERYDONE",
    [16]="DHCPACTIVELEASEQUERY", [17]="DHCPLEASEQUERYSTATUS", [18]="DHCPTLS"
};

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

/**
 * \brief Try to resolve the message type option value to an IANA string.
 *
 * \param data pointer to message type data
 *
 * \return pointer to string from lookup table
 */
static const char *dhcp_option_msg_type_lookup(const unsigned char *data)
{
    if (*data >= 1 && *data <= 18) {
        /* Make sure the data value is within accepted bounds */
        return dhcp_option_msg_types[*data];
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
static int dhcp_option_value_to_string(struct dhcp_option *opt,
                                       const unsigned char *data)
{
    if (opt == NULL || data == NULL) {
        return 0;
    }

    if (opt->code == 53) {
        opt->value_str = dhcp_option_msg_type_lookup(data);
        return 1;
    }

    return 0;
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
            /*
             * Try to convert the option value into a human-readable string.
             * If none are found, then copy in the raw bytes.
             */
            if (!dhcp_option_value_to_string(&msg->options[index], ptr)) {
                /* Allocate memory for the option data */
                msg->options[index].value = malloc(opt_len);

                memcpy(msg->options[index].value, ptr, opt_len);
            }

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

            if (ipv4_addr_needs_anonymization(&msg->ciaddr)) {
                zprintf(f, ",\"ciaddr\":\"%s\"", addr_get_anon_hexstring(&msg->ciaddr));
            } else {
                zprintf(f, ",\"ciaddr\":\"%s\"", inet_ntoa(msg->ciaddr));
            }
            if (ipv4_addr_needs_anonymization(&msg->yiaddr)) {
                zprintf(f, ",\"yiaddr\":\"%s\"", addr_get_anon_hexstring(&msg->yiaddr));
            } else {
                zprintf(f, ",\"yiaddr\":\"%s\"", inet_ntoa(msg->yiaddr));
            }
            if (ipv4_addr_needs_anonymization(&msg->siaddr)) {
                zprintf(f, ",\"siaddr\":\"%s\"", addr_get_anon_hexstring(&msg->siaddr));
            } else {
                zprintf(f, ",\"siaddr\":\"%s\"", inet_ntoa(msg->siaddr));
            }
            if (ipv4_addr_needs_anonymization(&msg->giaddr)) {
                zprintf(f, ",\"giaddr\":\"%s\"", addr_get_anon_hexstring(&msg->giaddr));
            } else {
                zprintf(f, ",\"giaddr\":\"%s\"", inet_ntoa(msg->giaddr));
            }

            zprintf(f, ",\"chaddr\":");
            zprintf_raw_as_hex(f, msg->chaddr, sizeof(msg->chaddr));
            if (msg->sname != NULL) {
                convert_string_to_printable(msg->sname, MAX_DHCP_SNAME);
                zprintf(f, ",\"sname\":\"%s\"", msg->sname);
            }
            if (msg->file != NULL) {
                convert_string_to_printable(msg->file, MAX_DHCP_FILE);
                zprintf(f, ",\"file\":\"%s\"", msg->file);
            }

            if (msg->options_count) {
                /* Begin array */
                zprintf(f, ",\"options\":[");
                for (k = 0; k < msg->options_count; k++) {
                    const struct dhcp_option *opt = &msg->options[k];
                    unsigned char code = opt->code;

                    /* Begin object */
                    zprintf(f, "{");

                    /* Begin option name object */
                    zprintf(f, "\"%s\":{", dhcp_options_str_table[code]);

                    zprintf(f, "\"code\":%u", opt->code);
                    zprintf(f, ",\"len\":%u", opt->len);
                    if (opt->value_str != NULL) {
                        zprintf(f, ",\"value\":\"%s\"", opt->value_str);
                    } else if (opt->value != NULL && opt->len != 0) {
                        zprintf(f, ",\"value\":");
                        zprintf_raw_as_hex(f, opt->value, opt->len);
                    }

                    zprintf(f, "}");
                    /* End option name object */

                    if (k == (msg->options_count - 1)) {
                        zprintf(f, "}");
                    } else {
                        zprintf(f, "},");
                    }
                    /* End object */
                }
                zprintf(f, "]");
                /* End array */
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

