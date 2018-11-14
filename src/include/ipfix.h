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

/**************************************************
 * @file ipfix.h
 *
 * @brief Interface to IPFIX code which is used
 *        to collect or export using the protocol.
 **************************************************/

#ifndef IPFIX_H
#define IPFIX_H

#include <time.h>

#ifndef WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <pthread.h>
#include "p2f.h"
#include "utils.h"

#define IPV4_HDR_LEN 20

/* @brief @verbatim
  IPFIX (RFC7011)

  The format of an IPFIX message header is as follows:

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |       Version Number         |            Length              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                           Export Time                         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        Sequence Number                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Observation Domain ID                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  The format of the Template Set is as follows:

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Set ID = 2          |           Length              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |       Template ID = 256       |       Field Count = N         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |1| Information Element id. 1.1 |       Field Length 1.1        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     Enterprise Number 1.1                     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |0| Information Element id. 1.2 |       Field Length 1.2        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |             ...               |             ...               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |1| Information Element id. 1.N |       Field Length 1.N        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     Enterprise Number 1.N                     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Template ID = 257         |       Field Count = M         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |0| Information Element id. 2.1 |       Field Length 2.1        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |1| Information Element id. 2.2 |       Field Length 2.2        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     Enterprise Number 2.2                     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |             ...               |             ...               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |1| Information Element id. 2.M |       Field Length 2.M        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                     Enterprise Number 2.M                     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         Padding (opt)                         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  The format of the Options Template Set is as follows:

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Set ID = 3           |          Length               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |         Template ID = 258     |         Field Count = N + M   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Scope Field Count = N     |0|  Scope 1 Infor. Element id. |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Scope 1 Field Length      |0|  Scope 2 Infor. Element id. |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Scope 2 Field Length      |             ...               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |            ...                |1|  Scope N Infor. Element id. |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Scope N Field Length      |   Scope N Enterprise Number  ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 ...  Scope N Enterprise Number   |1| Option 1 Infor. Element id. |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |    Option 1 Field Length      |  Option 1 Enterprise Number  ...
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 ... Option 1 Enterprise Number   |              ...              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |             ...               |0| Option M Infor. Element id. |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Option M Field Length     |      Padding (optional)       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  The format of the Data Set is as follows:

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Set ID = Template ID        |          Length               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Record 1 - Field Value 1    |   Record 1 - Field Value 2    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Record 1 - Field Value 3    |             ...               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Record 2 - Field Value 1    |   Record 2 - Field Value 2    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Record 2 - Field Value 3    |             ...               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Record 3 - Field Value 1    |   Record 3 - Field Value 2    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Record 3 - Field Value 3    |             ...               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |              ...              |      Padding (optional)       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

@endverbatim
*/


/*
 * @brief Structure representing an IPFIX message header.
 */
typedef struct ipfix_hdr_ {
    uint16_t version_number;
    uint16_t length;
    uint32_t export_time;
    uint32_t sequence_number;
    uint32_t observe_dom_id;
} ipfix_hdr_t;


/*
 * @brief Structure representing a set header.
 */
typedef struct ipfix_set_hdr_ {
    uint16_t set_id;
    uint16_t length;
} ipfix_set_hdr_t;


/*
 * @brief Structure representing a template header.
 */
typedef struct ipfix_template_hdr_ {
    uint16_t template_id;
    uint16_t field_count;
} ipfix_template_hdr_t;


/*
 * @brief Structure representing an options header.
 */
typedef struct ipfix_option_hdr_ {
    uint16_t template_id;
    uint16_t field_count;
    uint16_t scope_field_count;
} ipfix_option_hdr_t;


/*
 * @brief Structure representing a Collector Template Field specifier.
 *
 * This may not have the enterprise_num field populated with
 * data depending on whether the leftmost bit of info_elem_id
 * is set (big-endian).
 *
 */
typedef struct ipfix_template_field_ {
    uint16_t info_elem_id;
    uint16_t fixed_length;
    uint32_t enterprise_num;
    uint16_t variable_length;
    uint8_t var_hdr_length; /**< How many bytes the variable header consists of */
} ipfix_template_field_t;


/*
 * @brief Structure representing a Collector Template key.
 *
 * Used by the Collector to track Templates as unique entities.
 */
typedef struct ipfix_template_key_ {
    struct in_addr exporter_addr;
    uint32_t observe_dom_id;
    uint16_t template_id;
} ipfix_template_key_t;


/*
 * @brief Structure representing a single Collector Template entity.
 *
 * Stored by the collector to interpret subsequent related Data Sets.
 */
typedef struct ipfix_template_ {
    ipfix_template_key_t template_key;
    ipfix_template_hdr_t hdr;
    ipfix_template_field_t *fields;
    int payload_length; /**< Keeps track of the actual template field payload length encountered,
                           since all ipfix_template_fields have enterprise memory allocated,
                           but that may not have been true for payload */

    time_t last_seen;
    struct ipfix_template_ *next;
    struct ipfix_template_ *prev;
} ipfix_template_t;


/*
 * @brief Structure representing an IPFIX "basicList" data type.
 */
#ifdef WIN32

#define PACKED
#pragma pack(push,1)

typedef struct ipfix_basic_list_hdr_ {
    uint8_t semantic;
    uint16_t field_id;
    uint16_t element_length;
    uint32_t enterprise_num;
} ipfix_basic_list_hdr_t;

#pragma pack(pop)
#undef PACKED

#else

typedef struct __attribute__((__packed__)) ipfix_basic_list_hdr_ {
    uint8_t semantic;
    uint16_t field_id;
    uint16_t element_length;
    uint32_t enterprise_num;
} ipfix_basic_list_hdr_t;

#endif

/*
 * @brief Structure representing an IPFIX Collector.
 */
typedef struct ipfix_collector_ {
    struct sockaddr_in clctr_addr;  /**< collector address */
    int socket;
    unsigned int msg_count;
} ipfix_collector_t;


/*
 * Buffer size for sending/receiving network messages.
 */
#define TRANSPORT_MTU 1500

/*
 * The maximum length of any single IPFIX message.
 * 1500 - 20 (IP hdr) - 8 (UDP hdr)
 */
#define IPFIX_MTU 1472

/*
 * The maximum length of a set including it's header.
 * IPFIX_MTU - sizeof(ipfix_hdr_t)
 */
#define IPFIX_MAX_SET_LEN 1456

/*
 * The maximum length of the data contained within a set.
 * IPFIX_MAX_SET_LEN - sizeof(ipfix_set_hdr)
 */
#define IPFIX_MAX_SET_DATA_LEN 1448

/*
 * The maximum number of fields allowed residing within the data of a set.
 * IPFIX_MAX_SET_LEN - sizeof(ipfix_set_hdr)
 */
#define IPFIX_MAX_FIELDS (IPFIX_MAX_SET_DATA_LEN/4)


/*
 * @brief Enumeration representing IPFIX template type ids.
 * 
 * These are not defined in the spec, but rather created
 * and maintained locally in accordance with the spec in order
 * to export particular data we are interested in.
 */
typedef enum ipfix_template_type_ {
  IPFIX_RESERVED_TEMPLATE =                          0,
  IPFIX_SIMPLE_TEMPLATE =                            1,
  IPFIX_IDP_TEMPLATE =                               2
} ipfix_template_type_e;


typedef struct ipfix_exporter_template_field_ {
  uint16_t info_elem_id;
  uint16_t fixed_length;
  uint32_t enterprise_num;
} ipfix_exporter_template_field_t;


/*
 * @brief Structure representing an IPFIX Exporter Template.
 */
typedef struct ipfix_exporter_template_ {
  ipfix_template_hdr_t hdr;
  ipfix_exporter_template_field_t *fields;
  ipfix_template_type_e type;
  time_t last_sent; /**< the last time this template was sent to the collector */
  //time_t last_used; /**< the most recent time a data set was sent referencing this template */
  uint16_t length; /**< total length the template, including header */

  struct ipfix_exporter_template_ *next;
  struct ipfix_exporter_template_ *prev;
} ipfix_exporter_template_t;

/*
 * The minimum size of a variable length field is 3 because we
 * MUST send the flag and length encoded in each data record.
 */
#define MIN_SIZE_VAR_FIELD 3

typedef struct ipfix_variable_field_ {
    uint8_t flag;
    uint16_t length;
    unsigned char *info;
} ipfix_variable_field_t;

#define SIZE_IPFIX_DATA_SIMPLE 29

typedef struct ipfix_exporter_data_simple_ {
  uint32_t source_ipv4_address;
  uint32_t destination_ipv4_address;
  uint16_t source_transport_port;
  uint16_t destination_transport_port;
  uint8_t protocol_identifier;
  uint64_t flow_start_microseconds;
  uint64_t flow_end_microseconds;
} ipfix_exporter_data_simple_t;

/*
 * The minimum size because we have added an ipfix_variable_field.
 *
 * SIZE_IPFIX_DATA_IDP = 32
 */
#define SIZE_IPFIX_DATA_IDP SIZE_IPFIX_DATA_SIMPLE + MIN_SIZE_VAR_FIELD

typedef struct ipfix_exporter_data_idp_ {
  uint32_t source_ipv4_address;
  uint32_t destination_ipv4_address;
  uint16_t source_transport_port;
  uint16_t destination_transport_port;
  uint8_t protocol_identifier;
  uint64_t flow_start_microseconds;
  uint64_t flow_end_microseconds;
  ipfix_variable_field_t idp_field;
} ipfix_exporter_data_idp_t;


/*
 * @brief Structure representing an IPFIX Exporter Data record.
 */
typedef struct ipfix_exporter_data_ {
  union {
    ipfix_exporter_data_simple_t simple;
    ipfix_exporter_data_idp_t idp_record;
  } record;
  ipfix_template_type_e type;
  uint16_t length; /**< total length the data record */

  struct ipfix_exporter_data_ *next;
  struct ipfix_exporter_data_ *prev;
} ipfix_exporter_data_t;


/*
 * @brief Structure representing an IPFIX message.
 */
typedef struct ipfix_message_ {
  ipfix_hdr_t hdr;

  time_t creation_time; /**< used to track how long the message has existed */

  struct ipfix_exporter_set_node_ *sets_head;
  struct ipfix_exporter_set_node_ *sets_tail;
} ipfix_message_t;

/*
 * @brief Structure representing an Options Set.
 */
typedef struct ipfix_exporter_option_set_ {
  ipfix_set_hdr_t set_hdr;
  unsigned char set[IPFIX_MAX_SET_DATA_LEN];
} ipfix_exporter_option_set_t;


/*
 * @brief Structure representing a Data Set.
 */
typedef struct ipfix_exporter_data_set_ {
  ipfix_set_hdr_t set_hdr;

  ipfix_message_t *parent_message; /**< message which the set is attached to */
  ipfix_exporter_data_t *records_head;
  ipfix_exporter_data_t *records_tail;
} ipfix_exporter_data_set_t;


/*
 * @brief Structure representing a Template Set.
 */
typedef struct ipfix_exporter_template_set_ {
  ipfix_set_hdr_t set_hdr;

  ipfix_message_t *parent_message; /**< message which the set is attached to */
  ipfix_exporter_template_t *records_head;
  ipfix_exporter_template_t *records_tail;
} ipfix_exporter_template_set_t;

typedef struct ipfix_exporter_set_node_ {
  uint16_t set_type; /**< the internal set id, made visible here */
  //uint16_t length; /**< internal set length, made visible here */
  union {
    ipfix_exporter_template_set_t *template_set;
    ipfix_exporter_option_set_t *option_set;
    ipfix_exporter_data_set_t *data_set;
  } set;

  struct ipfix_exporter_set_node_ *next;
  struct ipfix_exporter_set_node_ *prev;
} ipfix_exporter_set_node_t;



/*
 * @brief Structure representing the raw data of an IPFIX message.
 */
typedef struct ipfix_raw_message_ {
  ipfix_hdr_t hdr;
  unsigned char payload[IPFIX_MAX_SET_LEN];
} ipfix_raw_message_t;


/*
 * @brief Structure representing an IPFIX Exporter.
 */
typedef struct ipfix_exporter_ {
    struct sockaddr_in exprt_addr;  /**< exporter address */
    struct sockaddr_in clctr_addr;  /**< collector address */
    int socket;
    unsigned int msg_count;
} ipfix_exporter_t;


#define ipfix_field_enterprise_bit(a) (a & 0x8000)

#ifndef WIN32
#define min(a,b) \
    ({ __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b; })
#endif

#if CPU_IS_BIG_ENDIAN
# define bytes_to_u32(bytes) (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3] 
#else
# define bytes_to_u32(bytes) bytes[0] + (bytes[1] << 8) + (bytes[2] << 16) + (bytes[3] << 24)
#endif

#ifdef WIN32
__declspec(noreturn) void *ipfix_cts_monitor(void *ptr);
#else
__attribute__((__noreturn__)) void *ipfix_cts_monitor(void *ptr);
#endif


void ipfix_module_cleanup(joy_ctx_data *ctx);


void ipfix_cts_cleanup(void);


void ipfix_xts_cleanup(void);


int ipfix_parse_template_set(const ipfix_hdr_t *ipfix,
                         const char *template_start,
                         uint16_t set_len,
                         const flow_key_t rec_key);


int ipfix_parse_data_set(joy_ctx_data *ctx,
                         const ipfix_hdr_t *ipfix,
                         const void *data_start,
                         uint16_t set_len,
                         uint16_t set_id,
                         const flow_key_t rec_key,
                         flow_key_t *prev_key);


int ipfix_collect_main(joy_ctx_data *ctx);


int ipfix_export_flush_message(joy_ctx_data *ctx);


int ipfix_export_main(joy_ctx_data *ctx, const flow_record_t *record);
int ipfix_exporter_init(const char *host_name);

/*
 * @brief Enumeration representing IPFIX set type ids.
 */
enum ipfix_set_type {
  IPFIX_RESERVED_SET_0 =                            0,
  IPFIX_RESERVED_SET_1 =                            1,
  IPFIX_TEMPLATE_SET =                              2,
  IPFIX_OPTION_SET =                                3,
};


/*
 * @brief Enumeration representing IPFIX field entities.
 */
enum ipfix_entities {
  IPFIX_RESERVED =                                  0,
  IPFIX_OCTET_DELTA_COUNT =                         1,
  IPFIX_PACKET_DELTA_COUNT =                        2,
  IPFIX_DELTA_FLOW_COUNT =                          3,
  IPFIX_PROTOCOL_IDENTIFIER =                       4,
  IPFIX_IP_CLASS_OF_SERVICE =                       5,
  IPFIX_TCP_CONTROL_BITS =                          6,
  IPFIX_SOURCE_TRANSPORT_PORT =                     7,
  IPFIX_SOURCE_IPV4_ADDRESS =                       8,
  IPFIX_SOURCE_IPV4_PREFIX_LENGTH =                 9,
  IPFIX_INGRESS_INTERFACE =                         10,
  IPFIX_DESTINATION_TRANSPORT_PORT =                11,
  IPFIX_DESTINATION_IPV4_ADDRESS =                  12,
  IPFIX_DESTINATION_IPV4_PREFIX_LENGTH =            13,
  IPFIX_EGRESS_INTERFACE =                          14,
  IPFIX_IP_NEXT_HOP_IPV4_ADDRESS =                  15,
  IPFIX_BGP_SOURCE_AS_NUMBER =                      16,
  IPFIX_BGP_DESTINATION_AS_NUMBER =                 17,
  IPFIX_BGP_NEXT_HOP_IPV4_ADDRESS =                 18,
  IPFIX_POST_MCAST_PACKET_DELTA_COUNT =             19,
  IPFIX_POST_MCAST_OCTET_DELTA_COUNT =              20,
  IPFIX_FLOW_END_SYS_UP_TIME =                      21,
  IPFIX_FLOW_START_SYS_UP_TIME =                    22,
  IPFIX_FLOW_START_SECONDS =                        150,
  IPFIX_FLOW_END_SECONDS =                          151,
  IPFIX_FLOW_START_MILLISECONDS =                   152,
  IPFIX_FLOW_END_MILLISECONDS =                     153,
  IPFIX_FLOW_START_MICROSECONDS =                   154,
  IPFIX_FLOW_END_MICROSECONDS =                     155,
  IPFIX_BASIC_LIST =                                291,
  IPFIX_COLLECT_IDP =                               12172,
  IPFIX_IDP =                                       44940,
  IPFIX_BYTE_DISTRIBUTION_FORMAT =                  44943,
  IPFIX_BYTE_DISTRIBUTION =                         44944,
  IPFIX_TLS_CIPHER_SUITES =                         44946,
  IPFIX_TLS_VERSION =                               44948,
  IPFIX_TLS_KEY_LENGTH =                            44949,
  IPFIX_TLS_SESSION_ID =                            44950,
  IPFIX_TLS_RANDOM =                                44951,
  IPFIX_SEQUENCE_PACKET_LENGTHS =                   44952,
  IPFIX_SEQUENCE_PACKET_TIMES =                     44953,
  IPFIX_TLS_RECORD_LENGTHS =                        44956,
  IPFIX_TLS_RECORD_TIMES =                          44957,
  IPFIX_TLS_CONTENT_TYPES =                         44958,
  IPFIX_TLS_HANDSHAKE_TYPES =                       44959,
  IPFIX_TLS_EXTENSION_LENGTHS =                     44960,
  IPFIX_TLS_EXTENSION_TYPES =                       44961
};


#endif /* IPFIX_H */
