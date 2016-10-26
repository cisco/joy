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

/**************************************************
 * @file ipfix.h
 *
 * @brief Interface to IPFIX code which is used
 *        to collect or export using the protocol.
 **************************************************/

#ifndef IPFIX_H
#define IPFIX_H

#include <time.h>
#include <netinet/in.h>
#include <pthread.h>
#include "p2f.h"


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
struct ipfix_hdr {
  uint16_t version_number;
  uint16_t length;
  uint32_t export_time;
  uint32_t sequence_number;
  uint32_t observe_dom_id;
};


/*
 * @brief Structure representing a set header.
 */
struct ipfix_set_hdr {
  uint16_t set_id;
  uint16_t length;
};


/*
 * @brief Structure representing a template header.
 */
struct ipfix_template_hdr {
  uint16_t template_id;
  uint16_t field_count;
};


/*
 * @brief Structure representing an options header.
 */
struct ipfix_option_hdr {
  uint16_t template_id;
  uint16_t field_count;
  uint16_t scope_field_count;
};


/*
 * @brief Structure representing a template field specifier.
 *
 * This may not have the enterprise_num field populated with
 * data depending on whether the leftmost bit of info_elem_id
 * is set (big-endian).
 *
 * FIXME see if the enterprise_num memory can be dynamically chosen??
 */
struct ipfix_template_field {
  uint16_t info_elem_id;
  uint16_t fixed_length; /* FIXME make this into union eventually? */
  uint32_t enterprise_num;
  uint16_t variable_length;
  uint8_t var_hdr_length; /**< How many bytes the variable header consists of */
};


#define IPFIX_MAX_LEN 1480 /* FIXME is this the right limit? */
#define IPFIX_MAX_FIELDS (IPFIX_MAX_LEN/4)


/*
 * @brief Structure representing a Template key.
 *
 * Used by the Collector to track Templates as unique entities.
 */
struct ipfix_template_key {
  struct in_addr exporter_addr;
  uint32_t observe_dom_id;
  uint16_t template_id;
};


/*
 * @brief Structure representing a single Template entity.
 *
 * Stored by the collector to interpret subsequent related Data Sets.
 */
struct ipfix_template {
  struct ipfix_template_key template_key;
  struct ipfix_template_hdr hdr;
  struct ipfix_template_field *fields;
  int payload_length; /**< Keeps track of the actual template field payload length encountered,
                           since all ipfix_template_fields have enterprise memory allocated,
                           but that may not have been true for payload */

  time_t last_seen;
  struct ipfix_template *next;
  struct ipfix_template *prev;
};


/*
 * @brief Structure representing a Template Set.
 */
struct ipfix_template_set {
  struct ipfix_set_hdr set_hdr;
  struct ipfix_template_hdr template_hdr; /**< First template header is always needed */
  unsigned char set[IPFIX_MAX_LEN]; /**< May contain more template headers */
};


/*
 * @brief Structure representing an Options Set.
 */
struct ipfix_option_set {
  struct ipfix_set_hdr set_hdr;
  struct ipfix_option_hdr option_hdr; /**< First options header is always needed */
  unsigned char set[IPFIX_MAX_LEN]; /**< May contain more options headers */
};


/*
 * @brief Structure representing a Data Set.
 */
struct ipfix_data_set {
  struct ipfix_set_hdr set_hdr;
  unsigned char set[IPFIX_MAX_LEN];
};


struct __attribute__((__packed__)) ipfix_basic_list_hdr {
  uint8_t semantic;
  uint16_t field_id;
  uint16_t element_length;
  uint32_t enterprise_num;
};


/*
 * @brief Structure representing an IPFIX message.
 */
struct ipfix_msg {
  struct ipfix_hdr hdr;
  union {
    struct ipfix_template_set template_fs;
    struct ipfix_data_set     data_fs;
    struct ipfix_option_set   option_fs;
  } set;
};


#define ipfix_field_enterprise_bit(a) (a & 0x8000)

#define min(a,b) \
    ({ __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b; })


void *ipfix_cts_monitor(void *ptr);


void ipfix_cts_cleanup(void);


int ipfix_parse_template_set(const struct ipfix_hdr *ipfix,
                         const void *template_start,
                         uint16_t set_len,
                         const struct flow_key rec_key);


int ipfix_parse_data_set(const struct ipfix_hdr *ipfix,
                         const void *data_start,
                         uint16_t set_len,
                         uint16_t set_id,
                         const struct flow_key rec_key,
                         struct flow_key *prev_key);


/*
 * @brief Enumeration representing IPFIX field entities.
 *
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
  IPFIX_BASIC_LIST =                                291,
  IPFIX_IDP =                                       16386,
  IPFIX_BYTE_DISTRIBUTION =                         16390,
  IPFIX_BYTE_DISTRIBUTION_FORMAT =                  16398,
  IPFIX_SEQUENCE_PACKET_LENGTHS =                   16399,
  IPFIX_SEQUENCE_PACKET_TIMES =                     16400,
  IPFIX_TLS_RECORD_LENGTHS =                        16403,
  IPFIX_TLS_RECORD_TIMES =                          16404,
  IPFIX_TLS_CONTENT_TYPES =                         16405,
  IPFIX_TLS_HANDSHAKE_TYPES =                       16406,
  IPFIX_TLS_CIPHER_SUITES =                         16392,
  IPFIX_TLS_EXTENSION_LENGTHS =                     16407,
  IPFIX_TLS_EXTENSION_TYPES =                       16408,
  IPFIX_TLS_VERSION =                               16394,
  IPFIX_TLS_KEY_LENGTH =                            16395,
  IPFIX_TLS_SESSION_ID =                            16396,
  IPFIX_TLS_RANDOM =                                16397,
};


#endif /* IPFIX_H */
