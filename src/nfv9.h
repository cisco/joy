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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>

#include "p2f.h"

#define NFV9_MAX_ELEMENTS 10

/*
  
  Netflow v9 (RFC 3959)

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Version Number = 9        |            Count              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           sysUpTime                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           UNIX Secs                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Sequence Number                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Source ID                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Count
         The total number of records in the Export Packet, which is the
         sum of Options FlowSet records, Template FlowSet records, and
         Data FlowSet records.

   sysUpTime
         Time in milliseconds since this device was first booted.

   UNIX Secs
         Time in seconds since 0000 UTC 1970, at which the Export Packet
         leaves the Exporter.

   Sequence Number
         Incremental sequence counter of all Export Packets sent from
         the current Observation Domain by the Exporter.  This value
         MUST be cumulative, and SHOULD be used by the Collector to
         identify whether any Export Packets have been missed.

   Source ID
         A 32-bit value that identifies the Exporter Observation Domain.
         NetFlow Collectors SHOULD use the combination of the source IP
         address and the Source ID field to separate different export
         streams originating from the same Exporter.

   The format of the Template FlowSet is as follows:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       FlowSet ID = 0          |          Length               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Template ID 256          |         Field Count           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Field Type 1           |         Field Length 1        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Field Type 2           |         Field Length 2        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             ...               |              ...              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Field Type N           |         Field Length N        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Template ID 257          |         Field Count           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Field Type 1           |         Field Length 1        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Field Type 2           |         Field Length 2        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             ...               |              ...              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Field Type M           |         Field Length M        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             ...               |              ...              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Template ID K          |         Field Count           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             ...               |              ...              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


   The format of the Data FlowSet is as follows:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   FlowSet ID = Template ID    |          Length               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Record 1 - Field Value 1    |   Record 1 - Field Value 2    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Record 1 - Field Value 3    |             ...               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Record 2 - Field Value 1    |   Record 2 - Field Value 2    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Record 2 - Field Value 3    |             ...               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Record 3 - Field Value 1    |             ...               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              ...              |            Padding            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/


enum nfv9_type {                                 
  RESERVED =                       0,                         
  IN_BYTES =                       1,       
  IN_PKTS =                        2,      
  FLOWS =                          3,      
  PROTOCOL =                       4,      
  TOS =                            5,      
  //  TCP_FLAGS =                      6,     
  L4_SRC_PORT =                    7,     
  IPV4_SRC_ADDR =                  8,     
  SRC_MASK =                       9,     
  INPUT_SNMP =                    10,     
  L4_DST_PORT =                   11,     
  IPV4_DST_ADDR =                 12,     
  DST_MASK =                      13,     
  OUTPUT_SNMP =                   14,     
  IPV4_NEXT_HOP =                 15,     
  SRC_AS =                        16,     
  DST_AS =                        17,     
  BGP_IPV4_NEXT_HOP =             18,     
  MUL_DST_PKTS =                  19,     
  MUL_DST_BYTES =                 20,     
  LAST_SWITCHED =                 21,     
  FIRST_SWITCHED =                22,     
  OUT_BYTES =                     23,     
  OUT_PKTS =                      24,     
  IPV6_SRC_ADDR =                 27,     
  IPV6_DST_ADDR =                 28,     
  IPV6_SRC_MASK =                 29,     
  IPV6_DST_MASK =                 30,     
  IPV6_FLOW_LABEL =               31,     
  ICMP_TYPE =                     32,     
  MUL_IGMP_TYPE =                 33,     
  SAMPLING_INTERVAL =             34,     
  SAMPLING_ALGORITHM =            35,     
  FLOW_ACTIVE_TIMEOUT =           36,     
  FLOW_INACTIVE_TIMEOUT =         37,     
  ENGINE_TYPE =                   38,     
  ENGINE_ID =                     39,     
  TOTAL_BYTES_EXP =               40,     
  TOTAL_PKTS_EXP =                41,     
  TOTAL_FLOWS_EXP =               42,   
  IPV4_SRC_PREFIX =               44,   
  IPV4_DST_PREFIX =               45,   
  MPLS_TOP_LABEL_TYPE =           46,   
  MPLS_TOP_LABEL_IP_ADDR =        47,     
  FLOW_SAMPLER_ID =               48,     
  FLOW_SAMPLER_MODE =             49,     
  FLOW_SAMPLER_RANDOM_INTERVAL =  50,   
  MIN_TTL =                       52,   
  MAX_TTL =                       53,   
  IPV4_IDENT =                    54,   
  DST_TOS =                       55,     
  SRC_MAC =                       56,     
  DST_MAC =                       57,     
  SRC_VLAN =                      58,     
  DST_VLAN =                      59,     
  IP_PROTOCOL_VERSION =           60,     
  DIRECTION =                     61,     
  IPV6_NEXT_HOP =                 62,    
  BGP_IPV6_NEXT_HOP =             63,    
  IPV6_OPTION_HEADERS =           64,   
  MPLS_LABEL_1 =                  70,     
  MPLS_LABEL_2 =                  71,     
  MPLS_LABEL_3 =                  72,     
  MPLS_LABEL_4 =                  73,     
  MPLS_LABEL_5 =                  74,     
  MPLS_LABEL_6 =                  75,     
  MPLS_LABEL_7 =                  76,     
  MPLS_LABEL_8 =                  77,     
  MPLS_LABEL_9 =                  78,     
  MPLS_LABEL_10 =                 79,     
  IN_DST_MAC =                    80,   
  OUT_SRC_MAC =                   81,   
  IF_NAME =                       82,   
  IF_DESC =                       83,   
  SAMPLER_NAME =                  84,   
  IN_PERMANENT_BYTES =            85,   
  IN_PERMANENT_PKTS =             86,   
  FRAGMENT_OFFSET =               88,   
  FORWARDING_STATUS =             89,   
  MPLS_PAL_RD =                   90,   
  MPLS_PREFIX_LEN =               91,   
  SRC_TRAFFIC_INDEX =             92,   
  DST_TRAFFIC_INDEX =             93,   
  APPLICATION_DESCRIPTION =       94,   
  APPLICATION_TAG =               95,   
  APPLICATION_NAME =              96,   
  postipDiffServCodePoint =       98,   
  replication_factor =            99,   
  layer2packetSectionOffset =    102,   
  layer2packetSectionSize =      103,   
  layer2packetSectionData =      104,   
  IDP =                        16386,
  SPLT =                       16387,
  SALT =                       16388,
  SPLT_NGA =                   16389,
  BYTE_DISTRIBUTION =          16390
};


struct nfv9_field_type {
  char *FieldName;
  u_short Value;
  u_short Length;
};

#define MAX_TYPES 105

struct nfv9_field_type *get_nfv9_field_type(u_short typecode);

/* forwarding_status

Unknown
• 0

Forwarded
• Unknown 64
• Forwarded Fragmented 65
• Forwarded not Fragmented 66

Dropped
• Unknown 128,
• Drop ACL Deny 129,
• Drop ACL drop 130,
• Drop Unroutable 131,
• Drop Adjacency 132,
• Drop Fragmentation & DF set 133,
• Drop Bad header checksum 134,
• Drop Bad total Length 135,
• Drop Bad Header Length 136,
• Drop bad TTL 137,
• Drop Policer 138,
• Drop WRED 139,
• Drop RPF 140,
• Drop For us 141,
• Drop Bad output interface 142,
• Drop Hardware 143,

Consumed
• Unknown 192,
• Terminate Punt Adjacency 193,
• Terminate Incomplete Adjacency 194,
• Terminate For us 195

*/

struct nfv9_hdr {
  u_short VersionNumber;
  u_short Count;
  u_int sysUpTime;
  u_int UNIXSecs;
  u_int SequenceNumber;
  u_int SourceID;
};

struct nfv9_flowset_hdr {
  u_short FlowSetID;
  u_short Length;
};

struct nfv9_template_hdr {
  u_short TemplateID;
  u_short FieldCount;
};

struct nfv9_template_field {
  u_short FieldType;
  u_short FieldLength;
};

#define NFV9_MAX_LEN 1480
#define NFV9_MAX_FIELDS (NFV9_MAX_LEN/4)

struct nfv9_template_key {
  struct in_addr src_addr;
  u_long src_id;
  u_short template_id;
};

struct nfv9_template {
  struct nfv9_template_key template_key;
  struct nfv9_template_hdr hdr;
  struct nfv9_template_field fields[NFV9_MAX_FIELDS];
};

struct nfv9_template_flowset {
  struct nfv9_flowset_hdr flowset_hdr;
  u_char flowset[NFV9_MAX_LEN];
};

struct nfv9_data_flowset {
  struct nfv9_flowset_hdr flowset_hdr;
  u_char flowset[NFV9_MAX_LEN];
};

struct nfv9_option_flowset {
  struct nfv9_flowset_hdr flowset_hdr;
  u_char flowset[NFV9_MAX_LEN];
};

struct nfv9_exporter {
  struct sockaddr_in exprt_addr;  /* exporter address */
  struct sockaddr_in clctr_addr;  /* collector address */
  int socket;
  time_t sysUpTime;
  unsigned int msg_count;
  struct nfv9_option_flowset option_flowset;
};

struct nfv9_msg {
  struct nfv9_hdr hdr;
  union { 
    struct nfv9_template_flowset template_fs;
    struct nfv9_data_flowset     data_fs;
    struct nfv9_option_flowset   option_fs;
  } flowset;
};

typedef void (*template_handler_func)(void *, unsigned int);

struct template_handler {
  u_short template_id;
  struct nfv9_template template;
  template_handler_func func;
  struct template_handler *next; 
}x;

struct template_handler *get_template_handler(unsigned int template_id);

#define nfv9_template_field(a) ((struct nfv9_template_field) {a, 0})
#define nfv9_template_field_len(a,b) ((struct nfv9_template_field) {a, b})
#define nfv9_template_key_cmp(a, b) memcmp(a, b, sizeof(struct nfv9_template_key))

void nfv9_template_key_init(struct nfv9_template_key *k,
			    u_long addr,
			    u_long id,
			    u_short template_id);

void nfv9_exporter_init(struct nfv9_exporter *e, const char *hostname);


void nfv9_template_print(const struct nfv9_template *template);


void 
nfv9_template_flowset_encode_template(struct nfv9_template_flowset *fs,
				      const struct nfv9_template *template);



void nfv9_template_flowset_encode_init(struct nfv9_template_flowset *fs);


void nfv9_data_flowset_encode_init(struct nfv9_data_flowset *fs,
				   const struct nfv9_template *t);

void nfv9_data_flowset_encode_record(struct nfv9_data_flowset *fs,
				     const void *record,
				     const struct nfv9_template *template);

void nfv9_data_flowset_encode_final(struct nfv9_data_flowset *fs);

void nfv9_template_flowset_encode_final(struct nfv9_template_flowset *fs);

void nfv9_template_decode(const void *input,
			  struct nfv9_template *template,
			  unsigned int template_len);


void nfv9_flow_record_print(const void *record,
			    const struct nfv9_template *template);


int nfv9_flow_record_decode(const void *input, 
			    const struct nfv9_template *template,
			    void *record,  /* output */ 
			    unsigned int output_len);

void nfv9_data_flowset_decode_and_handle(struct nfv9_data_flowset *fs);


unsigned int nfv9_register_template_handler(const struct nfv9_template *t, 
					    template_handler_func f);


void nfv9_unregister_template_handler(unsigned int template_id);

/* functions for parsing nfv9 packets */
void nfv9_flow_key_init(struct flow_key *key, const struct nfv9_template *cur_template, const void *flow_data);

void nfv9_process_flow_record(struct flow_record *nf_record, const struct nfv9_template *cur_template, const void *flow_data, int record_num);

void nfv9_process_lengths(struct flow_record *nf_record, const void *length_data, int max_length_array, int pkt_len_index);

void nfv9_process_times(struct flow_record *nf_record, const void *time_data, struct timeval *old_val_time, int max_length_array, int pkt_time_index);

