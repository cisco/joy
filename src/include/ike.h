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

/*
 * ike.h
 *
 * Internet Key Exchange (IKE) awareness for joy
 *
 */

#ifndef IKE_H
#define IKE_H

#include <stdio.h>      /* for FILE* */
#include <pcap.h>
#include "output.h"
#include "feature.h"
#include "utils.h"      /* for joy_role_e */

#define ike_usage "  ike=1                      report IKE information\n"

#define ike_filter(record) \
    ((record->key.prot == 17) && \
     (record->app == 500 || \
      (record->key.dp == 500 || record->key.sp == 500 || record->key.dp == 4500 || record->key.sp == 4500) \
     ) \
    )

#define IKE_MAX_MESSAGE_LEN 35000 /* must be at least 1200, should be at least 3000 according to RFC 5996 */

/* these should all be reasonably conservative limits */
#define IKE_MAX_MESSAGES 20
#define IKE_MAX_PAYLOADS 20
#define IKE_MAX_PROPOSALS 20
#define IKE_MAX_TRANSFORMS 20
#define IKE_MAX_ATTRIBUTES 20

/**
 * \brief A vector structure contains a pointer to a byte array with a given length.
 */
typedef struct vector_ {
    unsigned int len;
    unsigned char *bytes;
} vector_t;

typedef struct ike_attribute_ {
    uint16_t type;
    uint8_t encoding;
    vector_t *data;
} ike_attribute_t;

typedef struct ike_transform_ {
    uint8_t last;
    uint16_t length;
    uint8_t type;
    uint16_t id;
    uint8_t num_v1;
    uint8_t id_v1;
    unsigned int num_attributes;
    ike_attribute_t *attributes[IKE_MAX_ATTRIBUTES];
} ike_transform_t;

typedef struct ike_proposal_ {
    uint8_t last;
    uint16_t length;
    uint8_t num;
    uint8_t protocol_id;
    vector_t *spi;
    uint8_t num_transforms;
    ike_transform_t *transforms[IKE_MAX_TRANSFORMS];
} ike_proposal_t;

typedef struct ike_sa_ {
    uint32_t doi_v1;
    uint32_t situation_v1;
    uint32_t ldi_v1;
    vector_t *secrecy_level_v1;
    vector_t *secrecy_category_v1;
    vector_t *integrity_level_v1;
    vector_t *integrity_category_v1;
    unsigned int num_proposals;
    ike_proposal_t *proposals[IKE_MAX_PROPOSALS];
} ike_sa_t;

typedef struct ike_ke_ {
    uint16_t group;
    vector_t *data;
} ike_ke_t;

typedef struct ike_id_ {
    uint8_t type;
    vector_t *data;
} ike_id_t;

typedef struct ike_cert_ {
    uint8_t encoding;
    vector_t *data;
} ike_cert_t;

typedef struct ike_cr_ {
    uint8_t encoding;
    vector_t *data;
} ike_cr_t;

typedef struct ike_auth_ {
    uint8_t method;
    vector_t *data;
} ike_auth_t;

typedef struct ike_hash_ {
    vector_t *data;
} ike_hash_t;

typedef struct ike_notify_ {
    uint32_t doi_v1;
    uint8_t protocol_id;
    uint16_t type;
    vector_t *spi;
    vector_t *data;
}ike_notify_t;

typedef struct ike_nonce_ {
    vector_t *data;
} ike_nonce_t;

typedef struct ike_vendor_id_ {
    vector_t *data;
} ike_vendor_id_t;

union ike_payload_body {
    ike_sa_t *sa;
    ike_ke_t *ke;
    ike_id_t *id;
    ike_cert_t *cert;
    ike_cr_t *cr;
    ike_auth_t *auth;
    ike_hash_t *hash;
    ike_nonce_t *nonce;
    ike_notify_t *notify;
    ike_vendor_id_t *vendor_id;
};

typedef struct ike_payload_ {
    uint8_t type;
    uint8_t next_payload;
    uint8_t reserved;
    uint16_t length;
    union ike_payload_body *body;
} ike_payload_t;

typedef struct ike_header_ {
    uint8_t init_spi[8]; /* IKEv1 initiator cookie */
    uint8_t resp_spi[8]; /* IKEv1 responder cookie */
    uint8_t next_payload;
    uint8_t major;
    uint8_t minor;
    uint8_t exchange_type;
    uint8_t flags;
    uint32_t message_id;
    uint32_t length;
} ike_header_t;

typedef struct ike_message_ {
    ike_header_t *header;
    unsigned int num_payloads;
    ike_payload_t *payloads[IKE_MAX_PAYLOADS];
} ike_message_t;

typedef struct ike_ {
    joy_role_e role;
    unsigned int num_messages;
    ike_message_t *messages[IKE_MAX_MESSAGES];
    vector_t *buffer;
} ike_t;

declare_feature(ike);

void ike_init(ike_t **ike_handle);

void ike_update(ike_t *ike,
                const struct pcap_pkthdr *header,
		const void *data,
		unsigned int len,
		unsigned int report_ike);

void ike_print_json(const ike_t *w1,
		    const ike_t *w2,
		    zfile f);

void ike_delete(ike_t **ike_handle);

void ike_unit_test();

#endif /* IKE_H */

