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
#include "utils.h"      /* for enum role */

#define ike_usage "  ike=1                      report IKE information\n"

#define ike_filter(key) ((key->prot == 17) && (key->dp == 500 || key->sp == 500 || key->dp == 4500 || key->sp == 4500))

#define IKE_MAX_MESSAGE_LEN 35000 /* must be at least 1200, should be at least 3000 according to RFC 5996 */

/* these should all be reasonably conservative limits */
#define IKE_MAX_MESSAGES 20
#define IKE_MAX_PAYLOADS 20
#define IKE_MAX_PROPOSALS 20
#define IKE_MAX_TRANSFORMS 20
#define IKE_MAX_ATTRIBUTES 20

struct ike_attribute {
    uint16_t type;
    uint8_t encoding;
    struct vector *data;
};

struct ike_transform {
    uint8_t last;
    uint16_t length;
    uint8_t type;
    uint16_t id;
    uint8_t num_v1;
    uint8_t id_v1;
    unsigned int num_attributes;
    struct ike_attribute *attributes[IKE_MAX_ATTRIBUTES];
};

struct ike_proposal {
    uint8_t last;
    uint16_t length;
    uint8_t num;
    uint8_t protocol_id;
    struct vector *spi;
    uint8_t num_transforms;
    struct ike_transform *transforms[IKE_MAX_TRANSFORMS];
};

struct ike_sa {
    uint32_t doi_v1;
    uint32_t situation_v1;
    uint32_t ldi_v1;
    struct vector *secrecy_level_v1;
    struct vector *secrecy_category_v1;
    struct vector *integrity_level_v1;
    struct vector *integrity_category_v1;
    unsigned int num_proposals;
    struct ike_proposal *proposals[IKE_MAX_PROPOSALS];
};

struct ike_ke {
    uint16_t group;
    struct vector *data;
};

struct ike_id {
    uint8_t type;
    struct vector *data;
};

struct ike_cert {
    uint8_t encoding;
    struct vector *data;
};

struct ike_cr {
    uint8_t encoding;
    struct vector *data;
};

struct ike_auth {
    uint8_t method;
    struct vector *data;
};

struct ike_hash_v1 {
    struct vector *data;
};

struct ike_notify {
    uint32_t doi_v1;
    uint8_t protocol_id;
    uint16_t type;
    struct vector *spi;
    struct vector *data;
};

struct ike_nonce {
    struct vector *data;
};

struct ike_vendor_id {
    struct vector *data;
};

union ike_payload_body {
    struct ike_sa *sa;
    struct ike_ke *ke;
    struct ike_id *id;
    struct ike_cert *cert;
    struct ike_cr *cr;
    struct ike_auth *auth;
    struct ike_hash_v1 *hash_v1;
    struct ike_nonce *nonce;
    struct ike_notify *notify;
    struct ike_vendor_id *vendor_id;
};

struct ike_payload {
    uint8_t type;
    uint8_t next_payload;
    uint8_t reserved;
    uint16_t length;
    union ike_payload_body *body;
};

struct ike_header {
    uint8_t init_spi[8]; /* IKEv1 initiator cookie */
    uint8_t resp_spi[8]; /* IKEv1 responder cookie */
    uint8_t next_payload;
    uint8_t major;
    uint8_t minor;
    uint8_t exchange_type;
    uint8_t flags;
    uint32_t message_id;
    uint32_t length;
};

struct ike_message {
    struct ike_header *header;
    unsigned int num_payloads;
    struct ike_payload *payloads[IKE_MAX_PAYLOADS];
};

typedef struct ike {
    enum role role;
    unsigned int num_messages;
    struct ike_message *messages[IKE_MAX_MESSAGES];
    struct vector *buffer;
} ike_t;

declare_feature(ike);

void ike_init(struct ike **ike_handle);

void ike_update(struct ike *ike,
                const struct pcap_pkthdr *header,
        const void *data,
        unsigned int len,
        unsigned int report_ike);

void ike_print_json(const struct ike *w1,
            const struct ike *w2,
            zfile f);

void ike_delete(struct ike **ike_handle);

void ike_unit_test();

#endif /* IKE_H */

