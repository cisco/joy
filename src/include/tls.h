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

/**
 * \file tls.h
 *
 * \brief header file for TLS functionality
 */

#ifndef TLS_H
#define TLS_H

#include <pcap.h>
#include "output.h"
#include "utils.h"
#include "fingerprint.h"

/** usage string for tls */
#define tls_usage "  tls=1                      report TLS data (ciphersuites, record lengths and times, ...)\n"

/** tls filter key */
#define tls_filter(record) (record->app == 443 || (record->key.dp == 443 || record->key.sp == 443))

/* constants for TLS awareness */
#define MAX_CS 256
#define MAX_EXTENSIONS 256
#define MAX_SID_LEN 256
#define MAX_NUM_RCD_LEN 100

/* Maxiumum handshakes we should see under a single content message */
#define MAX_TLS_HANDSHAKES 5

#ifdef OUT
#undef OUT
#endif
#define OUT "<"

#ifdef IN
#undef IN
#endif
#define IN  ">"

#define NUM_PKT_LEN_TLS 50
#define MAX_CERTIFICATES 4
#define MAX_RDN 12
#define MAX_SAN 12
#define MAX_CERT_EXTENSIONS 12
#define MAX_CKE_LEN 1024
/* The maimum size of string that we allow from OpenSSL */
#define MAX_OPENSSL_STRING 32

/** \remarks \verbatim
  structure for TLS awareness 

  From RFC 5246:

      struct {
          ContentType type;
          ProtocolVersion version;
          uint16 length;
          opaque fragment[TLSPlaintext.length];
      } TLSPlaintext;

      struct {
         HandshakeType msg_type;    
         uint24 length;             
         select (HandshakeType) {
            case hello_request:       HelloRequest;
            case client_hello:        ClientHello;
            case server_hello:        ServerHello;
            case certificate:         Certificate;
            case server_key_exchange: ServerKeyExchange;
            case certificate_request: CertificateRequest;
            case server_hello_done:   ServerHelloDone;
            case certificate_verify:  CertificateVerify;
            case client_key_exchange: ClientKeyExchange;
            case finished:            Finished;
         } body;
      } Handshake;

      struct {
          ProtocolVersion client_version;
          Random random;
          SessionID session_id;
          CipherSuite cipher_suites<2..2^16-2>;
          CompressionMethod compression_methods<1..2^8-1>;
          select (extensions_present) {
              case false:
                  struct {};
              case true:
                  Extension extensions<0..2^16-1>;
          };
      } ClientHello;

      struct {
          uint16 msg_length;
          uint8 msg_type;
          Version version;
          uint16 cipher_spec_length;
          uint16 session_id_length;
          uint16 challenge_length;
          V2CipherSpec cipher_specs[V2ClientHello.cipher_spec_length];
          opaque session_id[V2ClientHello.session_id_length];
          opaque challenge[V2ClientHello.challenge_length;
      } V2ClientHello;
 \endverbatim
 */

/*
 * Structures for storing relevant TLS information
 */

typedef struct tls_message_stat_ {
    unsigned char content_type;
    unsigned char handshake_types[MAX_TLS_HANDSHAKES];
    uint16_t handshake_lens[MAX_TLS_HANDSHAKES];
    unsigned char num_handshakes;
} tls_message_stat_t;

typedef struct tls_extension_ {
    uint16_t type;
    uint16_t length;
    unsigned char *data;
} tls_extension_t;

typedef struct tls_item_entry_ {
    char id[MAX_OPENSSL_STRING]; /**< Identification (string) */
    unsigned char *data; /**< Data encapsulated within the item */
    uint16_t data_length; /**< Length of the data in bytes */
} tls_item_entry_t;

typedef struct tls_certificate_ {
    uint16_t length;
    unsigned char *serial_number; /**< Serial Number */
    uint8_t serial_number_length; /**< Length of the serial number in bytes */
    unsigned char *signature; /**< Signature */
    uint16_t signature_length; /**< Length of the signature in bytes */
    char signature_algorithm[MAX_OPENSSL_STRING]; /**< Signature algorithm (string) */
    uint16_t signature_key_size; /**< Length of the signature key in bits */
    tls_item_entry_t issuer[MAX_RDN]; /**< Array of item entries corresponding
                                                to the issuer information */
    uint8_t num_issuer_items;
    tls_item_entry_t subject[MAX_RDN]; /**< Array of item entries corresponding
                                                 to the subject information */
    uint8_t num_subject_items;
    tls_item_entry_t extensions[MAX_CERT_EXTENSIONS]; /**< Array of item entries corresponding
                                                                to the extension information */
    uint8_t num_extension_items;
    unsigned char *validity_not_before;
    uint16_t validity_not_before_length;
    unsigned char *validity_not_after;
    uint16_t validity_not_after_length;
    char subject_public_key_algorithm[MAX_OPENSSL_STRING]; /**< Subject public key algorithm (string) */
    uint16_t subject_public_key_size; /**< Length of the subject public key in bits */
} tls_certificate_t;

typedef struct tls_ {
    joy_role_e role; /**< client, server, or unknown */
    uint16_t op;
    uint16_t lengths[MAX_NUM_RCD_LEN]; /**< TLS record lengths */
    struct timeval times[MAX_NUM_RCD_LEN]; /**< Arrival times */
    tls_message_stat_t msg_stats[MAX_NUM_RCD_LEN]; /**< Message generic stats */
    uint16_t num_ciphersuites; /**< Number of ciphersuites */
    uint16_t ciphersuites[MAX_CS]; /**< Ciphersuites */
    uint16_t num_extensions; /**< Number of extensions */
    uint16_t num_server_extensions; /**< Number of server extensions */
    tls_extension_t extensions[MAX_EXTENSIONS]; /**< Extensions */
    tls_extension_t server_extensions[MAX_EXTENSIONS]; /**< Extensions of server */
    unsigned char version; /**< TLS version */
    unsigned int client_key_length; /**< clientKeyExchange key length */
    unsigned char clientKeyExchange[MAX_CKE_LEN]; /**< clientKeyExchange data */
    unsigned char sid_len; /**< Session ID length */
    unsigned char sid[MAX_SID_LEN]; /**< Session ID */
    unsigned char random[32]; /**< Random field from hello */
    tls_certificate_t certificates[MAX_CERTIFICATES]; /**< X.509 certificates */
    unsigned char num_certificates; /**< Number of certificates */
    unsigned char *sni; /**< SNI a.k.a Server name indication */
    uint16_t sni_length; /**< Length of SNI */
    unsigned char *handshake_buffer; /**< Handshake message(s) data */
    uint16_t handshake_length; /**< Length of data in handshake buffer */
    unsigned char done_handshake; /**< Flag indicating the hanshake phase has completed */
    uint16_t seg_offset;
    fingerprint_t *tls_fingerprint;
} tls_t;


/*
 * Structures for parsing TLS content
 */

typedef struct tls_protocol_version_ {
    unsigned char major;
    unsigned char minor;
} tls_protocol_version_t;


typedef struct tls_ciphertext_ {
    tls_protocol_version_t protocol_version;
    unsigned char lengthMid;
    unsigned char lengthLo;
} tls_ciphertext_t;

typedef struct tls_handshake_ {
    unsigned char msg_type; /**< Handshake message type */
    unsigned char lengthHi; /**< First byte of Handshake length (big endian) */
    unsigned char lengthMid; /**< Middle byte of Handshake length (big endian) */
    unsigned char lengthLo; /**< Last byte of Handshake length (big endian) */
    unsigned char body; /**< Body, a.k.a payload of the message */
} tls_handshake_t;

typedef struct tls_header_ {
    unsigned char content_type;
    tls_protocol_version_t protocol_version;
    unsigned char lengthMid;
    unsigned char lengthLo;
    union {
        tls_ciphertext_t ciphertext;
        tls_handshake_t handshake;
    };
} tls_header_t;

typedef struct tls_random {
    unsigned int gmt_unix_time;
    unsigned char random_bytes[28];
} tls_random_t;

typedef struct tls_client_hello_ {
    tls_protocol_version_t protocol_version;
    tls_random_t random;
    unsigned char session_id_length;
    uint16_t count_cipher_suites;
} tls_client_hello_t;

/*
 * @brief Enumeration representing TLS versions internal to Joy.
 */
typedef enum tls_version_ {
    TLS_VERSION_UNKNOWN = 0,
    TLS_VERSION_SSLV2 = 1,
    TLS_VERSION_SSLV3 = 2,
    TLS_VERSION_1_0 = 3,
    TLS_VERSION_1_1 = 4,
    TLS_VERSION_1_2 = 5,
    TLS_VERSION_1_3 = 6
} tls_version_e;

/*
 * @brief Enumeration representing TLS HandshakeTypes.
 */
typedef enum tls_handshake_type_ {
    TLS_HANDSHAKE_HELLO_REQUEST = 0,
    TLS_HANDSHAKE_CLIENT_HELLO = 1,
    TLS_HANDSHAKE_SERVER_HELLO = 2,
    TLS_HANDSHAKE_CERTIFICATE = 11,
    TLS_HANDSHAKE_SERVER_KEY_EXCHANGE = 12,
    TLS_HANDSHAKE_CERTIFICATE_REQUEST = 13,
    TLS_HANDSHAKE_SERVER_HELLO_DONE = 14,
    TLS_HANDSHAKE_CERTIFICATE_VERIFY = 15,
    TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE = 16,
    TLS_HANDSHAKE_FINISHED = 20
} tls_handshake_type_e;

/*
 * @brief Enumeration representing TLS ContentTypes.
 */
typedef enum tls_content_type_ {
    TLS_CONTENT_CHANGE_CIPHER_SPEC = 20,
    TLS_CONTENT_ALERT = 21,
    TLS_CONTENT_HANDSHAKE = 22,
    TLS_CONTENT_APPLICATION_DATA = 23
} tls_content_type_e;

/*
 * TLS module public functions
 */

/** initialize TLS structure */
void tls_init(tls_t **tls_handle);

/** free data associated with TLS record */
void tls_delete(tls_t **tls_handle);

/** process TLS packet for consumption */
void tls_update(tls_t *r,
                const struct pcap_pkthdr *header,
                const void *data,
                unsigned int data_len,
                unsigned int report_tls);

/** print out the TLS information to the destination file */
void tls_print_json(const tls_t *data, const tls_t *data_twin, zfile f);

void tls_unit_test();

#if 0
int tls_load_fingerprints(void);
#endif

#endif /* TLS_H */

