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
 * tls.h
 *
 * header file for TLS functionality
 */

#ifndef TLS_H
#define TLS_H

#include <pcap.h>
#include "output.h"

/* constants for TLS awareness */
#define MAX_CS 256
#define MAX_EXTENSIONS 256
#define MAX_SID_LEN 256
#define MAX_NUM_RCD_LEN 200
#define OUT "<"
#define IN  ">"
#define NUM_PKT_LEN_TLS 50
#define MAX_CERTIFICATES 4
#define MAX_RDN 12
#define MAX_SAN 12
#define MAX_CERT_EXTENSIONS 12
#define MAX_CERTIFICATE_BUFFER 11000

/* structure for TLS awareness */
/*
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
 */

/* structures for storing relevant TLS information */
struct tls_type_code {
  unsigned char content;
  unsigned char handshake;
};

struct tls_extension {
  unsigned short int type;
  unsigned short int length;
  void *data;
};

struct tls_certificate {
  unsigned short length;
  void *serial_number;
  unsigned short serial_number_length;
  void *signature;
  unsigned short signature_length;
  void *issuer_id[MAX_RDN];
  unsigned short issuer_id_length[MAX_RDN];
  void *issuer_string[MAX_RDN];
  //unsigned short issuer_string_length[MAX_RDN];
  unsigned short num_issuer;
  void *validity_not_before;
  //unsigned short validity_not_before_length;
  void *validity_not_after;
  //unsigned short validity_not_after_length;
  void *subject_id[MAX_RDN];
  unsigned short subject_id_length[MAX_RDN];
  void *subject_string[MAX_RDN];
  //unsigned short subject_string_length[MAX_RDN];
  unsigned short num_subject;
  void *subject_public_key_algorithm;
  unsigned short subject_public_key_algorithm_length;
  unsigned short subject_public_key_size;
  void *ext_id[MAX_CERT_EXTENSIONS];
  unsigned short ext_id_length[MAX_CERT_EXTENSIONS];
  void *ext_data[MAX_CERT_EXTENSIONS];
  unsigned short ext_data_length[MAX_CERT_EXTENSIONS];
  unsigned short num_ext;
  unsigned short signature_key_size;
  void *san[MAX_SAN];
  unsigned short num_san;
};

struct tls_information {
  unsigned int   tls_op;
  unsigned short tls_len[MAX_NUM_RCD_LEN];  /* array of TLS record lengths     */  
  struct timeval tls_time[MAX_NUM_RCD_LEN]; /* array of TLS arrival times      */
  struct tls_type_code tls_type[MAX_NUM_RCD_LEN];  /* TLS record type codes    */
  unsigned short int num_ciphersuites;   /* number of SSLv3/TLS ciphersuites   */
  unsigned short int ciphersuites[MAX_CS];  /* array of ciphersuites           */
  unsigned short int num_tls_extensions;  /* number of TLS extensions          */
  unsigned short int num_server_tls_extensions;  /* number of TLS extensions          */
  struct tls_extension tls_extensions[MAX_EXTENSIONS];  /* array of extensions */
  struct tls_extension server_tls_extensions[MAX_EXTENSIONS];  /* array of extensions */
  unsigned char tls_v;                   /* TLS version                        */
  unsigned int tls_client_key_length;    /* client key exchange key length     */
  unsigned char tls_sid_len;             /* TLS session ID length              */
  unsigned char tls_sid[MAX_SID_LEN];    /* TLS session ID                     */
  unsigned char tls_random[32];          /* TLS random field from hello        */ 
  struct tls_certificate certificates[MAX_CERTIFICATES];
  unsigned char num_certificates;
  unsigned char start_cert;
  void *sni;
  unsigned short int sni_length;
  void *certificate_buffer;
  unsigned short certificate_offset;
};

/* structures for parsing TLS content */
struct TLSCiphertext {
  unsigned char ProtocolVersionMajor;
  unsigned char ProtocolVersionMinor;
  unsigned char lengthMid;
  unsigned char lengthLo;
} TLSCiphertext;

struct TLSHandshake {
  unsigned char HandshakeType;
  unsigned char lengthHi;
  unsigned char lengthMid;
  unsigned char lengthLo;
  unsigned char body;
};

struct tls_header {
  unsigned char ContentType; 
  unsigned char ProtocolVersionMajor;
  unsigned char ProtocolVersionMinor;
  unsigned char lengthMid;
  unsigned char lengthLo;
  union {
    struct TLSCiphertext Ciphertext;
    struct TLSHandshake Handshake; 
  };
};

struct Random {
  unsigned int gmt_unix_time;
  unsigned char random_bytes[28];
};

struct TLSClientHello {
  unsigned char ProtocolVersionMajor;
  unsigned char ProtocolVersionMinor;
  struct Random Random;
  unsigned char SessionIDLength;
  unsigned short NumCipherSuites;
};

/* useful enums */
enum tls_version {
  tls_unknown = 0,
  tls_sslv2 = 1,
  tls_sslv3 = 2,
  tls_tls1_0 = 3,
  tls_tls1_1 = 4,
  tls_tls1_2 = 5
};
  
enum HandshakeType {
  hello_request = 0, 
  client_hello = 1, 
  server_hello = 2,
  certificate = 11, 
  server_key_exchange  = 12,
  certificate_request = 13, 
  server_hello_done = 14,
  certificate_verify = 15, 
  client_key_exchange = 16,
  finished = 20
};

enum ContentType {
  change_cipher_spec = 20, 
  alert = 21, 
  handshake = 22,
  application_data = 23
};

/* useful typedef's */
typedef unsigned char CipherSuite[2];

/* TLS functions */
void tls_record_init(struct tls_information *r);
void tls_record_delete(struct tls_information *r);
unsigned short raw_to_unsigned_short(const void *x);
//void TLSClientKeyExchange_get_key_length(const void *x, int len, int version,
//					 struct tls_information *r);
void TLSClientHello_get_ciphersuites(const void *x, int len, 
				     struct tls_information *r);
void TLSClientHello_get_extensions(const void *x, int len, 
				   struct tls_information *r);
void TLSServerCertificate_parse(const void *x, unsigned int len,
				    struct tls_information *r);
void TLSServerHello_get_ciphersuite(const void *x, unsigned int len,
				    struct tls_information *r);
void TLSServerHello_get_extensions(const void *x, int len, 
				   struct tls_information *r);
void parse_san(const void *x, int len, struct tls_certificate *r);
unsigned int TLSHandshake_get_length(const struct TLSHandshake *H);
unsigned int tls_header_get_length(const struct tls_header *H);
char *tls_version_get_string(enum tls_version v);
unsigned char tls_version(const void *x);
unsigned int packet_is_sslv2_hello(const void *data);
struct tls_information *process_tls(const struct pcap_pkthdr *h, const void *start,
				int len, struct tls_information *r);
struct tls_information *process_certificate(const void *start,
				int len, struct tls_information *r);

void len_time_print_interleaved_tls(unsigned int op, const unsigned short *len, const struct timeval *time,
				    const struct tls_type_code *type, unsigned int op2,
				    const unsigned short *len2, const struct timeval *time2,
				    const struct tls_type_code *type2, zfile f);
void printf_raw_as_hex_tls(const void *data, unsigned int len);
void zprintf_raw_as_hex_tls(zfile f, const void *data, unsigned int len);
void print_bytes_dir_time_tls(unsigned short int pkt_len, char *dir, struct timeval ts, struct tls_type_code type, char *term, zfile f);
unsigned int timeval_to_milliseconds_tls(struct timeval ts);

void tls_printf(const struct tls_information *data, const struct tls_information *data_twin, zfile f);
void certificate_printf(const struct tls_certificate *data, zfile f);


#endif /* TLS_H */








