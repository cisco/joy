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

/**
 * \file tls.c
 *
 * \brief contains the functionality for TLS awareness
 * 
 */
#include <stdio.h>  
#include <pcap.h>  
#include <ctype.h>   
#include <string.h> 
#include <stdlib.h>

#ifdef WIN32
#include "Ws2tcpip.h"
#include <openssl/applink.c>
#else
#include <netinet/in.h>
#endif

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include "tls.h"
#include "parson.h"
#include "fingerprint.h"
#include "pkt.h"
#include "utils.h"
#include "err.h"

/*
 * The maxiumum allowed length of a serial number is 20 octets
 * according to RFC5290 section 4.1.2.2. We give some leeway
 * for any non-conforming certificates.
 */
#define MAX_CERT_SERIAL_LENGTH 24

/*
 * External objects, defined in joy.c
 */
extern unsigned int ipfix_collect_port;

/* Store the tls_fingerprint.json data */
static fingerprint_db_t tls_fingerprint_db;
static int tls_fingerprint_db_loaded = 0;

/* Local prototypes */
static int tls_certificate_process(const char *data, int data_len, struct tls_information *tls_info);
static int tls_header_version_capture(struct tls_information *tls_info, const struct tls_header *tls_hdr);
static void tls_certificate_printf(const struct tls_certificate *data, zfile f);

/**
 * \fn void tls_init (struct tls_information *r)
 *
 * \brief Initialize the memory of TLS struct.
 *
 * \param tls_handle contains tls structure to initialize
 *
 * \return
 */
void tls_init (struct tls_information **tls_handle) {
    if (*tls_handle != NULL) {
        tls_delete(tls_handle);
    }

    *tls_handle = malloc(sizeof(struct tls_information));
    if (*tls_handle == NULL) {
        /* Allocation failed */
        joy_log_err("malloc failed");
        return;
    }
    memset(*tls_handle, 0, sizeof(struct tls_information));
}

/**
 * \brief Delete the memory of TLS struct.
 *
 * \param tls_handle contains tls structure to delete
 *
 * \return
 */
void tls_delete (struct tls_information **tls_handle) {
    int i, j = 0;
    struct tls_information *r = *tls_handle;

    if (r == NULL) {
      return;
    }

    if (r->sni) {
        free(r->sni);
    }
    if (r->certificate_buffer) {
        free(r->certificate_buffer);
    }
    for (i=0; i<r->num_tls_extensions; i++) {
        if (r->tls_extensions[i].data) {
            free(r->tls_extensions[i].data);
        }
    }
    for (i=0; i<r->num_server_tls_extensions; i++) {
        if (r->server_tls_extensions[i].data) {
            free(r->server_tls_extensions[i].data);
        }
    }

    for (i = 0; i < r->num_certificates; i++) {
        struct tls_certificate *cert = &r->certificates[i];

        if (cert->signature) {
            /* Free the signature */
            free(cert->signature);
        }
        if (cert->serial_number) {
            /* Free the serial number */
            free(cert->serial_number);
        }
        for (j = 0; j < cert->num_issuer_items; j++) {
            /*
             * Iterate over all the issuer entries.
             */
            struct tls_item_entry *entry = &cert->issuer[j];

            if (entry->data) {
                /* Free the entry data */
	            free(entry->data);
            }
        }
        for (j = 0; j < cert->num_subject_items; j++) {
            /*
             * Iterate over all the subject entries.
             */
            struct tls_item_entry *entry = &cert->subject[j];

            if (entry->data) {
                /* Free the entry data */
	            free(entry->data);
            }
        }
        for (j = 0; j < cert->num_extension_items; j++) {
            /*
             * Iterate over all the subject entries.
             */
            struct tls_item_entry *entry = &cert->extensions[j];

            if (entry->data) {
                /* Free the entry data */
	            free(entry->data);
            }
        }
        if (cert->validity_not_before) {
            free(cert->validity_not_before);
        }
        if (cert->validity_not_after) {
            free(cert->validity_not_after);
        }
    }

    /* Free the memory and set to NULL */
    free(r);
    *tls_handle = NULL;
}

static unsigned short raw_to_unsigned_short (const void *x) {
    unsigned short int y;
    const unsigned char *z = x;

    y = z[0];
    y *= 256;
    y += z[1];
    return y;
}

/**
 * \fn void tls_header_get_length (const struct tls_header *hdr)
 *
 * \brief Calculate the message body length encoded in the TLS header.
 *
 * \param hdr TLS header structure pointer
 *
 * \return Length of the message body.
 */
static unsigned int tls_header_get_length (const struct tls_header *hdr) {
    return hdr->lengthLo + (((unsigned int) hdr->lengthMid) << 8);
}

/**
 * \fn void tls_handshake_get_length (const struct tls_handshake *hand)
 *
 * \brief Calculate the body length encoded in the TLS handshake header.
 *
 * \param hand TLS handshake structure pointer
 *
 * \return Length of the handshake body.
 */
static unsigned int tls_handshake_get_length (const struct tls_handshake *hand) {
    unsigned int len = 0;

    len = (unsigned int)hand->lengthLo;
    len += (unsigned int)hand->lengthMid << 8;
    len += (unsigned int)hand->lengthHi << 16;

    return len;
}

/**
 * \fn void tls_client_hello_get_ciphersuites (const void *x,
 *                                             unsigned int len,
 *                                             struct tls_information *r)
 *
 * \brief Extract the client offered ciphersuites.
 *
 * \param x Pointer to the hello message body data.
 * \param len Length of the data in bytes.
 * \param r tls_information structure that will be written into.
 *
 * \return
 *
 */
static void tls_client_hello_get_ciphersuites (const void *x,
                                               int len,
                                               struct tls_information *r) {
    unsigned int session_id_len;
    const unsigned char *y = x;
    unsigned short int cipher_suites_len;
    unsigned int i = 0;

    //  mem_print(x, len);
    //  fprintf(stderr, "TLS version %0x%0x\n", y[0], y[1]);

    /* Check the TLS version */
    if (!r->tls_v) {
        /* Unsupported version */
        return;
    }

    if (r->num_ciphersuites) {
        /* Already have the ciphersuites */
        return;
    }

    /* record the 32-byte Random field */
    memcpy(r->tls_random, y+2, 32); 

    y += 34;  /* skip over ProtocolVersion and Random */
    session_id_len = *y;

    len -= (session_id_len + 3);
    if (len < 0) {
        //fprintf(info, "error: TLS session ID too long\n"); 
        return;   /* error: session ID too long */
    }

    /* record the session id, if there is one */
    if (session_id_len) {
        r->tls_sid_len = session_id_len;
        memcpy(r->tls_sid, y+1, session_id_len); 
    }

    y += (session_id_len + 1);   /* skip over SessionID and SessionIDLen */
    // mem_print(y, 2);
    cipher_suites_len = raw_to_unsigned_short(y);
    if (len < cipher_suites_len) {
        //fprintf(info, "error: TLS ciphersuite list too long\n"); 
        return;   /* error: session ID too long */
    }
    y += 2;

    r->num_ciphersuites = cipher_suites_len/2;
    r->num_ciphersuites = r->num_ciphersuites > MAX_CS ? MAX_CS : r->num_ciphersuites;
    for (i=0; i < r->num_ciphersuites; i++) {
        unsigned short int cs;
    
        cs = raw_to_unsigned_short(y);
        r->ciphersuites[i] = cs;
        y += 2;
    }
}

/**
 * \fn void tls_client_hello_get_extensions (const void *x,
 *                                           unsigned int len,
 *                                           struct tls_information *r)
 *
 * \brief Extract the client hello extensions.
 *
 * \param x Pointer to the hello message body data.
 * \param len Length of the data in bytes.
 * \param r tls_information structure that will be written into.
 *
 * \return
 *
 */
static void tls_client_hello_get_extensions (const void *x,
                                             int len,
                                             struct tls_information *r) {
    unsigned int session_id_len, compression_method_len;
    const unsigned char *y = x;
    unsigned short int cipher_suites_len, extensions_len;
    unsigned int i = 0;

    /* Check the TLS version */
    if (!r->tls_v) {
        /* Unsupported version */
        return;
    }

    if (r->num_tls_extensions) {
        /* Already have the extensions */
        return;
    }

    y += 34;  /* skip over ProtocolVersion and Random */
    len -= 34;
    session_id_len = *y;

    len -= (session_id_len + 3);
    if (len < 0) {
        //fprintf(info, "error: TLS session ID too long\n"); 
        return;   /* error: session ID too long */
    }

    y += (session_id_len + 1);   /* skip over SessionID and SessionIDLen */
  
    cipher_suites_len = raw_to_unsigned_short(y);
    if (len < cipher_suites_len) {
        //fprintf(info, "error: TLS ciphersuite list too long\n"); 
        return;   /* error: session ID too long */
    }
    y += 2;
    len -= 2;

    // skip over ciphersuites
    y += cipher_suites_len;
    len -= cipher_suites_len;

    // skip over compression methods
    compression_method_len = *y;
    y += 1+compression_method_len;
    len -= 1+compression_method_len;

    // extensions length
    extensions_len = raw_to_unsigned_short(y);
    if (len < extensions_len) {
        //fprintf(info, "error: TLS extensions too long\n"); 
        return;   /* error: session ID too long */
    }
    y += 2;
    len -= 2;

    i = 0;
    while (len > 0) {
        if (raw_to_unsigned_short(y) == 0) {
            if (r->sni != NULL) {
                free(r->sni);
            }
            r->sni_length = raw_to_unsigned_short(y+7)+1;
            r->sni = malloc(r->sni_length);
            memset(r->sni, '\0', r->sni_length);
            memcpy(r->sni, y+9, r->sni_length-1);

	    r->tls_extensions[i].type = raw_to_unsigned_short(y);
	    r->tls_extensions[i].length = raw_to_unsigned_short(y+2);
	    r->tls_extensions[i].data = malloc(r->tls_extensions[i].length);
	    memcpy(r->tls_extensions[i].data, y+4, r->tls_extensions[i].length);  
	    r->num_tls_extensions += 1;
	    i += 1;

            len -= 4;
            len -= raw_to_unsigned_short(y+2);
            y += 4 + raw_to_unsigned_short(y+2);
      
            continue;
        }

        if (r->tls_extensions[i].data != NULL) {
            free(r->tls_extensions[i].data);
        }
        r->tls_extensions[i].type = raw_to_unsigned_short(y);
        r->tls_extensions[i].length = raw_to_unsigned_short(y+2);
        // should check if length is reasonable?
        r->tls_extensions[i].data = malloc(r->tls_extensions[i].length);
        memcpy(r->tls_extensions[i].data, y+4, r->tls_extensions[i].length);
  
        r->num_tls_extensions += 1;
        i += 1;
    
        len -= 4;
        len -= raw_to_unsigned_short(y+2);
        y += 4 + raw_to_unsigned_short(y+2);
    }
}

static void tls_handshake_get_client_key_exchange (const struct tls_handshake *h,
                                                   int len,
                                                   struct tls_information *r) {
    const unsigned char *y = &h->body;
    unsigned int byte_len = 0;

    if (r->tls_client_key_length == 0) {
        byte_len = tls_handshake_get_length(h);
        r->tls_client_key_length = byte_len * 8;

        if (r->tls_client_key_length >= 8193) { /* too large; data is possibly corrupted */
            r->tls_client_key_length = 0;
            return; 
        } else {
            memcpy(r->clientKeyExchange, y, byte_len); 
        }
    }
}

/**
 * \fn int tls_x509_get_validity_period(X509 *cert,
 *                                      struct tls_certificate *record)
 *
 * \brief Extract notBefore and notAfter out of a X509 certificate.
 *
 * \param cert OpenSSL X509 certificate structure.
 * \param record Destination tls_certificate structure
 *               that will be written into.
 *
 * \return 0 for success, 1 for failure
 */
static int tls_x509_get_validity_period(X509 *cert,
                                        struct tls_certificate *record) {
    BIO *time_bio = NULL;
    BUF_MEM *bio_mem_ptr = NULL;
    int not_before_data_len = 0;
    int not_after_data_len = 0;
    int rc_not_before = 1;
    int rc_not_after = 1;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ASN1_TIME *not_before = NULL;
    ASN1_TIME *not_after = NULL;

    not_before = X509_get_notBefore(cert);
    not_after = X509_get_notAfter(cert);
#else
    const ASN1_TIME *not_before = NULL;
    const ASN1_TIME *not_after = NULL;

    not_before = X509_get0_notBefore(cert);
    not_after = X509_get0_notAfter(cert);
#endif

    time_bio = BIO_new(BIO_s_mem());

    /*
     * Convert the time to into ISO-8601 string.
     */
    if (not_before != NULL) {
        ASN1_TIME_print(time_bio, not_before);

        /* Get length and pointer to memory inside of bio */
        BIO_get_mem_ptr(time_bio, &bio_mem_ptr);
        not_before_data_len = (int) bio_mem_ptr->length;

        if (not_before_data_len > 0) {
            /* Prepare the record */
            record->validity_not_before = malloc(not_before_data_len + 1);
            record->validity_not_before_length = not_before_data_len;

            /* Copy notBefore into record */
            memcpy(record->validity_not_before, bio_mem_ptr->data,
                   not_before_data_len);

            joy_utils_convert_to_json_string((char*)record->validity_not_before,
                                             not_before_data_len + 1);

            /* Clear the bio */
            (void) BIO_reset(time_bio);

            /* Success */
            rc_not_before = 0;
        } else {
            joy_log_warn("no data exists for notBefore");
        }
    } else {
        joy_log_err("could not extract notBefore");
    }

    if (not_after != NULL) {
        ASN1_TIME_print(time_bio, not_after);

        /* Get length and pointer to memory inside of bio */
        BIO_get_mem_ptr(time_bio, &bio_mem_ptr);
        not_after_data_len = (int) bio_mem_ptr->length;

        if (not_after_data_len > 0) {
            /* Prepare the record */
            record->validity_not_after = malloc(not_after_data_len + 1);
            record->validity_not_after_length = not_after_data_len;
            /* Copy notAfter into record */
            memcpy(record->validity_not_after, bio_mem_ptr->data,
                   not_after_data_len);

            joy_utils_convert_to_json_string((char*)record->validity_not_after,
                                             not_after_data_len + 1);

            /* Success */
            rc_not_after = 0;
        } else {
            joy_log_warn("no data exists for notAfter");
        }
    } else {
        joy_log_err("could not extract notAfter");
    }

    if (time_bio) {
        BIO_free(time_bio);
    }

    if (rc_not_before || rc_not_after) {
        return 1;
    } else {
        return 0;
    }
}

/**
 * \fn int tls_x509_get_subject(X509 *cert,
 *                              struct tls_certificate *record)
 *
 * \brief Extract the subject data out of a X509 certificate.
 *
 * \param cert OpenSSL X509 certificate structure.
 * \param record Destination tls_certificate structure
 *               that will be written into.
 *
 * \return 0 for success, 1 for failure
 */
static int tls_x509_get_subject(X509 *cert,
                                struct tls_certificate *record) {
    X509_NAME *subject = NULL;
    X509_NAME_ENTRY *entry = NULL;
    ASN1_OBJECT *entry_asn1_object = NULL;
    int entry_data_len = 0;
    int nid = 0;
    int num_of_entries = 0;
    int i = 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ASN1_STRING *entry_asn1_string = NULL;
    unsigned char *entry_data_str = NULL;
#else
    const ASN1_STRING *entry_asn1_string = NULL;
    const unsigned char *entry_data_str = NULL;
#endif

    subject = X509_get_subject_name(cert);
    if (subject == NULL) {
        joy_log_err("could not extract subject");
        return 1;
    }
    num_of_entries = X509_NAME_entry_count(subject);

    /* Place the count in record */
    if (num_of_entries > MAX_RDN) {
        /* Best effort */
        record->num_subject_items = MAX_RDN;
    } else {
        record->num_subject_items = num_of_entries;
    }

    for (i = 0; i < num_of_entries; i++) {
        const char *entry_name_str = NULL;
        struct tls_item_entry *cert_record_entry = &record->subject[i];

        if (i == MAX_RDN) {
            /* Best effort, got as many as we could */
            joy_log_warn("hit max entry threshold of %d", MAX_RDN);
            break;
        }

        /* Current subject entry */
        entry = X509_NAME_get_entry(subject, i);
        entry_asn1_object = X509_NAME_ENTRY_get_object(entry);
        entry_asn1_string = X509_NAME_ENTRY_get_data(entry);

        /* Get the info out of asn1_string */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        entry_data_str = ASN1_STRING_data(entry_asn1_string);
#else
        entry_data_str = ASN1_STRING_get0_data(entry_asn1_string);
#endif

        entry_data_len = ASN1_STRING_length(entry_asn1_string);

        /* NID of the asn1_object */
        nid = OBJ_obj2nid(entry_asn1_object);

        /*
         * Prepare the subject entry in the certificate record.
         * Give extra byte for manual null-termination.
         */
        cert_record_entry->data = malloc(entry_data_len + 1);
        cert_record_entry->data_length = entry_data_len;

        if (nid == NID_undef) {
            /*
             * The NID is unknown, so instead we will copy the OID.
             * The OID can be looked-up online to find the name.
             */
            OBJ_obj2txt(cert_record_entry->id, MAX_OPENSSL_STRING,
                        entry_asn1_object, 1);
            /* Make sure it's null-terminated */
            cert_record_entry->id[MAX_OPENSSL_STRING - 1] = '\0';
        } else {
            /*
             * Use the NID to get the name as defined in OpenSSL.
             */
            entry_name_str = OBJ_nid2ln(nid);
            strncpy(cert_record_entry->id, entry_name_str,
                    MAX_OPENSSL_STRING);
            /* Make sure it's null-terminated */
            cert_record_entry->id[MAX_OPENSSL_STRING - 1] = '\0';
        }

        memcpy(cert_record_entry->data, entry_data_str, entry_data_len);
        /* Find any special (json) characters and replace them */
        joy_utils_convert_to_json_string((char*)cert_record_entry->data,
                                         entry_data_len + 1);
    }

    return 0;
}

/**
 * \fn int tls_x509_get_issuer(X509 *cert,
 *                             struct tls_certificate *record)
 *
 * \brief Extract the issuer data out of a X509 certificate.
 *
 * \param cert OpenSSL X509 certificate structure.
 * \param record Destination tls_certificate structure
 *               that will be written into.
 *
 * \return 0 for success, 1 for failure
 */
static int tls_x509_get_issuer(X509 *cert,
                               struct tls_certificate *record) {
    X509_NAME *issuer = NULL;
    X509_NAME_ENTRY *entry = NULL;
    ASN1_OBJECT *entry_asn1_object = NULL;
    int entry_data_len = 0;
    int nid = 0;
    int num_of_entries = 0;
    int i = 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ASN1_STRING *entry_asn1_string = NULL;
    unsigned char *entry_data_str = NULL;
#else
    const ASN1_STRING *entry_asn1_string = NULL;
    const unsigned char *entry_data_str = NULL;
#endif

    issuer = X509_get_issuer_name(cert);
    if (issuer == NULL) {
        joy_log_err("could not extract issuer");
        return 1;
    }
    num_of_entries = X509_NAME_entry_count(issuer);

    /* Place the count in record */
    if (num_of_entries > MAX_RDN) {
        /* Best effort */
        record->num_issuer_items = MAX_RDN;
    } else {
        record->num_issuer_items = num_of_entries;
    }

    /*
     * Iterate over all of the entries.
     */
    for (i = 0; i < num_of_entries; i++) {
        const char *entry_name_str = NULL;
        struct tls_item_entry *cert_record_entry = &record->issuer[i];

        if (i == MAX_RDN) {
            /* Best effort, got as many as we could */
            joy_log_warn("hit max entry threshold of %d", MAX_RDN);
            break;
        }

        /* Current issuer entry */
        entry = X509_NAME_get_entry(issuer, i);
        entry_asn1_object = X509_NAME_ENTRY_get_object(entry);
        entry_asn1_string = X509_NAME_ENTRY_get_data(entry);

        /* Get the info out of asn1_string */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        entry_data_str = ASN1_STRING_data(entry_asn1_string);
#else
        entry_data_str = ASN1_STRING_get0_data(entry_asn1_string);
#endif

        entry_data_len = ASN1_STRING_length(entry_asn1_string);

        /* NID of the asn1_object */
        nid = OBJ_obj2nid(entry_asn1_object);

        /*
         * Prepare the issuer entry in the certificate record.
         * Give extra byte for manual null-termination.
         */
        cert_record_entry->data = malloc(entry_data_len + 1);
        cert_record_entry->data_length = entry_data_len;

        if (nid == NID_undef) {
            /*
             * The NID is unknown, so instead we will copy the OID.
             * The OID can be looked-up online to find the name.
             */
            OBJ_obj2txt(cert_record_entry->id, MAX_OPENSSL_STRING,
                        entry_asn1_object, 1);
            /* Make sure it's null-terminated */
            cert_record_entry->id[MAX_OPENSSL_STRING - 1] = '\0';
        } else {
            /*
             * Use the NID to get the name as defined in OpenSSL.
             */
            entry_name_str = OBJ_nid2ln(nid);
            strncpy(cert_record_entry->id, entry_name_str,
                    MAX_OPENSSL_STRING);
            /* Make sure it's null-terminated */
            cert_record_entry->id[MAX_OPENSSL_STRING - 1] = '\0';
        }

        memcpy(cert_record_entry->data, entry_data_str, entry_data_len);
        /* Find any special (json) characters and replace them */
        joy_utils_convert_to_json_string((char*)cert_record_entry->data,
                                         entry_data_len + 1);
    }

    return 0;
}

/**
 * \fn int tls_x509_get_serial(X509 *cert,
 *                             struct tls_certificate *record)
 *
 * \brief Extract the serial number out of a X509 certificate.
 *
 * \param cert OpenSSL X509 certificate structure.
 * \param record Destination tls_certificate structure
 *               that will be written into.
 *
 * \return 0 for success, 1 for failure
 */
static int tls_x509_get_serial(X509 *cert,
                               struct tls_certificate *record) {
    uint16_t serial_data_length = 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ASN1_INTEGER *serial = NULL;
    unsigned char *serial_data = NULL;
#else
    const ASN1_INTEGER *serial = NULL;
    const unsigned char *serial_data = NULL;
#endif

    serial = X509_get_serialNumber(cert);
    if (serial == NULL) {
        joy_log_err("could not extract serial");
        return 1;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    serial_data = ASN1_STRING_data(serial);
#else
    serial_data = ASN1_STRING_get0_data(serial);
#endif

    serial_data_length = ASN1_STRING_length(serial);

    if (serial_data_length > MAX_CERT_SERIAL_LENGTH) {
        /* This serial number is abnormally large */
        joy_log_warn("serial number is too large");
        return 1;
    }

    if (serial_data) {
        record->serial_number = malloc(serial_data_length);
        memcpy(record->serial_number, serial_data, serial_data_length);
        record->serial_number_length = (uint8_t)serial_data_length;
    }

    return 0;
}

/**
 * \fn int tls_x509_get_subject_pubkey_algorithm(X509 *cert,
 *                                               struct tls_certificate *record)
 *
 * \brief Extract the subject public key algorithm type out of a X509 certificate.
 *
 * \param cert OpenSSL X509 certificate structure.
 * \param record Destination tls_certificate structure
 *               that will be written into.
 *
 * \return 0 for success, 1 for failure
 */
static int tls_x509_get_subject_pubkey_algorithm(X509 *cert,
                                                 struct tls_certificate *record) {
    EVP_PKEY *evp_pubkey = NULL;
    const char *alg_str = NULL;
    int key_type = 0;

    /*
     * Get the X509 public key.
     */
    evp_pubkey = X509_get_pubkey(cert);
    if (evp_pubkey == NULL) {
        joy_log_err("could not extract public key");
        return 1;
    }

    /* Get the key type */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    key_type = EVP_PKEY_type(evp_pubkey->type);
#else
    key_type = EVP_PKEY_base_id(evp_pubkey);
#endif

    /*
     * Get the key size
     */
    record->subject_public_key_size = EVP_PKEY_bits(evp_pubkey);

    /* 
     * Get the algorithm type string
     */
    alg_str = OBJ_nid2ln(key_type);
    strncpy(record->subject_public_key_algorithm, alg_str, MAX_OPENSSL_STRING);
    /* Ensure null-termination */
    record->subject_public_key_algorithm[MAX_OPENSSL_STRING - 1] = '\0';

    if (evp_pubkey) {
        EVP_PKEY_free(evp_pubkey);
    }

    return 0;
}

/**
 * \fn int tls_x509_get_signature(X509 *cert,
 *                                struct tls_certificate *record)
 *
 * \brief Extract the signature data out of a X509 certificate.
 *
 * \param cert OpenSSL X509 certificate structure.
 * \param record Destination tls_certificate structure
 *               that will be written into.
 *
 * \return 0 for success, 1 for failure
 */
static int tls_x509_get_signature(X509 *cert,
                                  struct tls_certificate *record) {
    int sig_length = 0;
    const char *alg_str = NULL;
    int nid = 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ASN1_BIT_STRING *sig = NULL;
    unsigned char *sig_str = NULL;
    X509_ALGOR *alg = NULL;
    ASN1_OBJECT *alg_asn1_obj = NULL;
#else
    const ASN1_BIT_STRING *sig = NULL;
    const unsigned char *sig_str = NULL;
    const X509_ALGOR *alg = NULL;
    const ASN1_OBJECT *alg_asn1_obj = NULL;
#endif


#if OPENSSL_VERSION_NUMBER < 0x10100000L
    sig = cert->signature;
    alg = cert->sig_alg;
#else
    X509_get0_signature(&sig, &alg, cert);
#endif

    if (sig == NULL) {
        joy_log_err("problem getting signature");
        return 1;
    }

    if (alg == NULL) {
        joy_log_err("problem getting signature algorithm");
        return 1;
    }

    /*
     * Get the signature
     */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    sig_str = ASN1_STRING_data(sig);
#else
    sig_str = ASN1_STRING_get0_data(sig);
#endif

    sig_length = ASN1_STRING_length(sig);

    if (sig_length > 512) {
        /*
         * We shouldn't be seeing any signatures larger than this.
         * Using 4096 bits (512 bytes) as the standard for upper threshold.
         */
        joy_log_warn("signature is too large");
        return 1;
    } else {
        /* Multiply by 8 to get the number of bits */
        record->signature_key_size = sig_length << 3;
    }

    record->signature = malloc(sig_length);
    memcpy(record->signature, sig_str, sig_length);
    record->signature_length = sig_length;

    /*
     * Get the signature algorithm
     */
    X509_ALGOR_get0(&alg_asn1_obj, NULL, NULL, alg);
    if (alg_asn1_obj == NULL) {
        joy_log_err("problem getting signature algorithm asn1 obj");
        return 1;
    }

    /* Get the NID of the asn1_object */
    nid = OBJ_obj2nid(alg_asn1_obj);

    if (nid == NID_undef) {
        /*
         * The NID is unknown, so instead we will copy the OID.
         * The OID can be looked-up online to find the name.
         */
        OBJ_obj2txt(record->signature_algorithm,
                    MAX_OPENSSL_STRING, alg_asn1_obj, 1);
        /* Ensure null-termination */
        record->signature_algorithm[MAX_OPENSSL_STRING - 1] = '\0';
    } else {
        alg_str = OBJ_nid2ln(nid);
        strncpy(record->signature_algorithm, alg_str,
                MAX_OPENSSL_STRING);
        /* Ensure null-termination */
        record->signature_algorithm[MAX_OPENSSL_STRING - 1] = '\0';
    }

    strncpy(record->signature_algorithm, alg_str, MAX_OPENSSL_STRING);
    /* Ensure null-termination */
    record->signature_algorithm[MAX_OPENSSL_STRING - 1] = '\0';

    return 0;
}

/**
 * \fn int tls_x509_get_extensions(X509 *cert,
 *                                 struct tls_certificate *record)
 *
 * \brief Extract all extensions type/data out of a X509 certificate.
 *
 * \param cert OpenSSL X509 certificate structure.
 * \param record Destination tls_certificate structure
 *               that will be written into.
 *
 * \return 0 for success, 1 for failure
 */
static int tls_x509_get_extensions(X509 *cert,
                                   struct tls_certificate *record) {
    X509_EXTENSION *extension = NULL;
    ASN1_OBJECT *ext_asn1_object = NULL;
    int nid = 0;
    int num_exts = 0;
    int i = 0;

    num_exts = X509_get_ext_count(cert);

    /* Place the count in record */
    if (num_exts > MAX_CERT_EXTENSIONS) {
        /* Best effort */
        record->num_extension_items = MAX_CERT_EXTENSIONS;
    } else {
        record->num_extension_items = num_exts;
    }

    /*
     * Iterate over all of the extensions.
     */
    for (i= 0; i < num_exts; i++) {
        BIO *ext_bio = NULL;
        BUF_MEM *bio_mem_ptr = NULL;
        int ext_data_len = 0;
        const char *ext_name_str = NULL;
        struct tls_item_entry *cert_record_entry = &record->extensions[i];

        if (i == MAX_CERT_EXTENSIONS) {
            /* Best effort, got as many as we could */
            joy_log_warn("hit max extension threshold of %d",
                         MAX_CERT_EXTENSIONS);
            break;
        }

        /* Current extension */
        extension = X509_get_ext(cert, i);
        ext_asn1_object = X509_EXTENSION_get_object(extension);

        /* NID of the asn1_object */
        nid = OBJ_obj2nid(ext_asn1_object);

        /*
         * Convert the extension value into readable string format.
         */
        ext_bio = BIO_new(BIO_s_mem());

        if (!X509V3_EXT_print(ext_bio, extension, 0, 0)) {
            ASN1_STRING_print(ext_bio, X509_EXTENSION_get_data(extension));
        }

        /* Get length and pointer to memory inside of bio */
        BIO_get_mem_ptr(ext_bio, &bio_mem_ptr);
        ext_data_len = (int) bio_mem_ptr->length;

        /*
         * Prepare the extension entry in the certificate record.
         */
        cert_record_entry->data = malloc(ext_data_len + 1);
        memset(cert_record_entry->data, 0, ext_data_len + 1);
        cert_record_entry->data_length = ext_data_len;

        if (nid == NID_undef) {
            /*
             * The NID is unknown, so instead we will copy the OID.
             * The OID can be looked-up online to find the name.
             */
            OBJ_obj2txt(cert_record_entry->id, MAX_OPENSSL_STRING,
                        ext_asn1_object, 1);
            /* Make sure it's null-terminated */
            cert_record_entry->id[MAX_OPENSSL_STRING - 1] = '\0';
        } else {
            /*
             * Use the NID to get the name as defined in OpenSSL.
             */
            ext_name_str = OBJ_nid2ln(nid);
            strncpy(cert_record_entry->id, ext_name_str,
                    MAX_OPENSSL_STRING);
            /* Make sure it's null-terminated */
            cert_record_entry->id[MAX_OPENSSL_STRING - 1] = '\0';
        }

        memcpy(cert_record_entry->data, bio_mem_ptr->data, ext_data_len);
        /* Find any special (json) characters and replace them */
        joy_utils_convert_to_json_string((char*)cert_record_entry->data,
                                         ext_data_len + 1);

        if (ext_bio) {
            BIO_free(ext_bio);
        }
    }

    return 0;
}

/**
 * \fn void tls_server_certificate_parse (const unsigned char *data,
 *                                        unsigned int data_len,
 *                                        struct tls_information *r)
 *
 * \brief Parse a server certificate chain.
 *
 * \param data Pointer to the certificate message payload data.
 * \param data_len Length of the data in bytes.
 * \param r tls_information structure that will be written into.
 *
 * \return
 *
 */
static void tls_server_certificate_parse (const unsigned char *data,
                                          unsigned int data_len,
                                          struct tls_information *r) {

    unsigned short total_certs_len = 0, remaining_certs_len,
                   cert_len, index_cert = 0;
    int rc = 0;

    /* Move past the all_certs_len */
    total_certs_len = raw_to_unsigned_short(data + 1);
    data += 3;

    joy_log_debug("all certificates length: %d", total_certs_len);

    if (total_certs_len > data_len) {
        /*
         * The length of all the certificates is supposedly
         * longer than the entire handshake message.
         * This should not be possible.
         */
        return;
    }

    remaining_certs_len = total_certs_len;

    while (0 < remaining_certs_len && remaining_certs_len <= total_certs_len) {
        struct tls_certificate *certificate = NULL;
        const unsigned char *ptr_openssl = NULL;
        X509 *x509_cert = NULL;

        if (r->num_certificates >= MAX_CERTIFICATES) {
            /*
             * The TLS record cannot hold anymore certificates.
             */
            return;
        }

        /* Current certificate length */
        cert_len = raw_to_unsigned_short(data + 1);

        if (cert_len == 0 || cert_len > remaining_certs_len) {
            /*
             * The certificate length is zero or claims to be
             * larger than the total set. Both cases are invalid.
             */
            return;
        }

        /* The index to retrieve the proper certificate record */
        index_cert = r->num_certificates;
        r->num_certificates += 1;

        /* Point to the current certificate record */
        certificate = &r->certificates[index_cert];
        certificate->length = cert_len;

        /* Move past the cert_len */
        data += 3;
        remaining_certs_len -= 3;

        joy_log_debug("current certificate length: %d", cert_len);

        ptr_openssl = data;
        /* Convert to OpenSSL X509 object */
        x509_cert = d2i_X509(NULL, &ptr_openssl, (size_t)cert_len);

        if (x509_cert == NULL) {
            joy_log_warn("Failed cert conversion");
        } else {
            /* Get subject */
            tls_x509_get_subject(x509_cert, certificate);

            /* Get issuer */
            tls_x509_get_issuer(x509_cert, certificate);

            /* Get the validity notBefore and notAfter */
            tls_x509_get_validity_period(x509_cert, certificate);

            /* Get serial */
            tls_x509_get_serial(x509_cert, certificate);

            /* Get extensions */
            tls_x509_get_extensions(x509_cert, certificate);

            /* Get signature and signature algorithm*/
            tls_x509_get_signature(x509_cert, certificate);

            /* Get public-key info */
            tls_x509_get_subject_pubkey_algorithm(x509_cert, certificate);
        }

        /*
         * Skip to the next certificate
         */
        data += cert_len;
        remaining_certs_len -= cert_len;

        /*
         * Cleanup
         */
        if (x509_cert) {
            X509_free(x509_cert);
            CRYPTO_cleanup_all_ex_data();
        }

        if (rc) {
            return;
        }
    }
}

/**
 * \fn void tls_server_hello_get_ciphersuite (const void *x,
 *                                            unsigned int len,
 *                                            struct tls_information *r)
 *
 * \brief Extract the server selected ciphersuite (scs).
 *
 * \param x Pointer to the hello message body data.
 * \param len Length of the data in bytes.
 * \param r tls_information structure that will be written into.
 *
 * \return
 *
 */
static void tls_server_hello_get_ciphersuite (const void *x,
                                              unsigned int len,
                                              struct tls_information *r) {
    unsigned int session_id_len;
    const unsigned char *y = x;
    unsigned short int cs; 
    unsigned char flag_tls13 = 0;

    /* Check the TLS version */
    if (!r->tls_v) {
        /* Unsupported version */
        return;
    }

    if (r->num_ciphersuites) {
        /* Already have the ciphersuite */
        return;
    }

    if (r->tls_v == TLS_VERSION_1_3) {
        /* Flag that this is TLS 1.3 */
        flag_tls13 = 1;
    }

    /* Record the 32-byte Random field */
    memcpy(r->tls_random, y+2, 32); 

    /* Skip over ProtocolVersion and Random */
    y += 34;

    /* If TLS 1.3, jump over this part */
    if (!flag_tls13) {
        session_id_len = *y;
        if (session_id_len + 3 > len) {
            //fprintf(info, "error: TLS session ID too long\n"); 
            return;   /* error: session ID too long */
        }

        /* record the session id, if there is one */
        if (session_id_len) {
            r->tls_sid_len = session_id_len;
            memcpy(r->tls_sid, y+1, session_id_len); 
        }

        /* Skip over SessionID and SessionIDLen */
        y += (session_id_len + 1);
    }

    /* Record the single selected cipher suite */
    cs = raw_to_unsigned_short(y);

    r->num_ciphersuites = 1;
    r->ciphersuites[0] = cs;
}

/**
 * \fn void tls_server_hello_get_extensions (const void *x,
 *                                           unsigned int len,
 *                                           struct tls_information *r)
 *
 * \brief Extract the server hello extensions.
 *
 * \param x Pointer to the hello message body data.
 * \param len Length of the data in bytes.
 * \param r tls_information structure that will be written into.
 *
 * \return
 *
 */
static void tls_server_hello_get_extensions (const void *x, int len,
    struct tls_information *r) {
    unsigned int session_id_len, compression_method_len;
    const unsigned char *y = x;
    unsigned short int extensions_len;
    unsigned int i = 0;
    unsigned char flag_tls13 = 0;

    /* Check the TLS version */
    if (!r->tls_v) {
        /* Unsupported version */
        return;
    }

    if (r->num_server_tls_extensions) {
        /* Already have the extensions */
        return;
    }

    if (r->tls_v == TLS_VERSION_1_3) {
        /* Flag that this is TLS 1.3 */
        flag_tls13 = 1;
    }

    /* Skip over ProtocolVersion and Random */
    y += 34;
    len -= 34;

    /* If TLS 1.3, jump over this part */
    if (!flag_tls13) {
        /* Skip over SessionID and SessionIDLen */
        session_id_len = *y;
        len -= (session_id_len + 1);
        y += (session_id_len + 1);   
    }

    /* Skip over scs (cipher_suite) */
    len -= 2; 
    y += 2;

    /* If TLS 1.3, jump over this part */
    if (!flag_tls13) {
        /* Skip over compression methods */
        compression_method_len = *y;
        y += 1+compression_method_len;
        len -= 1+compression_method_len;
    }

    /* Extensions length */
    extensions_len = raw_to_unsigned_short(y);
    if (len < extensions_len) {
        //fprintf(info, "error: TLS extensions too long\n"); 
        return;   /* error: session ID too long */
    }
    y += 2;
    len -= 2;

    i = 0;
    while (len > 0) {
        if (raw_to_unsigned_short(y+2) > 256) {
            break;
        }
        r->server_tls_extensions[i].type = raw_to_unsigned_short(y);
        r->server_tls_extensions[i].length = raw_to_unsigned_short(y+2);
        // should check if length is reasonable?
        r->server_tls_extensions[i].data = malloc(r->server_tls_extensions[i].length);
        memcpy(r->server_tls_extensions[i].data, y+4, r->server_tls_extensions[i].length);

        r->num_server_tls_extensions += 1;
        i += 1;

        len -= 4;
        len -= raw_to_unsigned_short(y+2);
        y += 4 + raw_to_unsigned_short(y+2);
    }
}

/*
 * @brief Load the tls_fingerprint.json data into the running process.
 *
 * Load the tls_fingerprint.json file into this processes memory,
 * which contains a known dataset that is used for TLS connection
 * fingerprinting.
 *
 * return 0 for success, 1 for failure
 */
int tls_load_fingerprints(void) {
    JSON_Value *root_value = NULL;
    JSON_Object *root_obj = NULL;
    JSON_Object *data_obj = NULL;
    JSON_Array *tls_libraries = NULL;
    JSON_Object *library_obj = NULL;
    JSON_Value *library_name = NULL;
    JSON_Array *cipher_suites = NULL;
    JSON_Array *extensions = NULL;
    const char *lib_name_str = NULL;
    const char *cipher_suite_str = NULL;
    const char *extension_str = NULL;
    size_t i = 0;
    int rc = 1;

    /* Parse the Json file and validate */
    root_value = joy_utils_open_resource_parson("tls_fingerprint.json");
    if (json_value_get_type(root_value) != JSONObject) {
        fprintf(stderr, "error: expected JSON object\n");
        goto cleanup;
    }

    /* Get the root object */
    root_obj = json_value_get_object(root_value);

    /* Get the data object */
    data_obj = json_object_get_object(root_obj, "data");

    /* Get the tls libraries list */
    tls_libraries = json_object_get_array(data_obj, "tls_libraries");

    /*
     * Iterate through each individual library
     */
    for (i = 0; i < json_array_get_count(tls_libraries); i++) {
        fingerprint_t fp_local;
        fingerprint_t *fp_match = NULL;
        unsigned short int cs_val = 0;
        unsigned short int ext_val = 0;
        size_t cs_count = 0;
        size_t ext_count = 0;
        size_t k = 0;

        library_obj = json_array_get_object(tls_libraries, i);
        library_name = json_object_get_value(library_obj, "library_name");
        cipher_suites = json_object_get_array(library_obj, "cipher_suites");
        extensions = json_object_get_array(library_obj, "extensions");

        /* Get the library version name */
        lib_name_str = json_value_get_string(library_name);

        /* Get the number of cipher suites and extensions */
        cs_count = json_array_get_count(cipher_suites);
        ext_count = json_array_get_count(extensions);

        if (cs_count + ext_count > MAX_FINGERPRINT_LEN / sizeof(unsigned short int)) {
            fprintf(stderr, "error: cs+ext larger than allowed fingerprint size\n");
            goto cleanup;
        }

        /* Prepare the local fingerprint for use */
        memset(&fp_local, 0, sizeof(fingerprint_t));

        /* Fill the local fingerprint buffer */
        for (k = 0; k < cs_count; k++) {
            cipher_suite_str = json_value_get_string(json_array_get_value(cipher_suites, k));
            /* Convert the current hex string to a 2-byte value */
            sscanf(cipher_suite_str, "%hx", &cs_val);
            /* Copy into the functions local fingerprint */
            fp_local.fingerprint[fp_local.fingerprint_len] = cs_val;
            fp_local.fingerprint_len += sizeof(unsigned short int);
        }
        for (k = 0; k < ext_count; k++) {
            extension_str = json_value_get_string(json_array_get_value(extensions, k));
            /* Convert the current hex string to a 2-byte value */
            sscanf(extension_str, "%hx", &ext_val);
            /* Copy into the functions local fingerprint */
            fp_local.fingerprint[fp_local.fingerprint_len] = ext_val;
            fp_local.fingerprint_len += sizeof(unsigned short int);
        }

        /*
         * Check if the fingerprint already exists in the database.
         */
        fp_match = fingerprint_db_match_exact(&tls_fingerprint_db, &fp_local); 

        if (fp_match != NULL) {
            /*
             * Found an existing fingerprint entry.
             */
            uint16_t label_count = fp_match->label_count;

            if (label_count == (MAX_FINGERPRINT_LABELS - 1)) {
                fprintf(stderr, "warning: tls_fingerprint_t is at max label capacity");
            } else {
                strncpy(fp_match->labels[label_count], lib_name_str,
                        MAX_FINGERPRINT_LABEL_LEN);
                fp_match->labels[label_count][MAX_FINGERPRINT_LABEL_LEN - 1] = '\0';
                fp_match->label_count += 1;
            }
        } else {
            /*
             * This is a new fingerprint database entry.
             */
            uint16_t db_count = tls_fingerprint_db.fingerprint_count;
            if (db_count < MAX_FINGERPRINT_DB) {
                /* Copy the library name label into local fingerprint */
                strncpy(fp_local.labels[0], lib_name_str,
                        MAX_FINGERPRINT_LABEL_LEN);
                fp_local.labels[0][MAX_FINGERPRINT_LABEL_LEN - 1] = '\0';
                fp_local.label_count += 1;

                /* Copy local fingerprint to the database */
                fingerprint_copy(&tls_fingerprint_db.fingerprints[db_count],
                                 &fp_local);

                /* Increment database count */
                tls_fingerprint_db.fingerprint_count += 1;
            } else {
                fprintf(stderr, "warning: tls_fingerprint_store is at max capacity");
            }
        }
    }

    tls_fingerprint_db_loaded = 1;
    rc = 0;

cleanup:
    /* Free the internal json memory */
    if (root_value) {
        json_value_free(root_value);
    }

    return rc;
}

/*
 * @brief Find a client TLS fingerprint match.
 *
 * Use data from the current flow's \p tls_info to search
 * the known tls fingerprint database for any matches.
 * If any matches are found, a pointer to the entry in the database
 * is set in \p tls_info for later retrieval. The \p percent
 * represents the users required percent of confidence in
 * order for a match to occur, 0 to 100. 100 means an exact match
 * (100% of fingerprint must be matched). 70 means a partial
 * match (70% of fingerprint must be matched).
 *
 * @param tls_info The client TLS information
 * @param percent The callers required percent of fingerprint match.
 *
 * return 0 for success, 1 for error
 */
static int tls_client_fingerprint_match(struct tls_information *tls_info,
                                        unsigned int percent) {
    fingerprint_t fp;
    fingerprint_t *db_fingerprint = NULL;
    unsigned short cs_count = 0;
    unsigned short ext_count = 0;
    int i, k = 0;

    if (!tls_fingerprint_db_loaded) {
        /* The fingerprint database is empty, bail out */
        return 1;
    }

    /* Get the number of ciphersuites and extensions */
    cs_count = tls_info->num_ciphersuites;
    ext_count = tls_info->num_tls_extensions;

    /* Zero the temporary fp */
    memset(&fp, 0, sizeof(fingerprint_t));

    fp.fingerprint_len = (cs_count + ext_count) * sizeof(unsigned short);

    if (fp.fingerprint_len > MAX_FINGERPRINT_LEN) {
        joy_log_err("fingerprint too large, aborting");
        return 1;
    }

    /*
     * Copy data into temporary fingerprint.
     */
    if (cs_count) {
        k = 0;
        for (i = 0; i < cs_count; i++) {
            /*
             * Kinda weird because we're copying 2 bytes
             * at a time into a raw byte buffer
             */
            memcpy(&fp.fingerprint[k],
                   (unsigned char *)&tls_info->ciphersuites[i],
                   sizeof(unsigned short));

            k += sizeof(unsigned short);
        }
    }
    if (ext_count) {
        /* Start just beyond the cs data */
        int start_pos = cs_count * 2;
        k = 0;
        for (i = 0; i < ext_count; i ++) {
            /*
             * Kinda weird because we're copying 2 bytes
             * at a time into a raw byte buffer
             */
            memcpy(&fp.fingerprint[k + start_pos],
                   (unsigned char *)&tls_info->tls_extensions[i].type,
                   sizeof(unsigned short));

            k += sizeof(unsigned short);
        }
    }

    if (percent == 100) {
        /* Find an exact database fingerprint match */
        db_fingerprint = fingerprint_db_match_exact(&tls_fingerprint_db, &fp);
    } else {
        joy_log_err("partial matching not supported yet");
        return 1;
    }

    if (db_fingerprint != NULL) {
        /* Point to database entry in client tls info */
        tls_info->tls_fingerprint = db_fingerprint;
    }

    return 0;
}

static int tls_version_to_internal(unsigned char major,
                                   unsigned char minor) {
    int internal_version = 0;

    if ((major != 3) || (minor > 4)) {
        /*
         * Currently only capture SSLV3, TLS1.0, 1.1, 1.2, 1.3
         * Allow the dev version of TlS 1.3
         */
        if (major != 0x7F || minor != 0x12) {
            return 0;
        }
    }

    switch(major) {
        case 3:
            switch(minor) {
                case 0:
                    internal_version = TLS_VERSION_SSLV3;
                    break;
                case 1:
                    internal_version = TLS_VERSION_1_0;
                    break;
                case 2:
                    internal_version = TLS_VERSION_1_1;
                    break;
                case 3:
                    internal_version = TLS_VERSION_1_2;
                    break;
                case 4:
                    internal_version = TLS_VERSION_1_3;
                    break;
            }
            break;
        case 2:
            internal_version = TLS_VERSION_SSLV2;
            break;
        case 0x7F:
            switch(minor) {
                case 0x12:
                    internal_version = TLS_VERSION_1_3;
                    break;
            }
        default:
            ;
    }

    return internal_version;
}

static int tls_handshake_hello_get_version(struct tls_information *tls_info,
                                           const unsigned char *data) {
    int internal_version = 0;
    unsigned char major = *data;
    unsigned char minor = *(data + 1);

    internal_version = tls_version_to_internal(major, minor);
    if (!internal_version) {
        /* Could not get the version, error or unsupported */
        return 1;
    }

    /* Capture it */
    tls_info->tls_v = internal_version;

    return 0;
}

/**
 * \fn void tls_update (struct tls_information *r,
 *                      const struct pcap_pkthdr *header,
 *                      const void *payload,
 *                      unsigned int len,
 *                      unsigned int report_tls)
 *
 * \brief Parse, process, and record TLS payload data.
 *
 * \param r TLS structure pointer
 * \param payload Beginning of the payload data.
 * \param len Length in bytes of the data that \p payload is pointing to.
 * \param report_tls Flag indicating whether this feature should run.
 *                   0 for no, 1 for yes
 *
 * \return
 */
void tls_update (struct tls_information *r,
                 const struct pcap_pkthdr *header,
                 const void *payload,
                 unsigned int len,
                 unsigned int report_tls) {
    const char *start = payload;
    const struct tls_header *tls = NULL;
    uint16_t tls_len;

    /*
     * Check run flag.
     * Bail if 0.
     */
    if (!report_tls) {
        return;
    }

    /* currently skipping SSLv2 */
  
    /* TODO Should have a more robust way to deal with "large" packets */
    if (len > 6000 || len == 0) {
        return;
    }

    /* Cast beginning of payload to a tls_header */
    tls = (const struct tls_header *)start;

    if (tls->content_type == TLS_CONTENT_HANDSHAKE &&
	(tls->handshake.msg_type == TLS_HANDSHAKE_SERVER_HELLO ||
	 tls->handshake.msg_type == TLS_HANDSHAKE_CERTIFICATE)) {
        if (r->start_cert == 0) {
            /* Create buffer to store the server certificate */
            r->certificate_buffer = calloc(1,MAX_CERTIFICATE_BUFFER);
            memcpy(r->certificate_buffer, tls, len);
            r->certificate_offset += len;
      
            r->start_cert = 1;
        } else if (r->start_cert == 1){
            /*
             * The TLS record already contains data related to the server certificate.
             * Try to append to that buffer if there is enough space.
             */
            if (r->certificate_offset + len <= MAX_CERTIFICATE_BUFFER) {
	            memcpy(r->certificate_buffer+r->certificate_offset, tls, len);
	            r->certificate_offset += len;
            }
        }

    } else if (r->start_cert == 1) {
        if (r->certificate_offset + len > MAX_CERTIFICATE_BUFFER) {
        } else {
            memcpy(r->certificate_buffer+r->certificate_offset, tls, len);
            r->certificate_offset += len;
        }
    }

    while (len > 0) {
        /* Cast beginning of payload to a tls_header */
        tls = (const struct tls_header *)start;

        /* Find the length of the TLS message */
        tls_len = tls_header_get_length(tls);

        if (((tls_len == 0) || (tls_len > len)) && !ipfix_collect_port) {
            return;
        }

        if (r->certificate_offset && r->start_cert == 1 &&
            ((tls->content_type == TLS_CONTENT_APPLICATION_DATA) ||
             (tls->content_type == TLS_CONTENT_CHANGE_CIPHER_SPEC) ||
             (tls->content_type == TLS_CONTENT_ALERT) ||
             (r->certificate_offset >= MAX_CERTIFICATE_BUFFER - 300) ||
             (ipfix_collect_port && tls->content_type == TLS_CONTENT_HANDSHAKE &&
              tls->handshake.msg_type == TLS_HANDSHAKE_CERTIFICATE))) {
            /*
             * We are past the certificate exchange phase in the handshake.
             * Now decide if we want to process the data in certificate buffer or not.
             */
            if (r->certificate_offset > 200) {
                /*
                 * The certificate is long enough to process. Go ahead and do that now.
                 */
                tls_certificate_process(r->certificate_buffer, r->certificate_offset, r);
                if (r->certificate_buffer) {
                    free(r->certificate_buffer);
                    r->certificate_buffer = 0;
                }
            } else {
                /*
                 * Free up the memory space we previously allocated in the certificate buffer.
                 */
                if (r->certificate_buffer) {
                    free(r->certificate_buffer);
                    r->certificate_buffer = 0;
                }
            }

            /*
             *  Indicate that we are finished dealing with the certificates
             *  for remainder of this particular flow.
             */
            r->start_cert = 2;
        }

        /*
         *********************************
         * CONTENT SWITCH
         *********************************
         */
        if (tls->content_type == TLS_CONTENT_APPLICATION_DATA) {
            if (!r->tls_v) {
                /* Write the TLS version to record if empty */
                if (tls_header_version_capture(r, tls)) {
                    /* TLS version sanity check failed */
                    return;
                }
            }
        } else if (tls->content_type == TLS_CONTENT_CHANGE_CIPHER_SPEC) {
            /*
             * The next message is encrypted, so ignore to avoid potential errors.
             */
            if (!r->tls_v) {
                /* Write the TLS version to record if empty */
                if (tls_header_version_capture(r, tls)) {
                    /* TLS version sanity check failed */
                    return;
                }
            }
            return;
        } else if (tls->content_type == TLS_CONTENT_HANDSHAKE) {
            /*
             * Check if handshake type is valid.
             */
            if (((tls->handshake.msg_type > 4) && (tls->handshake.msg_type < 11)) ||
                ((tls->handshake.msg_type > 16) && (tls->handshake.msg_type < 20)) ||
                (tls->handshake.msg_type > 23)) {
                /*
                 * We encountered an unknown HandshakeType, so this packet is
                 * not actually a TLS handshake, so we bail on decoding it.
                 */
                joy_log_err("unknown handshake type %u", tls->handshake.msg_type);
                return;
            }

            /*
             * Match to a handshake type we are interested in.
             */
            if (tls->handshake.msg_type == TLS_HANDSHAKE_CLIENT_HELLO) {
                /*
                 * Handshake: ClientHello
                 */
                unsigned int body_len = 0;

                if (!r->tls_v) {
                    /* Write the TLS version to record if empty */
                    if (tls_handshake_hello_get_version(r, &tls->handshake.body)) {
                        /* TLS version sanity check failed */
                        return;
                    }
                }

                r->role = role_client;
                body_len = tls_handshake_get_length(&tls->handshake);
                if (body_len > tls_len) {
                    return;
                }
                tls_client_hello_get_ciphersuites(&tls->handshake.body, body_len, r);
                tls_client_hello_get_extensions(&tls->handshake.body, body_len, r);

                if (r->tls_fingerprint == NULL) {
                    tls_client_fingerprint_match(r, 100);
                }
            } else if (tls->handshake.msg_type == TLS_HANDSHAKE_SERVER_HELLO) {
                /*
                 * Handshake: ServerHello
                 */
                unsigned int body_len = 0;

                if (!r->tls_v) {
                    /* Write the TLS version to record if empty */
                    if (tls_handshake_hello_get_version(r, &tls->handshake.body)) {
                        /* TLS version sanity check failed */
                        return;
                    }
                }

                r->role = role_server;
                body_len = tls_handshake_get_length(&tls->handshake);
                if (body_len > tls_len) {
                    return;
                }
                tls_server_hello_get_ciphersuite(&tls->handshake.body, body_len, r);
                tls_server_hello_get_extensions(&tls->handshake.body, body_len, r);
            } else if (tls->handshake.msg_type == TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE) {
                /*
                 * Handshake: ClientKeyExchange
                 */
                tls_handshake_get_client_key_exchange(&tls->handshake, tls_len, r);
            }

            if (r->tls_op < MAX_NUM_RCD_LEN) {
                /* Record the handshake message type for this packet */
	            r->tls_type[r->tls_op].handshake = tls->handshake.msg_type;
            }      
        } else if (tls->content_type != TLS_CONTENT_CHANGE_CIPHER_SPEC && 
	               tls->content_type != TLS_CONTENT_ALERT) {
            /* 
             * We encountered an unknown ContentType, so this is not
             * actually a TLS record, so we bail on decoding it.
             */      
            return;
        } else if (tls->content_type == TLS_CONTENT_ALERT) {
            /*
             * In the case of a Server sending an alert in response to a ClientHello
             */
            if (!r->tls_v) {
                /* Write the TLS version to record if empty */
                if (tls_handshake_hello_get_version(r, &tls->handshake.body)) {
                    /* TLS version sanity check failed */
                    return;
                }
            }
        }

        /*
         * Record TLS record lengths and arrival times
         */
        if (r->tls_op < MAX_NUM_RCD_LEN) {
            r->tls_type[r->tls_op].content = tls->content_type;
            r->tls_len[r->tls_op] = tls_len;
            if (header == NULL) {
                /* The pcap_pkthdr is not available, cannot get timestamp */
                const struct timeval ts = {0};
                r->tls_time[r->tls_op] = ts;
            } else {
                r->tls_time[r->tls_op] = header->ts;
            }
        }

        /* Increment TLS record count in tls_information */
        r->tls_op++;

        /* Advance over header */
        tls_len += 5;
        start += tls_len;

        if ((tls_len == 0) || (tls_len > len)) {
            return;
        }

        len -= tls_len;
    }

    return;
}

/**
 * \fn int tls_certificate_process (const void *data,
 *                                  int data_len,
 *                                  struct tls_information *tls_info)
 *
 * \brief Sift through \p data processing any certificate
 *        handshake messages that are encountered.
 *
 * \param data Beginning of the data to process.
 * \param data_len Length of \p data in bytes.
 * \param tls_info Pointer to the TLS info struct that will be written into.
 *
 * \return 0 for success, 1 for failure
 */
static int tls_certificate_process (const char *data,
                                    int data_len,
                                    struct tls_information *tls_info) {
    const struct tls_header *tls_hdr;
    unsigned int tls_len;

    while (data_len > 200) {
        tls_hdr = (const struct tls_header*)data;
        if (tls_hdr->content_type != TLS_CONTENT_HANDSHAKE) {
            break;
        }

        /* Get the length of the handshake portion of the message */
        tls_len = tls_header_get_length(tls_hdr);

        /* Only parse Certificate message types */
        if (tls_hdr->handshake.msg_type == TLS_HANDSHAKE_CERTIFICATE) {
            unsigned int body_len = tls_handshake_get_length(&tls_hdr->handshake);
	    if (body_len > tls_len) {
	      return 0;
	    }
            tls_server_certificate_parse(&tls_hdr->handshake.body, body_len, tls_info);
        }

        /* Adjust for the length of tls_hdr metadata */
        tls_len += 5;

        /* Advance over this handshake message */
        data += tls_len;
        data_len -= tls_len;
    }

    return 0;
}

/**
 * \fn void tls_header_version_capture (struct tls_information *tls_info,
 *                                      const struct tls_header *tls_hdr)
 *
 * \brief Get the TLS version out of the header, and write it into the record.
 *
 * \param tls_info TLS structure pointer
 * \param tls_hdr TLS header structure that holds version.
 *
 * \return 0 for success, 1 for failure
 */
static int tls_header_version_capture (struct tls_information *tls_info,
                                       const struct tls_header *tls_hdr) {
    int internal_version = 0;
    struct tls_protocol_version version = tls_hdr->protocol_version;

    internal_version = tls_version_to_internal(version.major, version.minor);
    if (!internal_version) {
        /* Could not get the version, error or unsupported */
        return 1;
    }

    /* Capture it */
    tls_info->tls_v = internal_version;

    return 0;
}

static void zprintf_raw_as_hex_tls (zfile f, const unsigned char *data, unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    if (len > 1024) {
        zprintf(f, "\"");   /* quotes needed for JSON */
        zprintf(f, "\"");
        return;
    }

    if (data == NULL) { /* special case for nfv9 TLS export */
        zprintf(f, "\"");   /* quotes needed for JSON */
        zprintf(f, "\"");
        return ;
    }
  
    zprintf(f, "\"");   /* quotes needed for JSON */
    while (x < end) {
        zprintf(f, "%02x", *x++);
    }
    zprintf(f, "\"");
}

static void print_bytes_dir_time_tls (unsigned short int pkt_len, 
    char *dir, struct timeval ts, struct tls_type_code type, 
    char *term, zfile f) {

    zprintf(f, "{\"b\":%u,\"dir\":\"%s\",\"ipt\":%u,\"tp\":\"%u:%u\"}%s", 
	      pkt_len, dir, joy_timeval_to_milliseconds(ts), type.content,
          type.handshake, term);
}

static void len_time_print_interleaved_tls (unsigned int op, const unsigned short *len, 
    const struct timeval *time, const struct tls_type_code *type,
    unsigned int op2, const unsigned short *len2, 
    const struct timeval *time2, const struct tls_type_code *type2, zfile f) {
    unsigned int i, j, imax, jmax;
    struct timeval ts, ts_last, ts_start, tmp;
    unsigned int pkt_len;
    char *dir;
    struct tls_type_code typecode;
    unsigned int num_pkt_len_tls = NUM_PKT_LEN_TLS;

    zprintf(f, ",\"srlt\":[");

    if (len2 == NULL) {
      
        ts_start = *time;

        imax = op > num_pkt_len_tls ? num_pkt_len_tls : op;
        if (imax == 0) { 
            ; /* no packets had data, so we print out nothing */
        } else {
            for (i = 0; i < imax-1; i++) {
	            if (i > 0) {
	                joy_timer_sub(&time[i], &time[i-1], &ts);
	            } else {
	                joy_timer_clear(&ts);
	            }
	            print_bytes_dir_time_tls(len[i], OUT, ts, type[i], ",", f);
            }
            if (i == 0) {        /* this code could be simplified */ 	
	            joy_timer_clear(&ts);  
            } else {
	            joy_timer_sub(&time[i], &time[i-1], &ts);
            }
            print_bytes_dir_time_tls(len[i], OUT, ts, type[i], "", f);
        }
        zprintf(f, "]"); 
    } else {

        if (joy_timer_lt(time, time2)) {
            ts_start = *time;
        } else {
            ts_start = *time2;
        }

        imax = op > num_pkt_len_tls ? num_pkt_len_tls : op;
        jmax = op2 > num_pkt_len_tls ? num_pkt_len_tls : op2;
        i = j = 0;
        ts_last = ts_start;
        while ((i < imax) || (j < jmax)) {      

            if (i >= imax) {  /* record list is exhausted, so use twin */
	            dir = OUT;
	            ts = time2[j];
	            pkt_len = len2[j];
	            typecode = type2[j];
	            j++;
            } else if (j >= jmax) {  /* twin list is exhausted, so use record */
	            dir = IN;
	            ts = time[i];
	            pkt_len = len[i];
	            typecode = type[i];
	            i++;
            } else { /* neither list is exhausted, so use list with lowest time */     

	            if (joy_timer_lt(&time[i], &time2[j])) {
	                ts = time[i];
	                pkt_len = len[i];
	                typecode = type[i];
	                dir = IN;
	                if (i < imax) {
	                    i++;
	                }
	            } else {
	                ts = time2[j];
	                pkt_len = len2[j];
	                typecode = type2[j];
	                dir = OUT;
	                if (j < jmax) {
	                    j++;
	                }
	            }
            }
            joy_timer_sub(&ts, &ts_last, &tmp);
            print_bytes_dir_time_tls(pkt_len, dir, tmp, typecode, "", f);
            ts_last = ts;
            if (!((i == imax) & (j == jmax))) { /* we are done */
	            zprintf(f, ",");
            }
        }
        zprintf(f, "]");
    }
}

/**
 * \fn void tls_print_json (const struct tls_information *data,
 *                          const struct tls_information *data_twin,
 *                          zfile f)
 *
 * \param data pointer to TLS information structure
 * \param data_twin pointer to twin TLS information structure
 * \param f destination file for the output
 *
 * \return
 *
 */
void tls_print_json (const struct tls_information *data,
                     const struct tls_information *data_twin,
                     zfile f) {
    int i;

    /* sanity check tls data passed in */
    if (data == NULL) {
        return;
    }

    /* make sure the tls info passed in is reliable */
    if (!data->tls_v) {
        return;
    }

    /* if a twin is present make sure its info is reliable */
    if (data_twin != NULL && !data_twin->tls_v) {
        return;
    }

    zprintf(f, ",\"tls\":{");

    if (data->tls_v) {
        zprintf(f, "\"tls_ov\":%u", data->tls_v);
    }
    if (data_twin && data_twin->tls_v) {
        if (data->tls_v) {
            zprintf(f, ",\"tls_iv\":%u", data_twin->tls_v);
        } else {
            zprintf(f, "\"tls_iv\":%u", data_twin->tls_v);
        }
    }

    if (data->tls_client_key_length) {
        zprintf(f, ",\"tls_client_key_length\":%u", data->tls_client_key_length);
        zprintf(f, ",\"clientKeyExchange\":");
        zprintf_raw_as_hex_tls(f, data->clientKeyExchange, data->tls_client_key_length/8);
    }
    if (data_twin && data_twin->tls_client_key_length) {
        zprintf(f, ",\"tls_client_key_length\":%u", data_twin->tls_client_key_length);
        zprintf(f, ",\"clientKeyExchange\":");
        zprintf_raw_as_hex_tls(f, data_twin->clientKeyExchange, data_twin->tls_client_key_length/8);
    }

    /* print out TLS random */
    if (data->role == role_client) {
	zprintf(f, ",\"tls_crandom\":");
	zprintf_raw_as_hex_tls(f, data->tls_random, 32);
	if (data_twin) {
	    if (data_twin->role == role_server) {
		zprintf(f, ",\"tls_srandom\":");
		zprintf_raw_as_hex_tls(f, data_twin->tls_random, 32);
	    }  else if (data_twin->role == role_client) {
		zprintf(f, ",\"error\":\"twin clients\"");  
	    } 
	} 
    } else if (data->role == role_server) {
	zprintf(f, ",\"tls_srandom\":");
	zprintf_raw_as_hex_tls(f, data->tls_random, 32);
	if (data_twin) {
	    if (data_twin->role == role_client) {
		zprintf(f, ",\"tls_crandom\":");
		zprintf_raw_as_hex_tls(f, data_twin->tls_random, 32);
	    } else if (data_twin->role == role_server) {
		zprintf(f, ",\"error\":\"twin servers\"");  
	    }
	}
    }

    if (data->tls_sid_len) {
        zprintf(f, ",\"tls_osid\":");
        zprintf_raw_as_hex_tls(f, data->tls_sid, data->tls_sid_len);
    }
    if (data_twin && data_twin->tls_sid_len) {
        zprintf(f, ",\"tls_isid\":");
        zprintf_raw_as_hex_tls(f, data_twin->tls_sid, data_twin->tls_sid_len);
    }

    if (data->sni_length) {
        zprintf(f, ",\"SNI\":[\"%s\"]",(char *)data->sni);
    }
    if (data_twin && data_twin->sni_length) {
        zprintf(f, ",\"SNI\":[\"%s\"]",(char *)data_twin->sni);
    }

    if (data->num_ciphersuites) {
        if (data->num_ciphersuites == 1) {
            zprintf(f, ",\"scs\":\"%04x\"", data->ciphersuites[0]);
        } else {
            zprintf(f, ",\"cs\":[");
            for (i = 0; i < data->num_ciphersuites-1; i++) {
	            zprintf(f, "\"%04x\",", data->ciphersuites[i]);
            }
            zprintf(f, "\"%04x\"]", data->ciphersuites[i]);
        }
    }  
    if (data_twin && data_twin->num_ciphersuites) {
        if (data_twin->num_ciphersuites == 1) {
            zprintf(f, ",\"scs\":\"%04x\"", data_twin->ciphersuites[0]);
        } else {
            zprintf(f, ",\"cs\":[");
            for (i = 0; i < data_twin->num_ciphersuites-1; i++) {
	            zprintf(f, "\"%04x\",", data_twin->ciphersuites[i]);
            }
            zprintf(f, "\"%04x\"]", data_twin->ciphersuites[i]);
        }
    }    
  
    if (data->num_tls_extensions) {
        zprintf(f, ",\"tls_ext\":[");
        for (i = 0; i < data->num_tls_extensions-1; i++) {
            zprintf(f, "{\"type\":\"%04x\",", data->tls_extensions[i].type);
            zprintf(f, "\"length\":%i,\"data\":", data->tls_extensions[i].length);
            zprintf_raw_as_hex_tls(f, data->tls_extensions[i].data, data->tls_extensions[i].length);
            zprintf(f, "},");
        }
        zprintf(f, "{\"type\":\"%04x\",", data->tls_extensions[i].type);
        zprintf(f, "\"length\":%i,\"data\":", data->tls_extensions[i].length);
        zprintf_raw_as_hex_tls(f, data->tls_extensions[i].data, data->tls_extensions[i].length);
        zprintf(f, "}]");
    }  
    if (data_twin && data_twin->num_tls_extensions) {
        zprintf(f, ",\"tls_ext\":[");
        for (i = 0; i < data_twin->num_tls_extensions-1; i++) {
            zprintf(f, "{\"type\":\"%04x\",", data_twin->tls_extensions[i].type);
            zprintf(f, "\"length\":%i,\"data\":", data_twin->tls_extensions[i].length);
            zprintf_raw_as_hex_tls(f, data_twin->tls_extensions[i].data, data_twin->tls_extensions[i].length);
            zprintf(f, "},");
        }
        zprintf(f, "{\"type\":\"%04x\",", data_twin->tls_extensions[i].type);
        zprintf(f, "\"length\":%i,\"data\":", data_twin->tls_extensions[i].length);
        zprintf_raw_as_hex_tls(f, data_twin->tls_extensions[i].data, data_twin->tls_extensions[i].length);
        zprintf(f, "}]");
    }
  
    if (data->num_server_tls_extensions) {
        zprintf(f, ",\"s_tls_ext\":[");
        for (i = 0; i < data->num_server_tls_extensions-1; i++) {
            zprintf(f, "{\"type\":\"%04x\",", data->server_tls_extensions[i].type);
            zprintf(f, "\"length\":%i,\"data\":", data->server_tls_extensions[i].length);
            zprintf_raw_as_hex_tls(f, data->server_tls_extensions[i].data, data->server_tls_extensions[i].length);
            zprintf(f, "},");
        }
        zprintf(f, "{\"type\":\"%04x\",", data->server_tls_extensions[i].type);
        zprintf(f, "\"length\":%i,\"data\":", data->server_tls_extensions[i].length);
        zprintf_raw_as_hex_tls(f, data->server_tls_extensions[i].data, data->server_tls_extensions[i].length);
        zprintf(f, "}]");
    }  
    if (data_twin && data_twin->num_server_tls_extensions) {
        zprintf(f, ",\"s_tls_ext\":[");
        for (i = 0; i < data_twin->num_server_tls_extensions-1; i++) {
            zprintf(f, "{\"type\":\"%04x\",", data_twin->server_tls_extensions[i].type);
            zprintf(f, "\"length\":%i,\"data\":", data_twin->server_tls_extensions[i].length);
            zprintf_raw_as_hex_tls(f, data_twin->server_tls_extensions[i].data, data_twin->server_tls_extensions[i].length);
            zprintf(f, "},");
        }
        zprintf(f, "{\"type\":\"%04x\",", data_twin->server_tls_extensions[i].type);
        zprintf(f, "\"length\":%i,\"data\":", data_twin->server_tls_extensions[i].length);
        zprintf_raw_as_hex_tls(f, data_twin->server_tls_extensions[i].data, data_twin->server_tls_extensions[i].length);
        zprintf(f, "}]");
    }

    if (data->tls_fingerprint) {
        zprintf(f, ",\"fingerprint_labels\":[");
        for (i = 0; i < data->tls_fingerprint->label_count; i++) {
	        zprintf(f, "\"%s\"", data->tls_fingerprint->labels[i]);
            if (i == (data->tls_fingerprint->label_count - 1)) {
                zprintf(f, "]");
            } else {
                zprintf(f, ", ");
            }
        }
    }

    if (data->num_certificates) {
        zprintf(f, ",\"server_cert\":[");
        for (i = 0; i < data->num_certificates-1; i++) {
            tls_certificate_printf(&data->certificates[i], f);
            zprintf(f, "},");
        }
        tls_certificate_printf(&data->certificates[i], f);    
        zprintf(f, "}]");
    }
    if (data_twin && data_twin->num_certificates) {
        zprintf(f, ",\"server_cert\":[");
        for (i = 0; i < data_twin->num_certificates-1; i++) {
            tls_certificate_printf(&data_twin->certificates[i], f);
            zprintf(f, "},");
        }
        tls_certificate_printf(&data_twin->certificates[i], f);    
        zprintf(f, "}]");
    }  
    /* print out TLS application data lengths and times, if any */

    if (data->tls_op) {
        if (data_twin) {
	        len_time_print_interleaved_tls(data->tls_op, data->tls_len, data->tls_time, data->tls_type,
				       data_twin->tls_op, data_twin->tls_len, data_twin->tls_time, data_twin->tls_type, f);
        } else {
	    /*
	     * unidirectional TLS does not typically happen, but if it
	     * does, we need to pass in zero/NULLs, since there is no twin
	     */
	        len_time_print_interleaved_tls(data->tls_op, data->tls_len, data->tls_time, data->tls_type, 0, NULL, NULL, NULL, f);
        }
    }

    zprintf(f, "}");
}

/**
 * \fn void tls_certificate_printf (const struct tls_certificate *data,
 *                                  zfile f)
 *
 * \brief Print the contents of a TLS certificate to compressed JSON output.
 *
 * \param data pointer to TLS certificate structure
 * \param f destination file for the output
 *
 * \return
 *
 */
static void tls_certificate_printf (const struct tls_certificate *data, zfile f) {
    int j = 0;

    zprintf(f, "{\"length\":%i", data->length);
    if (data->serial_number) {
        zprintf(f, ",\"serial_number\":");
        zprintf_raw_as_hex_tls(f, data->serial_number, data->serial_number_length);
    }
    
    if (data->signature) {
        zprintf(f, ",\"signature\":");
        zprintf_raw_as_hex_tls(f, data->signature, data->signature_length);
    }

    if (*data->signature_algorithm) {
        zprintf(f, ",\"signature_algorithm\": \"%s\"", data->signature_algorithm);
    }

    if (data->signature_key_size) {
        zprintf(f, ",\"signature_key_size\":%i", data->signature_key_size);
    }
    
    if (data->num_issuer_items) {
        zprintf(f, ",\"issuer\":[");
        for (j = 0; j < data->num_issuer_items; j++) {
	        zprintf(f, "{\"entry_id\": \"%s\",", data->issuer[j].id);
            /* Print the data as a string */
	        zprintf(f, "\"entry_data\":\"%s\"}", (char *)data->issuer[j].data);
            if (j == (data->num_issuer_items - 1)) {
                zprintf(f, "]");
            } else {
                zprintf(f, ",");
            }
        }
    }

    if (data->num_subject_items) {
        zprintf(f, ",\"subject\":[");
        for (j = 0; j < data->num_subject_items; j++) {
	        zprintf(f, "{\"entry_id\": \"%s\",", data->subject[j].id);
            /* Print the data as a string */
	        zprintf(f, "\"entry_data\":\"%s\"}", (char *)data->subject[j].data);
            if (j == (data->num_subject_items - 1)) {
                zprintf(f, "]");
            } else {
                zprintf(f, ",");
            }
        }
    }

    if (data->num_extension_items) {
        zprintf(f, ",\"extensions\":[");
        for (j = 0; j < data->num_extension_items; j++) {
	        zprintf(f, "{\"entry_id\": \"%s\", ", data->extensions[j].id);
            /* Print the data as a string */
	        zprintf(f, "\"entry_data\": \"%s\"}", (char *)data->extensions[j].data);
            if (j == (data->num_extension_items - 1)) {
                zprintf(f, "]");
            } else {
                zprintf(f, ",");
            }
        }
    }
    
    if (data->validity_not_before) {
        zprintf(f, ",\"validity_not_before\": \"%s\"", data->validity_not_before);
    }
    if (data->validity_not_after) {
        zprintf(f, ",\"validity_not_after\": \"%s\"", data->validity_not_after);
    }
    
    if (*data->subject_public_key_algorithm) {
        zprintf(f, ",\"subject_public_key_algorithm\": \"%s\"", data->subject_public_key_algorithm);
    }
    
    if (data->subject_public_key_size) {
        zprintf(f, ",\"subject_public_key_size\":%i", data->subject_public_key_size);
    }
}

/*
 * \brief Unit test for ts_client_fingerprint_match().
 *
 * \return 0 for success, otherwise number of failures
 */
static int tls_test_client_fingerprint_match() {
    struct tls_information *record = NULL;
    int num_fails = 0;

    tls_init(&record);

    record->num_ciphersuites = 20;
    record->num_tls_extensions = 1;

    /* Known ciphersuites */
    record->ciphersuites[0] = 0x0039;
    record->ciphersuites[1] = 0x0038;
    record->ciphersuites[2] = 0x0035;
    record->ciphersuites[3] = 0x0016;
    record->ciphersuites[4] = 0x0013;
    record->ciphersuites[5] = 0x000a;
    record->ciphersuites[6] = 0x0033;
    record->ciphersuites[7] = 0x0032;
    record->ciphersuites[8] = 0x002f;
    record->ciphersuites[9] = 0x0007;
    record->ciphersuites[10] = 0x0005;
    record->ciphersuites[11] = 0x0004;
    record->ciphersuites[12] = 0x0015;
    record->ciphersuites[13] = 0x0012;
    record->ciphersuites[14] = 0x0009;
    record->ciphersuites[15] = 0x0014;
    record->ciphersuites[16] = 0x0011;
    record->ciphersuites[17] = 0x0008;
    record->ciphersuites[18] = 0x0006;
    record->ciphersuites[19] = 0x0003;

    /* Known extensions */
    record->tls_extensions[0].type = 0x0023;

    tls_client_fingerprint_match(record, 100);
    if (record->tls_fingerprint == NULL) {
        joy_log_err("could not match known fingerprint");
        num_fails++;
    }

    tls_delete(&record);

    return num_fails;
}

/*
 * \brief Test the internal TLS X509 certificate parsing api.
 *
 * \return 0 for success, otherwise number of failures
 */
static int tls_test_certificate_parsing() {
    const char *test_cert_filenames[] = {"dummy_cert_rsa2048.pem"};
    int max_filename_len = 50;
    int num_test_cert_files = 1;
    int num_fails = 0;
    int i = 0;

    for (i = 0; i < num_test_cert_files; i++) {
        FILE *fp = NULL;
        X509 *cert = NULL;
        struct tls_information *tmp_tls_record = NULL;
        struct tls_certificate *cert_record = NULL;
        const char *filename = test_cert_filenames[i];

        /* Preprare the temporary record */
        tls_init(&tmp_tls_record);
        cert_record = &tmp_tls_record->certificates[0];
        tmp_tls_record->num_certificates++;

        fp = joy_utils_open_test_file(filename);
        if (!fp) {
            joy_log_err("unable to open %s", filename);
            num_fails++;
            goto end_loop;
        }

        cert = PEM_read_X509(fp, NULL, NULL, NULL);
        if (!cert) {
            joy_log_err("could not convert %s PEM into X509", filename);
            num_fails++;
            goto end_loop;
        }

        /*************************************
         * Test subject
         ************************************/
        if (tls_x509_get_subject(cert, cert_record)){
            joy_log_err("fail, tls_x509_get_subject - %s", filename);
            num_fails++;
        } else {
            if (!strncmp(filename, "dummy_cert_rsa2048.pem", max_filename_len)) {
                /* We are using the dummy_rsa2048 for this case */
                int known_items_count = 7;
                int failed = 0;

                if (cert_record->num_subject_items == known_items_count) {
					/* windows compiler needs the constant and not the variable here */
					//struct tls_item_entry kat_subject[known_items_count];
					struct tls_item_entry kat_subject[7];
					int j = 0;

                    /* Known values */
                    strncpy(kat_subject[0].id, "countryName", MAX_OPENSSL_STRING);
                    kat_subject[0].data_length = 2;
                    kat_subject[0].data = calloc(kat_subject[0].data_length, sizeof(unsigned char));
                    memcpy(kat_subject[0].data, "US", kat_subject[0].data_length);

                    strncpy(kat_subject[1].id, "stateOrProvinceName", MAX_OPENSSL_STRING);
                    kat_subject[1].data_length = 10;
                    kat_subject[1].data = calloc(kat_subject[1].data_length, sizeof(unsigned char));
                    memcpy(kat_subject[1].data, "California", kat_subject[1].data_length);

                    strncpy(kat_subject[2].id, "localityName", MAX_OPENSSL_STRING);
                    kat_subject[2].data_length = 11;
                    kat_subject[2].data = calloc(kat_subject[2].data_length, sizeof(unsigned char));
                    memcpy(kat_subject[2].data, "Los Angeles", kat_subject[2].data_length);

                    strncpy(kat_subject[3].id, "organizationName", MAX_OPENSSL_STRING);
                    kat_subject[3].data_length = 12;
                    kat_subject[3].data = calloc(kat_subject[3].data_length, sizeof(unsigned char));
                    memcpy(kat_subject[3].data, "Joy Software", kat_subject[3].data_length);

                    strncpy(kat_subject[4].id, "organizationalUnitName", MAX_OPENSSL_STRING);
                    kat_subject[4].data_length = 12;
                    kat_subject[4].data = calloc(kat_subject[4].data_length, sizeof(unsigned char));
                    memcpy(kat_subject[4].data, "Unit Testing", kat_subject[4].data_length);

                    strncpy(kat_subject[5].id, "commonName", MAX_OPENSSL_STRING);
                    kat_subject[5].data_length = 10;
                    kat_subject[5].data = calloc(kat_subject[5].data_length, sizeof(unsigned char));
                    memcpy(kat_subject[5].data, "github.com", kat_subject[5].data_length);

                    strncpy(kat_subject[6].id, "emailAddress", MAX_OPENSSL_STRING);
                    kat_subject[6].data_length = 16;
                    kat_subject[6].data = calloc(kat_subject[6].data_length, sizeof(unsigned char));
                    memcpy(kat_subject[6].data, "dummy@brains.com", kat_subject[6].data_length);

                    /*
                     * KAT
                     */
                    for (j = 0; j < known_items_count; j++) {
                        if (strncmp(cert_record->subject[j].id, kat_subject[j].id, MAX_OPENSSL_STRING)) {
                            joy_log_err("subject[%d].id does not match", j);
                            failed = 1;
                        }
                        if (cert_record->subject[j].data_length != kat_subject[j].data_length) {
                            joy_log_err("subject[%d].data_length does not match", j);
                            failed = 1;
                        }
                        if (memcmp(cert_record->subject[j].data, kat_subject[j].data, kat_subject[j].data_length)) {
                            joy_log_err("subject[%d].data does not match", j);
                            failed = 1;
                        }
                    }

                    /* Cleanup the temp known value */
                    for (j = 0; j < known_items_count; j++) {
                        if (kat_subject[j].data) {
                            free(kat_subject[j].data);
                        }
                    }
                } else {
                    joy_log_err("expected %d subject items, got %d",
                                known_items_count, cert_record->num_subject_items);
                    failed = 1;
                }

                if (failed){
                    /* There was at least one case that threw error */
                    joy_log_err("fail, tls_x509_get_subject - %s", filename);
                    num_fails++;
                }
            }
        }

        /*************************************
         * Test issuer
         ************************************/
        if (tls_x509_get_issuer(cert, cert_record)) {
            joy_log_err("fail, tls_x509_get_issuer - %s", filename);
            num_fails++;
        } else {
            if (!strncmp(filename, "dummy_cert_rsa2048.pem", max_filename_len)) {
                /* We are using the dummy_rsa2048 for this case */
                int known_items_count = 7;
                int failed = 0;

                if (cert_record->num_issuer_items == known_items_count) {
					/* windows compiler needs the constant and not the variable here */
					//struct tls_item_entry kat_issuer[known_items_count];
					struct tls_item_entry kat_issuer[7];
					int j = 0;

                    /* Known values */
                    strncpy(kat_issuer[0].id, "countryName", MAX_OPENSSL_STRING);
                    kat_issuer[0].data_length = 2;
                    kat_issuer[0].data = calloc(kat_issuer[0].data_length, sizeof(unsigned char));
                    memcpy(kat_issuer[0].data, "US", kat_issuer[0].data_length);

                    strncpy(kat_issuer[1].id, "stateOrProvinceName", MAX_OPENSSL_STRING);
                    kat_issuer[1].data_length = 10;
                    kat_issuer[1].data = calloc(kat_issuer[1].data_length, sizeof(unsigned char));
                    memcpy(kat_issuer[1].data, "California", kat_issuer[1].data_length);

                    strncpy(kat_issuer[2].id, "localityName", MAX_OPENSSL_STRING);
                    kat_issuer[2].data_length = 11;
                    kat_issuer[2].data = calloc(kat_issuer[2].data_length, sizeof(unsigned char));
                    memcpy(kat_issuer[2].data, "Los Angeles", kat_issuer[2].data_length);

                    strncpy(kat_issuer[3].id, "organizationName", MAX_OPENSSL_STRING);
                    kat_issuer[3].data_length = 12;
                    kat_issuer[3].data = calloc(kat_issuer[3].data_length, sizeof(unsigned char));
                    memcpy(kat_issuer[3].data, "Joy Software", kat_issuer[3].data_length);

                    strncpy(kat_issuer[4].id, "organizationalUnitName", MAX_OPENSSL_STRING);
                    kat_issuer[4].data_length = 12;
                    kat_issuer[4].data = calloc(kat_issuer[4].data_length, sizeof(unsigned char));
                    memcpy(kat_issuer[4].data, "Unit Testing", kat_issuer[4].data_length);

                    strncpy(kat_issuer[5].id, "commonName", MAX_OPENSSL_STRING);
                    kat_issuer[5].data_length = 10;
                    kat_issuer[5].data = calloc(kat_issuer[5].data_length, sizeof(unsigned char));
                    memcpy(kat_issuer[5].data, "github.com", kat_issuer[5].data_length);

                    strncpy(kat_issuer[6].id, "emailAddress", MAX_OPENSSL_STRING);
                    kat_issuer[6].data_length = 16;
                    kat_issuer[6].data = calloc(kat_issuer[6].data_length, sizeof(unsigned char));
                    memcpy(kat_issuer[6].data, "dummy@brains.com", kat_issuer[6].data_length);

                    /*
                     * KAT
                     */
                    for (j = 0; j < known_items_count; j++) {
                        if (strncmp(cert_record->issuer[j].id, kat_issuer[j].id, MAX_OPENSSL_STRING)) {
                            joy_log_err("issuer[%d].id does not match", j);
                            failed = 1;
                        }
                        if (cert_record->issuer[j].data_length != kat_issuer[j].data_length) {
                            joy_log_err("issuer[%d].data_length does not match", j);
                            failed = 1;
                        }
                        if (memcmp(cert_record->issuer[j].data, kat_issuer[j].data, kat_issuer[j].data_length)) {
                            joy_log_err("issuer[%d].data does not match", j);
                            failed = 1;
                        }
                    }

                    /* Cleanup the temp known value */
                    for (j = 0; j < known_items_count; j++) {
                        if (kat_issuer[j].data) {
                            free(kat_issuer[j].data);
                        }
                    }
                } else {
                    joy_log_err("expected %d issuer items, got %d",
                            known_items_count, cert_record->num_issuer_items);
                    failed = 1;
                }

                if (failed){
                    /* There was at least one case that threw error */
                    joy_log_err("fail, tls_x509_get_issuer - %s", filename);
                    num_fails++;
                }
            }
        }

        /*************************************
         * Test validity
         ************************************/
        if (tls_x509_get_validity_period(cert, cert_record)) {
            joy_log_err("fail, tls_x509_get_validity_period - %s", filename);
            num_fails++;
        } else {
            if (!strncmp(filename, "dummy_cert_rsa2048.pem", max_filename_len)) {
                /* We are using the dummy_rsa2048 for this case */
                uint16_t known_not_before_length = 24;
                uint16_t known_not_after_length = 24;
                int failed = 0;

                char *known_not_before = "Mar 31 18:28:35 2017 GMT";

                char *known_not_after = "Mar 31 18:28:35 2018 GMT";

                if (cert_record->validity_not_before_length != known_not_before_length) {
                    joy_log_err("not_before length does not match");
                    failed = 1;
                }

                if (strncmp((char*)cert_record->validity_not_before, known_not_before,
                            known_not_before_length)) {
                    joy_log_err("not_before data does not match");
                    failed = 1;
                }

                if (cert_record->validity_not_before_length != known_not_before_length) {
                    joy_log_err("not_after length does not match");
                    failed = 1;
                }

                if (strncmp((char*)cert_record->validity_not_after, known_not_after,
                            known_not_after_length)) {
                    joy_log_err("not_after data does not match");
                    failed = 1;
                }

                if (failed){
                    /* There was at least one case that threw error */
                    joy_log_err("fail, tls_x509_get_validity_period - %s", filename);
                    num_fails++;
                }
            }
        }

        /*************************************
         * Test serial
         ************************************/
        if (tls_x509_get_serial(cert, cert_record)) {
            joy_log_err("fail, tls_x509_get_serial - %s", filename);
            num_fails++;
        } else {
            if (!strncmp(filename, "dummy_cert_rsa2048.pem", max_filename_len)) {
                /* We are using the dummy_rsa2048 for this case */
                uint16_t known_serial_length = 8;
                int failed = 0;

                unsigned char known_serial[] = {
                    0xd4, 0xfe, 0x2c, 0xa9, 0xfe, 0x6e, 0x39, 0x2b
                };

                if (cert_record->serial_number_length != known_serial_length) {
                    joy_log_err("serial length does not match");
                    failed = 1;
                }

                if (memcmp(cert_record->serial_number, known_serial, known_serial_length)) {
                    joy_log_err("serial data does not match");
                    failed = 1;
                }

                if (failed){
                    /* There was at least one case that threw error */
                    joy_log_err("fail, tls_x509_get_serial - %s", filename);
                    num_fails++;
                }
            }
        }

        /*************************************
         * Test extensions
         ************************************/
        if (tls_x509_get_extensions(cert, cert_record)) {
            joy_log_err("fail, tls_x509_get_extensions - %s", filename);
            num_fails++;
        } else {
            if (!strncmp(filename, "dummy_cert_rsa2048.pem", max_filename_len)) {
                /* We are using the dummy_rsa2048 for this case */
                int known_items_count = 3;
                int failed = 0;

                if (cert_record->num_extension_items == known_items_count) {
					/* windows compiler needs the constant and not the variable here */
					//struct tls_item_entry kat_extensions[known_items_count];
					struct tls_item_entry kat_extensions[3];
					int j = 0;

                    char *known_subject_key_identifier = "CE:BF:D3:46:C6:75:AB:8C:B2:E8:"
                                                         "CF:B8:2E:2F:43:6E:C9:17:AD:BA";

                    char *known_authority_key_identifier = "keyid:CE:BF:D3:46:C6:75:AB:8C:B2:"
                                                           "E8:CF:B8:2E:2F:43:6E:C9:17:AD:BA.";

                    char *known_basic_constraints = "CA:TRUE";

                    /* Known values */
                    strncpy(kat_extensions[0].id, "X509v3 Subject Key Identifier", MAX_OPENSSL_STRING);
                    kat_extensions[0].data_length = 59;
                    kat_extensions[0].data = calloc(kat_extensions[0].data_length, sizeof(unsigned char));
                    memcpy(kat_extensions[0].data, known_subject_key_identifier, kat_extensions[0].data_length);

                    strncpy(kat_extensions[1].id, "X509v3 Authority Key Identifier", MAX_OPENSSL_STRING);
                    kat_extensions[1].data_length = 66;
                    kat_extensions[1].data = calloc(kat_extensions[1].data_length, sizeof(unsigned char));
                    memcpy(kat_extensions[1].data, known_authority_key_identifier, kat_extensions[1].data_length);

                    strncpy(kat_extensions[2].id, "X509v3 Basic Constraints", MAX_OPENSSL_STRING);
                    kat_extensions[2].data_length = 7;
                    kat_extensions[2].data = calloc(kat_extensions[2].data_length, sizeof(unsigned char));
                    memcpy(kat_extensions[2].data, known_basic_constraints, kat_extensions[2].data_length);

                    /*
                     * KAT
                     */
                    for (j = 0; j < known_items_count; j++) {
                        if (strncmp(cert_record->extensions[j].id, kat_extensions[j].id, MAX_OPENSSL_STRING)) {
                            joy_log_err("extensions[%d].id does not match", j);
                            failed = 1;
                        }
                        if (cert_record->extensions[j].data_length != kat_extensions[j].data_length) {
                            joy_log_err("extensions[%d].data_length does not match", j);
                            failed = 1;
                        }
                        if (memcmp(cert_record->extensions[j].data, kat_extensions[j].data, kat_extensions[j].data_length)) {
                            joy_log_err("extensions[%d].data does not match", j);
                            failed = 1;
                        }
                    }

                    /* Cleanup the temp known value */
                    for (j = 0; j < known_items_count; j++) {
                        if (kat_extensions[j].data) {
                            free(kat_extensions[j].data);
                        }
                    }
                } else {
                    joy_log_err("expected %d extension items, got %d",
                                known_items_count, cert_record->num_extension_items);
                    failed = 1;
                }

                if (failed){
                    /* There was at least one case that threw error */
                    joy_log_err("fail, tls_x509_get_extensions - %s", filename);
                    num_fails++;
                }
            }
        }

        /*************************************
         * Test signature
         ************************************/
        if (tls_x509_get_signature(cert, cert_record)) {
            joy_log_err("fail, tls_x509_get_signature - %s", filename);
            num_fails++;
        } else {
            if (!strncmp(filename, "dummy_cert_rsa2048.pem", max_filename_len)) {
                /* We are using the dummy_rsa2048 for this case */
                uint16_t known_signature_length = 256;
                uint16_t known_signature_key_size = 2048;
                char *known_signature_algorithm = "sha256WithRSAEncryption";
                int failed = 0;

                unsigned char known_signature[] = {
                    0xbf, 0x79, 0x42, 0xe4, 0xb3, 0xba, 0x38, 0x06,
                    0x95, 0xba, 0x8e, 0x1d, 0xdb, 0xbd, 0xa7, 0xd1,
                    0xe7, 0xd6, 0x92, 0xf7, 0xbe, 0x77, 0x05, 0xa6,
                    0x92, 0x0e, 0x17, 0x75, 0x05, 0xb7, 0x06, 0xaf,
                    0x80, 0xe0, 0x5a, 0x2b, 0xd5, 0x8b, 0x4f, 0x7f,
                    0xce, 0x1b, 0xf6, 0xdb, 0x06, 0x95, 0x8d, 0x85,
                    0xda, 0x27, 0xf1, 0xbd, 0x88, 0x43, 0xa6, 0x86,
                    0xe0, 0x51, 0x3f, 0x1d, 0xc7, 0x4e, 0xe9, 0xcc,
                    0x29, 0x37, 0x7e, 0x57, 0x5a, 0x91, 0x1b, 0x4f,
                    0xaa, 0xd0, 0x62, 0x62, 0xc8, 0x01, 0x8d, 0x92,
                    0x48, 0xb2, 0x19, 0x0e, 0x89, 0x9f, 0x26, 0x8a,
                    0x34, 0x98, 0xa1, 0x2d, 0x71, 0xfe, 0xa0, 0xa8,
                    0x4c, 0x64, 0xba, 0xc8, 0x43, 0x81, 0x2f, 0xd8,
                    0x83, 0xd6, 0xb8, 0x14, 0xb9, 0xf8, 0xf2, 0x71,
                    0x31, 0x86, 0x5d, 0x79, 0xd8, 0xe4, 0x48, 0xee,
                    0xd0, 0xaf, 0xcc, 0x66, 0x94, 0x8d, 0x6d, 0xa9,
                    0x20, 0xf9, 0x61, 0x13, 0x77, 0x25, 0x86, 0xc0,
                    0xb2, 0x75, 0xb0, 0x95, 0xbe, 0x8e, 0xc0, 0x68,
                    0x3c, 0xc3, 0x35, 0xe4, 0x8f, 0x5b, 0xc1, 0x1b,
                    0x91, 0x16, 0x2e, 0x9a, 0x3a, 0x77, 0x36, 0x0c,
                    0xe0, 0x1f, 0x5e, 0x3f, 0x75, 0xc9, 0xfe, 0x3b,
                    0x9d, 0xfc, 0x2a, 0xaf, 0x20, 0x4c, 0xf0, 0xe1,
                    0xa3, 0xac, 0x3b, 0x42, 0x11, 0x61, 0x60, 0xf5,
                    0x82, 0x93, 0x06, 0x3c, 0x53, 0x5f, 0x44, 0x54,
                    0xcf, 0x7d, 0x96, 0xc0, 0xf2, 0x44, 0xe1, 0x03,
                    0x43, 0x9a, 0x4e, 0xc4, 0x7e, 0x16, 0xaf, 0x6f,
                    0xe2, 0x41, 0x84, 0x54, 0x82, 0x73, 0x0f, 0x48,
                    0x2e, 0xd3, 0x04, 0x40, 0x81, 0x97, 0x82, 0xf3,
                    0x49, 0x9f, 0x6d, 0xc5, 0x8f, 0x56, 0xc8, 0x45,
                    0x73, 0xf4, 0x39, 0x88, 0xbf, 0x6e, 0xe4, 0x39,
                    0x24, 0xaf, 0xaa, 0x13, 0xb3, 0x1b, 0x23, 0x9d,
                    0xee, 0xa2, 0xc4, 0xc1, 0x02, 0xec, 0xd6, 0xdf
                };

                if (cert_record->signature_key_size != known_signature_key_size) {
                    joy_log_err("signature key size does not match");
                    failed = 1;
                }

                if (cert_record->signature_length != known_signature_length) {
                    joy_log_err("signature length does not match");
                    failed = 1;
                }

                if (memcmp(cert_record->signature, known_signature, known_signature_length)) {
                    joy_log_err("signature data does not match");
                    failed = 1;
                }

                if (strncmp(cert_record->signature_algorithm, known_signature_algorithm, MAX_OPENSSL_STRING)) {
                    joy_log_err("signature algorithm does not match");
                    failed = 1;
                }

                if (failed){
                    /* There was at least one case that threw error */
                    joy_log_err("fail, tls_x509_get_signature - %s", filename);
                    num_fails++;
                }
            }
        }

        /*************************************
         * Test public key info
         ************************************/
        if (tls_x509_get_subject_pubkey_algorithm(cert, cert_record)) {
            joy_log_err("fail, tls_x509_get_subject_pubkey_algorithm - %s", filename);
            num_fails++;
        } else {
            if (!strncmp(filename, "dummy_cert_rsa2048.pem", max_filename_len)) {
                /* We are using the dummy_rsa2048 for this case */
                char *known_public_key_algorithm = "rsaEncryption";
                uint16_t known_public_key_size = 2048;
                int failed = 0;

                if (cert_record->subject_public_key_size != known_public_key_size) {
                    joy_log_err("public key size does not match");
                    failed = 1;
                }

                if (strncmp(cert_record->subject_public_key_algorithm, known_public_key_algorithm, MAX_OPENSSL_STRING)) {
                    joy_log_err("public key algorithm does not match");
                    failed = 1;
                }

                if (failed){
                    /* There was at least one case that threw error */
                    joy_log_err("fail, tls_x509_get_subject_pubkey_algorithm - %s", filename);
                    num_fails++;
                }
            }
        }

end_loop:
        /*
         * Cleanup
         */
        if (cert) {
            X509_free(cert);
            CRYPTO_cleanup_all_ex_data();
        }
        if (fp) {
            fclose(fp);
        }
        tls_delete(&tmp_tls_record);
    }

    return num_fails;
}

static unsigned char* tls_skip_packet_tcp_header(const unsigned char *packet_data,
                                                 unsigned int packet_len,
                                                 unsigned int *size_payload) {
    const struct ip_hdr *ip = NULL;
    unsigned int ip_hdr_len = 0;
    const struct tcp_hdr *tcp = NULL;
    unsigned int tcp_hdr_len = 0;
    unsigned char *payload = NULL;

    /* define/compute ip header offset */
    ip = (struct ip_hdr*)(packet_data + ETHERNET_HDR_LEN);
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

    tcp = (const struct tcp_hdr *)((unsigned char *)ip + ip_hdr_len);
    tcp_hdr_len = tcp_hdr_length(tcp);

    if (tcp_hdr_len < 20 || tcp_hdr_len > (packet_len - ip_hdr_len)) {
      joy_log_err("invalid tcp hdr length");
      return NULL;
    }

    /* define/compute tcp payload (segment) offset */
    payload = ((unsigned char *)tcp + tcp_hdr_len);

    /* compute tcp payload (segment) size */
    *size_payload = packet_len - ETHERNET_HDR_LEN - ip_hdr_len - tcp_hdr_len;

    return payload;
}

static int tls_test_extract_client_hello(const unsigned char *data,
                                         unsigned int data_len,
                                         char *filename) {
    struct tls_information *record = NULL;
    const struct tls_header *tls_hdr = NULL;
    const unsigned char *body = NULL;
    unsigned int body_len = 0;
    int num_fails = 0;

    tls_init(&record);

    tls_hdr = (const struct tls_header *)data;
    body_len = tls_handshake_get_length(&tls_hdr->handshake);
    body = &tls_hdr->handshake.body;

    if (body_len > data_len) {
        joy_log_err("handshake body length (%d) too long", body_len);
        num_fails++;
        goto end;
    }

    tls_handshake_hello_get_version(record, body);
    tls_client_hello_get_ciphersuites(body, body_len, record);
    tls_client_hello_get_extensions(body, body_len, record);

    if (!strcmp(filename, "sample_tls12_handshake_0.pcap")) {
        unsigned short known_ciphersuites_count = 15;
        unsigned short known_extensions_count = 11;
		/* windows compiler needs the constant and not the variable here */
		//struct tls_extension known_extensions[known_extensions_count];
		struct tls_extension known_extensions[11];
		int failed = 0;
        int i = 0;

        unsigned short known_ciphersuites[] = {49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161,
                                               49171, 49172, 51, 57, 47, 53, 10};

        unsigned char kat_data_0[] = {0x00, 0x13, 0x00, 0x00, 0x10, 0x77, 0x77, 0x77,
                                      0x2e, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f,
                                      0x6b, 0x2e, 0x63, 0x6f, 0x6d};
        unsigned char kat_data_3[] = {0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18,
                                      0x00, 0x19};
        unsigned char kat_data_4[] = {0x01, 0x00};
        unsigned char kat_data_6[] = {0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74,
                                      0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31};
        unsigned char kat_data_7[] = {0x01, 0x00, 0x00, 0x00, 0x00};
        unsigned char kat_data_10[] = {0x00, 0x16, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
                                       0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01,
                                       0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01};

        memset(known_extensions, 0, sizeof(known_extensions));

        /* Fill in the KAT extensions */
        known_extensions[0].type = 0x0000;
        known_extensions[0].length = 21;
        known_extensions[0].data = calloc(known_extensions[0].length, sizeof(unsigned char));
        memcpy(known_extensions[0].data, kat_data_0, known_extensions[0].length);

        known_extensions[1].type = 0x0017;
        known_extensions[1].length = 0;

        known_extensions[2].type = 0xff01;
        known_extensions[2].length = 1;
        known_extensions[2].data = calloc(known_extensions[2].length, sizeof(unsigned char));

        known_extensions[3].type = 0x000a;
        known_extensions[3].length = 10;
        known_extensions[3].data = calloc(known_extensions[3].length, sizeof(unsigned char));
        memcpy(known_extensions[3].data, kat_data_3, known_extensions[3].length);

        known_extensions[4].type = 0x000b;
        known_extensions[4].length = 2;
        known_extensions[4].data = calloc(known_extensions[4].length, sizeof(unsigned char));
        memcpy(known_extensions[4].data, kat_data_4, known_extensions[4].length);

        known_extensions[5].type = 0x0023;
        known_extensions[5].length = 0;

        known_extensions[6].type = 0x0010;
        known_extensions[6].length = 14;
        known_extensions[6].data = calloc(known_extensions[6].length, sizeof(unsigned char));
        memcpy(known_extensions[6].data, kat_data_6, known_extensions[6].length);

        known_extensions[7].type = 0x0005;
        known_extensions[7].length = 5;
        known_extensions[7].data = calloc(known_extensions[7].length, sizeof(unsigned char));
        memcpy(known_extensions[7].data, kat_data_7, known_extensions[7].length);

        known_extensions[8].type = 0x0012;
        known_extensions[8].length = 0;

        known_extensions[9].type = 0xff03;
        known_extensions[9].length = 0;

        known_extensions[10].type = 0x000d;
        known_extensions[10].length = 24;
        known_extensions[10].data = calloc(known_extensions[10].length, sizeof(unsigned char));
        memcpy(known_extensions[10].data, kat_data_10, known_extensions[10].length);

        if (record->num_ciphersuites != known_ciphersuites_count) {
            joy_log_err("ciphersuites count does not match")
            failed = 1;
        } else {
            for (i = 0; i < known_ciphersuites_count; i++) {
                if (record->ciphersuites[i] != known_ciphersuites[i]) {
                    joy_log_err("ciphersuite[%d] does not match", i)
                    failed = 1;
                }
            }
        }

        if (record->num_tls_extensions != known_extensions_count) {
            joy_log_err("extensions count does not match")
            failed = 1;
        } else {
            for (i = 0; i < known_extensions_count; i++) {
                /*
                 * KAT
                 */
                if (known_extensions[i].type != record->tls_extensions[i].type) {
                    joy_log_err("extension[%d] type does not match", i)
                    failed = 1;
                }

                if (known_extensions[i].length != record->tls_extensions[i].length) {
                    joy_log_err("extension[%d] length does not match", i)
                    failed = 1;
                }

                if (known_extensions[i].data) {
                    if (memcmp(known_extensions[i].data, record->tls_extensions[i].data,
                               known_extensions[i].length)) {
                        joy_log_err("extension[%d] data does not match", i)
                        failed = 1;
                    }

                    /* Free the temporary allocated data */
                    free(known_extensions[i].data);
                }
            }
        }

        if (failed) {
            joy_log_err("fail, tls_test_extract_client_hello - %s", filename);
            num_fails++;
        }
    }

end:
    /* Cleanup */
    tls_delete(&record);

    return num_fails;
}

static int tls_test_extract_server_hello(const unsigned char *data,
                                         unsigned int data_len,
                                         const char *filename) {
    struct tls_information *record = NULL;
    const struct tls_header *tls_hdr = NULL;
    const unsigned char *body = NULL;
    unsigned int body_len = 0;
    int num_fails = 0;

    tls_init(&record);

    tls_hdr = (const struct tls_header *)data;
    body_len = tls_handshake_get_length(&tls_hdr->handshake);
    body = &tls_hdr->handshake.body;

    if (body_len > data_len) {
        joy_log_err("handshake body length (%d) too long", body_len);
        num_fails++;
        goto end;
    }

    tls_handshake_hello_get_version(record, body);
    tls_server_hello_get_ciphersuite(body, body_len, record);
    tls_server_hello_get_extensions(body, body_len, record);

    if (!strcmp(filename, "sample_tls12_handshake_0.pcap")) {
        unsigned short known_extensions_count = 5;
        unsigned short known_ciphersuite = 0xc02b;
		/* windows compiler needs the constant and not the variable here */
		//struct tls_extension known_extensions[known_extensions_count];
		struct tls_extension known_extensions[5];
		int failed = 0;
        int i = 0;

        unsigned char kat_data_2[] = {0x03, 0x00, 0x01, 0x02};
        unsigned char kat_data_4[] = {0x00, 0x03, 0x02, 0x68, 0x32};

        memset(known_extensions, 0, sizeof(known_extensions));

        /* Fill in the KAT extensions */
        known_extensions[0].type = 0x0000;
        known_extensions[0].length = 0;

        known_extensions[1].type = 0xff01;
        known_extensions[1].length = 1;
        known_extensions[1].data = calloc(known_extensions[1].length, sizeof(unsigned char));

        known_extensions[2].type = 0x000b;
        known_extensions[2].length = 4;
        known_extensions[2].data = calloc(known_extensions[2].length, sizeof(unsigned char));
        memcpy(known_extensions[2].data, kat_data_2, known_extensions[2].length);

        known_extensions[3].type = 0x0023;
        known_extensions[3].length = 0;

        known_extensions[4].type = 0x0010;
        known_extensions[4].length = 5;
        known_extensions[4].data = calloc(known_extensions[4].length, sizeof(unsigned char));
        memcpy(known_extensions[4].data, kat_data_4, known_extensions[4].length);

        if (record->ciphersuites[0] != known_ciphersuite) {
            joy_log_err("ciphersuite does not match")
            failed = 1;
        }

        if (record->num_server_tls_extensions != known_extensions_count) {
            joy_log_err("extensions count does not match")
            failed = 1;
        } else {
            for (i = 0; i < known_extensions_count; i++) {
                /*
                 * KAT
                 */
                if (known_extensions[i].type != record->server_tls_extensions[i].type) {
                    joy_log_err("extension[%d] type does not match", i)
                    failed = 1;
                }

                if (known_extensions[i].length != record->server_tls_extensions[i].length) {
                    joy_log_err("extension[%d] length does not match", i)
                    failed = 1;
                }

                if (known_extensions[i].data) {
                    if (memcmp(known_extensions[i].data, record->server_tls_extensions[i].data,
                               known_extensions[i].length)) {
                        joy_log_err("extension[%d] data does not match", i)
                        failed = 1;
                    }

                    /* Free the temporary allocated data */
                    free(known_extensions[i].data);
                }
            }
        }

        if (failed) {
            joy_log_err("fail, tls_test_extract_server_hello - %s", filename);
            num_fails++;
        }
    }

end:
    /* Cleanup */
    tls_delete(&record);

    return num_fails;
}

static int tls_test_initial_handshake() {
    pcap_t *pcap_handle = NULL;
    struct pcap_pkthdr header;
    const unsigned char *pkt_ptr = NULL;
    const unsigned char *payload_ptr = NULL;
    unsigned int payload_len = 0;
    char *filename = "sample_tls12_handshake_0.pcap";
    int num_fails = 0;

    pcap_handle = joy_utils_open_test_pcap(filename);
    if (!pcap_handle) {
        joy_log_err("fail, unable to open %s", filename);
        num_fails++;
        goto end;
    }

    /* Test the client hello extraction */
    pkt_ptr = pcap_next(pcap_handle, &header);
    payload_ptr = tls_skip_packet_tcp_header(pkt_ptr, header.len, &payload_len);
    num_fails += tls_test_extract_client_hello(payload_ptr, payload_len, filename);

    /* Test the server hello extraction */
    pkt_ptr = pcap_next(pcap_handle, &header);
    payload_ptr = tls_skip_packet_tcp_header(pkt_ptr, header.len, &payload_len);
    num_fails += tls_test_extract_server_hello(payload_ptr, payload_len, filename);

    /* Certificate packet */
    pkt_ptr = pcap_next(pcap_handle, &header);
    payload_ptr = tls_skip_packet_tcp_header(pkt_ptr, header.len, &payload_len);

end:
    if (pcap_handle) {
        pcap_close(pcap_handle);
    }

    return num_fails;
}

/*
 * \brief Unit test for tls_handshake_hello_get_version().
 *
 * \return 0 for success, otherwise number of failures
 */
static int tls_test_handshake_hello_get_version() {
    struct tls_information *record = NULL;
    unsigned char ssl_v3[] = {0x03, 0x00};
    unsigned char tls_1_0[] = {0x03, 0x01};
    unsigned char tls_1_1[] = {0x03, 0x02};
    unsigned char tls_1_2[] = {0x03, 0x03};
    unsigned char tls_1_3[] = {0x03, 0x04};
    int num_fails = 0;

    tls_init(&record);

    tls_handshake_hello_get_version(record, ssl_v3);
    if (record->tls_v != TLS_VERSION_SSLV3) {
        joy_log_err("fail, sslv3 version capture");
        num_fails++;
    }

    tls_handshake_hello_get_version(record, tls_1_0);
    if (record->tls_v != TLS_VERSION_1_0) {
        joy_log_err("fail, tls 1.0 version capture");
        num_fails++;
    }

    tls_handshake_hello_get_version(record, tls_1_1);
    if (record->tls_v != TLS_VERSION_1_1) {
        joy_log_err("fail, tls 1.1 version capture");
        num_fails++;
    }

    tls_handshake_hello_get_version(record, tls_1_2);
    if (record->tls_v != TLS_VERSION_1_2) {
        joy_log_err("fail, tls 1.2 version capture");
        num_fails++;
    }

    tls_handshake_hello_get_version(record, tls_1_3);
    if (record->tls_v != TLS_VERSION_1_3) {
        joy_log_err("fail, tls 1.3 version capture");
        num_fails++;
    }

    tls_delete(&record);

    return num_fails;
}

static int tls_test_calculate_handshake_length() {
    struct tls_handshake hand;
    unsigned int result = 0;
    int num_fails = 0;

    hand.lengthHi = 0x00;
    hand.lengthMid = 0x00;
    hand.lengthLo = 0x01;
    result = tls_handshake_get_length(&hand);
    if (result != 1) {
        joy_log_err("fail, expected (%d), got (%d)", 1, result);
        num_fails++;
    }

    hand.lengthHi = 0x00;
    hand.lengthMid = 0xff;
    hand.lengthLo = 0xff;
    result = tls_handshake_get_length(&hand);
    if (result != 65535) {
        joy_log_err("fail, expected (%d), got (%d)", 65535, result);
        num_fails++;
    }

    hand.lengthHi = 0xff;
    hand.lengthMid = 0xff;
    hand.lengthLo = 0xff;
    result = tls_handshake_get_length(&hand);
    if (result != 16777215) {
        joy_log_err("fail, expected (%d), got (%d)", 16777215, result);
        num_fails++;
    }

    hand.lengthHi = 0x00;
    hand.lengthMid = 0x00;
    hand.lengthLo = 0x00;
    result = tls_handshake_get_length(&hand);
    if (result != 0) {
        joy_log_err("fail, expected (%d), got (%d)", 0, result);
        num_fails++;
    }

    return num_fails;
}

void tls_unit_test() {
    int num_fails = 0;

    if (tls_fingerprint_db_loaded == 0) {
        /* Attempt to load in the TLS fingerprints for testing */
        tls_load_fingerprints();
    }

    fprintf(info, "\n******************************\n");
    fprintf(info, "TLS Unit Test starting...\n");

    num_fails += tls_test_handshake_hello_get_version();

    num_fails += tls_test_calculate_handshake_length();

    num_fails += tls_test_client_fingerprint_match();

    num_fails += tls_test_initial_handshake();

    num_fails += tls_test_certificate_parsing();

    if (num_fails) {
        fprintf(info, "Finished - # of failures: %d\n", num_fails);
    } else {
        fprintf(info, "Finished - success\n");
    }
    fprintf(info, "******************************\n\n");
}

