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
#include <netinet/in.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include "tls.h"
#include "parson.h"
#include "fingerprint.h"

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

/** sends information to the destination output device */
#define loginfo(...) { \
        if (TO_SCREEN) print_dest = stderr; else print_dest = info; \
        fprintf(print_dest,"%s: ", __FUNCTION__); \
        fprintf(print_dest, __VA_ARGS__); \
        fprintf(print_dest, "\n"); }

#define JOY_TLS_DEBUG 0

/*
 * The maxiumum allowed length of a serial number is 20 octets
 * according to RFC5290 section 4.1.2.2. We give some leeway
 * for any non-conforming certificates.
 */
#define MAX_CERT_SERIAL_LENGTH 24

/*
 * External objects, defined in joy.c
 */
extern char *tls_fingerprint_file;

/* Store the tls_fingerprint.json data */
static fingerprint_db_t tls_fingerprint_db;
static uint8_t tls_fingerprint_db_loaded = 0;

/* Local prototypes */
static int tls_certificate_process(const void *data, int data_len, struct tls_information *tls_info);
static int tls_header_version_capture(struct tls_information *tls_info, const struct tls_header *tls_hdr);
static void tls_certificate_printf(const struct tls_certificate *data, zfile f);


/*
 * Inline functions
 */
static inline unsigned int timer_lt_tls (const struct timeval *a, const struct timeval *b) {
    return (a->tv_sec == b->tv_sec) ? (a->tv_usec < b->tv_usec) : (a->tv_sec < b->tv_sec);
}

static inline void timer_sub_tls (const struct timeval *a, const struct timeval *b, struct timeval *result)  {
    result->tv_sec = a->tv_sec - b->tv_sec;        
    result->tv_usec = a->tv_usec - b->tv_usec;     
    if (result->tv_usec < 0) {                         
        --result->tv_sec;                                
        result->tv_usec += 1000000;                      
    }                                                    
}

static inline void timer_clear_tls (struct timeval *a) {
    a->tv_sec = a->tv_usec = 0; 
}

static unsigned int timeval_to_milliseconds_tls (struct timeval ts) {
    unsigned int result = ts.tv_usec / 1000 + ts.tv_sec * 1000;
    return result;
}

/**
 * \fn void tls_init (struct tls_information *r)
 *
 * \brief Initialize the memory of TLS struct \r.
 *
 * \param r TLS record structure pointer
 *
 * \return
 */
void tls_init (struct tls_information *r) {
    int i;

    r->role = role_unknown;
    r->tls_op = 0;
    r->num_ciphersuites = 0;
    r->num_tls_extensions = 0;
    r->num_server_tls_extensions = 0;
    r->tls_sid_len = 0;
    r->tls_v = 0;
    r->tls_client_key_length = 0;
    r->certificate_buffer = 0;
    r->certificate_offset = 0;
    r->start_cert = 0;
    r->sni = 0;
    r->sni_length = 0;

    memset(r->tls_len, 0, sizeof(r->tls_len));
    memset(r->tls_time, 0, sizeof(r->tls_time));
    memset(r->tls_type, 0, sizeof(r->tls_type));
    memset(r->ciphersuites, 0, sizeof(r->ciphersuites));
    memset(r->tls_extensions, 0, sizeof(r->tls_extensions));
    memset(r->server_tls_extensions, 0, sizeof(r->server_tls_extensions));
    memset(r->tls_sid, 0, sizeof(r->tls_sid));
    memset(r->tls_random, 0, sizeof(r->tls_random));

    r->num_certificates = 0;
    for (i = 0; i < MAX_CERTIFICATES; i++) {
        struct tls_certificate *cert = &r->certificates[i];

        cert->length = 0;
        cert->signature = NULL;
        cert->signature_length = 0;
        memset(cert->signature_algorithm, 0,
               sizeof(cert->signature_algorithm));
        memset(cert->subject_public_key_algorithm, 0,
               sizeof(cert->signature_algorithm));
        cert->subject_public_key_size = 0;
        cert->signature_key_size = 0;
        cert->serial_number = NULL;
        cert->serial_number_length = 0;
        cert->validity_not_before = NULL;
        cert->validity_not_before_length = 0;
        cert->validity_not_after = NULL;
        cert->validity_not_after_length = 0;
        cert->num_issuer_items = 0;
        cert->num_subject_items = 0;
        cert->num_extension_items = 0;
        memset(cert->issuer, 0, sizeof(cert->issuer));
        memset(cert->subject, 0, sizeof(cert->subject));
        memset(cert->extensions, 0, sizeof(cert->extensions));
    }
}

/**
 * \fn void tls_delete (struct tls_information *r)
 *
 * \brief Clear and free memory of TLS struct \r.
 *
 * \param r TLS record structure pointer
 *
 * \return
 */
void tls_delete (struct tls_information *r) {
    int i, j = 0;

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
 * \brief Calculate the body length encoded in the TLS header.
 *
 * \param hdr TLS header structure pointer
 *
 * \return Length of the body.
 */
static unsigned int tls_header_get_length (const struct tls_header *hdr) {
    return hdr->lengthLo + (((unsigned int) hdr->lengthMid) << 8);
}

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

static void tls_client_hello_get_extensions (const void *x,
                                             int len,
                                             struct tls_information *r) {
    unsigned int session_id_len, compression_method_len;
    const unsigned char *y = x;
    unsigned short int cipher_suites_len, extensions_len;
    unsigned int i = 0;


    len -= 4; // get handshake message length
    /* Check the TLS version */
    if (!r->tls_v) {
        /* Unsupported version */
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
        byte_len = (unsigned int)h->lengthLo + 
            (unsigned int)h->lengthMid*256 + 
            (unsigned int)h->lengthHi*256*256;
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
    ASN1_TIME *not_before = NULL;
    ASN1_TIME *not_after = NULL;
    unsigned char *not_before_data_str = NULL;
    unsigned char *not_after_data_str = NULL;
    int not_before_data_len = 0;
    int not_after_data_len = 0;
    int rc_not_before = 1;
    int rc_not_after = 1;

    not_before = X509_get_notBefore(cert);
    not_after = X509_get_notAfter(cert);

    if (not_before != NULL) {
        /* Get the time data */
        not_before_data_str = ASN1_STRING_data(not_before);
        /* Get the length of the data */
        not_before_data_len = ASN1_STRING_length(not_before);

        if (not_before_data_len > 0) {
            /* Prepare the record */
            record->validity_not_before = malloc(not_before_data_len);
            record->validity_not_before_length = not_before_data_len;
            /* Copy notBefore into record */
            memcpy(record->validity_not_before, not_before_data_str,
                   not_before_data_len);

            /* Success */
            rc_not_before = 0;
        } else {
           if (JOY_TLS_DEBUG) {
               loginfo("warning: no data exists for notBefore");
           }
        }
    } else {
        if (JOY_TLS_DEBUG) {
            loginfo("warning: could not extract notBefore");
        }
    }

    if (not_after != NULL) {
        /* Get the time data */
        not_after_data_str = ASN1_STRING_data(not_after);
        /* Get the length of the data */
        not_after_data_len = ASN1_STRING_length(not_after);

        if (not_after_data_len > 0) {
            /* Prepare the record */
            record->validity_not_after = malloc(not_after_data_len);
            record->validity_not_after_length = not_after_data_len;
            /* Copy notAfter into record */
            memcpy(record->validity_not_after, not_after_data_str,
                   not_after_data_len);

            /* Success */
            rc_not_after = 0;
        } else {
           if (JOY_TLS_DEBUG) {
               loginfo("warning: no data exists for notAfter");
           }
        }
    } else {
        if (JOY_TLS_DEBUG) {
            loginfo("warning: could not extract notAfter");
        }
    }

    if (!rc_not_before || !rc_not_after) {
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
    ASN1_STRING *entry_asn1_string = NULL;
    ASN1_OBJECT *entry_asn1_object = NULL;
    unsigned char *entry_data_str = NULL;
    int entry_data_len = 0;
    int nid = 0;
    int num_of_entries = 0;
    int i = 0;

    subject = X509_get_subject_name(cert);
    if (subject == NULL) {
        if (JOY_TLS_DEBUG) {
            loginfo("warning: could not extract subject");
        }
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
            if (JOY_TLS_DEBUG) {
                loginfo("warning: hit max entry threshold of %d",
                        MAX_RDN);
            }
            break;
        }

        /* Current subject entry */
        entry = X509_NAME_get_entry(subject, i);
        entry_asn1_object = X509_NAME_ENTRY_get_object(entry);
        entry_asn1_string = X509_NAME_ENTRY_get_data(entry);

        /* Get the info out of asn1_string */
        entry_data_str = ASN1_STRING_data(entry_asn1_string);
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
        /* Null-terminated in case it's used as a string */
        cert_record_entry->data[entry_data_len] = 0;
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
    ASN1_STRING *entry_asn1_string = NULL;
    ASN1_OBJECT *entry_asn1_object = NULL;
    unsigned char *entry_data_str = NULL;
    int entry_data_len = 0;
    int nid = 0;
    int num_of_entries = 0;
    int i = 0;

    issuer = X509_get_issuer_name(cert);
    if (issuer == NULL) {
        if (JOY_TLS_DEBUG) {
            loginfo("warning: could not extract issuer");
        }
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
            if (JOY_TLS_DEBUG) {
                loginfo("warning: hit max entry threshold of %d",
                        MAX_RDN);
            }
            break;
        }

        /* Current issuer entry */
        entry = X509_NAME_get_entry(issuer, i);
        entry_asn1_object = X509_NAME_ENTRY_get_object(entry);
        entry_asn1_string = X509_NAME_ENTRY_get_data(entry);

        /* Get the info out of asn1_string */
        entry_data_str = ASN1_STRING_data(entry_asn1_string);
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
        /* Null-terminated in case it's used as a string */
        cert_record_entry->data[entry_data_len] = 0;
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
    ASN1_INTEGER *serial = NULL;
    unsigned char *serial_data = NULL;
    uint16_t serial_data_length = 0;

    serial = X509_get_serialNumber(cert);
    if (serial == NULL) {
        if (JOY_TLS_DEBUG) {
            loginfo("warning: could not extract serial");
        }
        return 1;
    }

    serial_data = ASN1_STRING_data(serial);
    serial_data_length = ASN1_STRING_length(serial);

    if (serial_data_length > MAX_CERT_SERIAL_LENGTH) {
        /* This serial number is abnormally large */
        if (JOY_TLS_DEBUG) {
            loginfo("warning: serial number is too large");
        }
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
    X509_PUBKEY *pubkey = NULL;
    ASN1_OBJECT *algorithm_asn1_obj = NULL;
    ASN1_BIT_STRING *pubkey_asn1_string = NULL;
    const char *pubkey_alg_str = NULL;
    int pubkey_length = 0;
    int nid = 0;

    /*
     * Get the X509 public key.
     */
    pubkey = X509_get_X509_PUBKEY(cert);
    if (pubkey == NULL) {
        if (JOY_TLS_DEBUG) {
            loginfo("warning: could not extract public key");
        }
        return 1;
    }

    algorithm_asn1_obj = pubkey->algor->algorithm;
    if (algorithm_asn1_obj == NULL) {
        if (JOY_TLS_DEBUG) {
            loginfo("warning: problem getting public key algorithm");
        }
        return 1;
    }

    /* Look at the actual public key embedded data */
    pubkey_asn1_string = pubkey->public_key;
    pubkey_length = ASN1_STRING_length(pubkey_asn1_string);

    /* Get the NID of the public key algorithm */
    nid = OBJ_obj2nid(algorithm_asn1_obj);

    /* Write the key size */
    record->subject_public_key_size = pubkey_length << 3;

    if (nid == NID_undef) {
        /*
         * The NID is unknown, so instead we will copy the OID.
         * The OID can be looked-up online to find the name.
         */
        OBJ_obj2txt(record->subject_public_key_algorithm,
                    MAX_OPENSSL_STRING, algorithm_asn1_obj, 1);
        /* Ensure null-termination */
        record->subject_public_key_algorithm[MAX_OPENSSL_STRING - 1] = '\0';
    } else {
        pubkey_alg_str = OBJ_nid2ln(nid);
        /* Copy the public key algorithm string */
        strncpy(record->subject_public_key_algorithm, pubkey_alg_str,
                MAX_OPENSSL_STRING);
        /* Ensure null-termination */
        record->subject_public_key_algorithm[MAX_OPENSSL_STRING - 1] = '\0';
    }

    return 0;
}

/**
 * \fn int tls_x509_get_signature_algorithm(X509 *cert,
 *                                          struct tls_certificate *record)
 *
 * \brief Extract the signature algorithm type out of a X509 certificate.
 *
 * \param cert OpenSSL X509 certificate structure.
 * \param record Destination tls_certificate structure
 *               that will be written into.
 *
 * \return 0 for success, 1 for failure
 */
static int tls_x509_get_signature_algorithm(X509 *cert,
                                            struct tls_certificate *record) {
    ASN1_OBJECT *sig_alg_asn1_obj = NULL;
    const char *sig_alg_str = NULL;
    int nid = 0;

    /*
     * Get the signature algorithm asn1_object
     * directly out of the X509 struct.
     */
    sig_alg_asn1_obj = cert->sig_alg->algorithm;
    if (sig_alg_asn1_obj == NULL) {
        if (JOY_TLS_DEBUG) {
            loginfo("warning: problem getting signature algorithm");
        }
        return 1;
    }

    /* Get the NID of the asn1_object */
    nid = OBJ_obj2nid(sig_alg_asn1_obj);

    if (nid == NID_undef) {
        /*
         * The NID is unknown, so instead we will copy the OID.
         * The OID can be looked-up online to find the name.
         */
        OBJ_obj2txt(record->signature_algorithm,
                    MAX_OPENSSL_STRING, sig_alg_asn1_obj, 1);
        /* Ensure null-termination */
        record->signature_algorithm[MAX_OPENSSL_STRING - 1] = '\0';
    } else {
        sig_alg_str = OBJ_nid2ln(nid);
        strncpy(record->signature_algorithm, sig_alg_str,
                MAX_OPENSSL_STRING);
        /* Ensure null-termination */
        record->signature_algorithm[MAX_OPENSSL_STRING - 1] = '\0';
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
    ASN1_BIT_STRING *sig = NULL;
    unsigned char *sig_str = NULL;
    int sig_length = 0;

    sig = cert->signature;
    if (sig == NULL) {
        if (JOY_TLS_DEBUG) {
            loginfo("warning: problem getting signature");
        }
        return 1;
    }

    sig_str = ASN1_STRING_data(sig);
    sig_length = ASN1_STRING_length(sig);

    if (sig_length > 512) {
        /*
         * We shouldn't be seeing any signatures larger than this.
         * Using 4096 bits (512 bytes) as the standard for upper threshold.
         */
        if (JOY_TLS_DEBUG) {
            loginfo("warning: signature is too large");
        }
        return 1;
    } else {
        /* Multiply by 8 to get the number of bits */
        record->signature_key_size = sig_length << 3;
    }

    record->signature = malloc(sig_length);
    memcpy(record->signature, sig_str, sig_length);
    record->signature_length = sig_length;

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
    ASN1_OCTET_STRING *ext_asn1_string = NULL;
    unsigned char *ext_data_str = NULL;
    int ext_data_len = 0;
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
        const char *ext_name_str = NULL;
        struct tls_item_entry *cert_record_entry = &record->extensions[i];

        if (i == MAX_CERT_EXTENSIONS) {
            /* Best effort, got as many as we could */
            if (JOY_TLS_DEBUG) {
                loginfo("warning: hit max extension threshold of %d",
                        MAX_CERT_EXTENSIONS);
            }
            break;
        }

        /* Current extension */
        extension = X509_get_ext(cert, i);
        ext_asn1_object = X509_EXTENSION_get_object(extension);
        ext_asn1_string = X509_EXTENSION_get_data(extension);
        ext_data_str = ASN1_STRING_data(ext_asn1_string);
        ext_data_len = ASN1_STRING_length(ext_asn1_string);

        /* NID of the asn1_object */
        nid = OBJ_obj2nid(ext_asn1_object);

        /*
         * Prepare the extension entry in the certificate record.
         */
        cert_record_entry->data = malloc(ext_data_len);
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

        memcpy(cert_record_entry->data, ext_data_str, ext_data_len);
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

    if (JOY_TLS_DEBUG) {
        loginfo("all certificates length: %d", total_certs_len);
    }

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

        /* The index to retrieve the proper certificate record */
        index_cert = r->num_certificates;
        r->num_certificates += 1;

        /* Point to the current certificate record */
        certificate = &r->certificates[index_cert];

        /* Current certificate length */
        cert_len = raw_to_unsigned_short(data + 1);
        certificate->length = cert_len;

        /* Move past the cert_len */
        data += 3;
        remaining_certs_len -= 3;

        if (JOY_TLS_DEBUG) {
            loginfo("current certificate length: %d", cert_len);
        }

        ptr_openssl = data;
        /* Convert to OpenSSL X509 object */
        x509_cert = d2i_X509(NULL, &ptr_openssl, (size_t)cert_len);

        if (x509_cert == NULL) {
            loginfo("Failed cert conversion");
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

            /* Get signature algorithm */
            tls_x509_get_signature_algorithm(x509_cert, certificate);

            /* Get signature */
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
        }

        if (rc) {
            return;
        }
#if 0
        // parse serial number
        tmp_len = (*y);
        if (tmp_len > 50) {
            rc = 1;
            goto cleanup;
        }
        r->certificates[cur_cert].serial_number = malloc(tmp_len);
        memcpy(r->certificates[cur_cert].serial_number, y+1, tmp_len);
        r->certificates[cur_cert].serial_number_length = tmp_len;
        //printf("\tserial_number: ");
        //printf_raw_as_hex_tls(r->certificates[cur_cert].serial_number, tmp_len);
        //printf("\n");
        y += tmp_len+1;
        certs_len -= tmp_len+1;
        y += 2;
        certs_len -= 2;

        // parse signature
        tmp_len = *(y+1);
        if (tmp_len > 50) {
            rc = 1;
            goto cleanup;
        }
        y += 2;
        certs_len -= 2;
        r->certificates[cur_cert].signature = malloc(tmp_len);
        memcpy(r->certificates[cur_cert].signature, y, tmp_len); 
        r->certificates[cur_cert].signature_length = tmp_len;
        //printf("\tsignature_algorithm: ");
        //printf_raw_as_hex_tls(r->certificates[cur_cert].signature, tmp_len);
        //printf("\n");
        y += tmp_len;
        certs_len -= tmp_len;
        y += 2;
        certs_len -= 2;

        // parse issuer
        cur_rdn = 0;
        issuer_len = *(y+1);
        if (issuer_len == 129) {
            issuer_len = *(y+2);
            y += 5;
            certs_len -= 5;
        } else if (issuer_len == 130) {
            issuer_len = raw_to_unsigned_short(y+2);
            y += 6;
            certs_len -= 6;
        } else {
            y += 4;
            certs_len -= 4;
        }
        while (issuer_len > 0) {
            if (cur_rdn >= MAX_RDN) {
	            break;
            }
            rdn_seq_len = *(y+1);
            y += 2;
            certs_len -= 2;
            issuer_len -= 2;
      
            tmp_len = *(y+1);
            //if (tmp_len > 50) {return;}
            r->certificates[cur_cert].issuer_id[cur_rdn] = malloc(tmp_len);
            memcpy(r->certificates[cur_cert].issuer_id[cur_rdn], y+2, tmp_len);
            r->certificates[cur_cert].issuer_id_length[cur_rdn] = tmp_len;
            //printf("\tissuer_id: ");
            //printf_raw_as_hex_tls(r->certificates[cur_cert].issuer_id[cur_rdn], tmp_len);
            //printf("\n");
          
            tmp_len2 = *(y+tmp_len+2+1);
            if (tmp_len2 > 100) {
                rc = 1;
                goto cleanup;
            }
            r->certificates[cur_cert].issuer_string[cur_rdn] = malloc(tmp_len2+1);
            memset(r->certificates[cur_cert].issuer_string[cur_rdn], '\0', tmp_len2+1);
            memcpy(r->certificates[cur_cert].issuer_string[cur_rdn], y+tmp_len+2+2, tmp_len2);
            //r->certificates[cur_cert].issuer_string_length[cur_rdn] = tmp_len2;
            //printf("\tissuer_string: \"%s\"\n", (char*)r->certificates[cur_cert].issuer_string[cur_rdn]);

            y += 2;
            certs_len -= 2;
            issuer_len -= 2;
            y += rdn_seq_len;
            certs_len -= rdn_seq_len;
            issuer_len -= rdn_seq_len;
            cur_rdn++;
            r->certificates[cur_cert].num_issuer = cur_rdn;
        }
    
        // validity_not_before
        //	  tmp_len = *(y+1);
    
        //y += 2;
        //certs_len -= 2;
        tmp_len = *(y+1);
        y += 2;
        certs_len -= 2;
        if (tmp_len > 50) {
            rc = 1;
            goto cleanup;
        }
        r->certificates[cur_cert].validity_not_before = malloc(tmp_len+1);
        memset(r->certificates[cur_cert].validity_not_before, '\0', tmp_len+1);
        memcpy(r->certificates[cur_cert].validity_not_before, y, tmp_len); 
        //printf("\tvalidity_not_before: \"%s\"\n", (char *)r->certificates[cur_cert].validity_not_before);
        y += tmp_len;
        certs_len -= tmp_len;
        // validity_not_after
        tmp_len = *(y+1);
        y += 2;
        certs_len -= 2;
        if (tmp_len > 50) {
            rc = 1;
            goto cleanup;
        }
        r->certificates[cur_cert].validity_not_after = malloc(tmp_len+1);
        memset(r->certificates[cur_cert].validity_not_after, '\0', tmp_len+1);
        memcpy(r->certificates[cur_cert].validity_not_after, y, tmp_len); 
        //printf("\tvalidity_not_after: \"%s\"\n", (char *)r->certificates[cur_cert].validity_not_after);
        y += tmp_len;
        certs_len -= tmp_len;

        // parse subject
        cur_rdn = 0;
        subject_len = *(y+1);
        if (subject_len == 129) {
          subject_len = *(y+2);
          y += 5;
          certs_len -= 5;
        } else if (subject_len == 130) {
          subject_len = raw_to_unsigned_short(y+2);
          y += 6;
          certs_len -= 6;
        } else {
          y += 4;
          certs_len -= 4;
        }
    
        while (subject_len > 0) {
            if (cur_rdn >= MAX_RDN) {
	            break;
            }
            rdn_seq_len = *(y+1);
            y += 2;
            certs_len -= 2;
            subject_len -= 2;
      
            tmp_len = *(y+1);
            if (tmp_len > 150) {
                rc = 1;
                goto cleanup;
            }
            r->certificates[cur_cert].subject_id[cur_rdn] = malloc(tmp_len);
            memcpy(r->certificates[cur_cert].subject_id[cur_rdn], y+2, tmp_len);
            r->certificates[cur_cert].subject_id_length[cur_rdn] = tmp_len;
            //printf("\tsubject_id: ");
            //printf_raw_as_hex_tls(r->certificates[cur_cert].subject_id[cur_rdn], tmp_len);
            //printf("\n");
      
            tmp_len2 = *(y+tmp_len+2+1);
            //if (tmp_len2 > 50) {return;}
            r->certificates[cur_cert].subject_string[cur_rdn] = malloc(tmp_len2+1);
            memset(r->certificates[cur_cert].subject_string[cur_rdn], '\0', tmp_len2+1);
            memcpy(r->certificates[cur_cert].subject_string[cur_rdn], y+tmp_len+2+2, tmp_len2);
            //printf("\tsubject_string: \"%s\"\n", (char*)r->certificates[cur_cert].subject_string[cur_rdn]);

            y += 2;
            certs_len -= 2;
            subject_len -= 2;
            y += rdn_seq_len;
            certs_len -= rdn_seq_len;
            subject_len -= rdn_seq_len;
            cur_rdn++;
            r->certificates[cur_cert].num_subject = cur_rdn;
        }
    
        //printf("\tNext Three Bytes: ");
        //printf_raw_as_hex_tls(y, 3);
        //printf("\n");
    
        // parse subject public key info
        if (*(y+1) == 48) {
            y += 3;
            certs_len -= 3;
        } else {
            y += 4;
            certs_len -= 4;
        }
        tmp_len = *(y+1);
        y += 2;
        certs_len -= 2;
        if (tmp_len > 50) {
            rc = 1;
            goto cleanup;
        }
        r->certificates[cur_cert].subject_public_key_algorithm = malloc(tmp_len);
        memcpy(r->certificates[cur_cert].subject_public_key_algorithm, y, tmp_len); 
        r->certificates[cur_cert].subject_public_key_algorithm_length = tmp_len;
        //printf("\tsubject_public_key_algorithm: ");
        //printf_raw_as_hex_tls(r->certificates[cur_cert].subject_public_key_algorithm, tmp_len);
        //printf("\n");
        y += tmp_len;
        certs_len -= tmp_len;
        y += 2;
        certs_len -= 2;
    
        if (*(y+1) == 129) {
            tmp_len = *(y+2);
            r->certificates[cur_cert].subject_public_key_size = (tmp_len-13)*8;
            //printf("\tsubject_public_key_size: %i\n", (tmp_len-13)*8);
            //tmp_len -= 13;
            y += tmp_len+3;
            certs_len -= tmp_len+3;
        } else if (*(y+1) == 130) {
            tmp_len = raw_to_unsigned_short(y+2);
            r->certificates[cur_cert].subject_public_key_size = (tmp_len-15)*8;
            //printf("\tsubject_public_key_size: %i\n", (tmp_len-15)*8);
            //tmp_len -= 15;
            y += tmp_len+4;
            certs_len -= tmp_len+4;	    
        } else {
            break ;
        }
    
    
        // optional: parse extensions
        if (*y == 163) {
            if (*(y+1) == 130) {
	            y += 5;
	            certs_len -= 5;
            } else if (*(y+1) == 129) {
	            y += 4;
	            certs_len -= 4;
            }
      
            if (*y == 130) {
	            ext_len = raw_to_unsigned_short(y+1);
	            y += 3;
	            certs_len -= 3;
            } else if (*y == 129) {
	            ext_len = *(y+1);
	            y += 2;
	            certs_len -= 2;
            } else {
	            ext_len = *y;
	            y += 2;
	            certs_len -= 2;
            }
            cur_ext = 0;
            while (ext_len > 0) {
	            if (cur_ext >= MAX_CERT_EXTENSIONS) {
	                break ;
	            }
	            if (certs_len <= 10) {
	                break;
            	}
	            tmp_len2 = *(y+1);
	            if (tmp_len2 == 130) {
	                tmp_len2 = raw_to_unsigned_short(y+2);
	                y += 4;
	                certs_len -= 4;
	                ext_len -= 4;		
	            } else if (tmp_len2 == 129) {
	                tmp_len2 = *(y+2);
	                y += 3;
	                certs_len -= 3;
	                ext_len -= 3;
	            } else {
	                y += 2;
	                certs_len -= 2;
	                ext_len -= 2;
	            }
	
	            // check for extension-specific parsing
	            hi = *(y+2);
	            mid = *(y+3);
	            lo = *(y+4);
	            if ((hi == 85) && (mid == 29) && (lo == 17)) { // parse SAN
	                tmp_len = *(y+1);
	                tmp_len2 = tmp_len2-tmp_len-2;

	                if (*(y+6) == 129) {
	                    tls_san_parse(y+tmp_len+2+4+2, tmp_len2-4-2, &r->certificates[cur_cert]);
	                } else {
	                    tls_san_parse(y+tmp_len+2+4, tmp_len2-4, &r->certificates[cur_cert]);
	                }
	  
	                y += tmp_len2+tmp_len+2;
	                certs_len -= tmp_len2+tmp_len+2;
	                ext_len -= tmp_len2+tmp_len+2;
	            } else { // general purpose ext parsing
	                tmp_len = *(y+1);
  
	                if (tmp_len == 130) {
	                    //tmp_len = *(y+2);
	                    tmp_len = raw_to_unsigned_short(y+2);
	                    y += 2;
	                    certs_len -= 2;
	                    ext_len -= 2;		
	                } else if (tmp_len == 129) {
	                    tmp_len = *(y+2);
	                    y += 1;
	                    certs_len -= 1;
	                    ext_len -= 1;
	                } else {
	                }
	  
	                if (tmp_len > 20 || tmp_len < 3 || tmp_len2-tmp_len-2 <= 0) {
	                    break;
	                }

	                //if (tmp_len > 50) {return;}
	                r->certificates[cur_cert].ext_id[cur_ext] = malloc(tmp_len);
	                memcpy(r->certificates[cur_cert].ext_id[cur_ext], y+2, tmp_len);
	                r->certificates[cur_cert].ext_id_length[cur_ext] = tmp_len;

	                //printf("\text_id: ");
	                //printf_raw_as_hex_tls(r->certificates[cur_cert].ext_id[cur_ext], tmp_len);
	                //printf("\n");
	  
	                //printf("%i\n",tmp_len);
	                //printf("%i\n",tmp_len2);
	                //printf("%i\n",certs_len);
	                //printf("%i\n",ext_len);
	                //printf("\n");

	                tmp_len2 = tmp_len2-tmp_len-2;
	                //if (tmp_len2 > 50) {return;}
	                r->certificates[cur_cert].ext_data[cur_ext] = malloc(tmp_len2);
	                //memset(r->certificates[cur_cert].ext_data[cur_ext], 0, tmp_len2);
	                memcpy(r->certificates[cur_cert].ext_data[cur_ext], y+tmp_len+2, tmp_len2);
	                r->certificates[cur_cert].ext_data_length[cur_ext] = tmp_len2;
	                //printf("\text_data: ");
	                //printf_raw_as_hex_tls(r->certificates[cur_cert].ext_data[cur_ext], tmp_len2);
	                //printf("\n");
	  
	                cur_ext++;
	                r->certificates[cur_cert].num_ext = cur_ext;
	                y += tmp_len2+tmp_len+2;
	                certs_len -= tmp_len2+tmp_len+2;
	                ext_len -= tmp_len2+tmp_len+2;
	            }
            }	    
        }
    
        // parse signature key size
        tmp_len = *(y+1);
        y += tmp_len+2;
        certs_len -= tmp_len+2;

        if (*(y+1) == 129) {
            tmp_len = *(y+2);
            //printf("\tsignature_key_size: %i\n", (tmp_len-1)*8);
            y += tmp_len+3;
            certs_len -= tmp_len+3;
        } else if (*(y+1) == 130) {
            tmp_len = raw_to_unsigned_short(y+2);
            //r->certificates[cur_cert].signature_key_size = (tmp_len-1)*8;
            //printf("\tsignature_key_size: %i\n", (tmp_len-1)*8);
            y += tmp_len+4;
            certs_len -= tmp_len+4;	    
        } else {
            break ;
        }

        // still not parsing unique identifiers
        //if ((tmp_len-1)*8 != 1024 || (tmp_len-1)*8 != 2048 || (tmp_len-1)*8 != 512) {
              //break;
        //}

        r->certificates[cur_cert].signature_key_size = (tmp_len-1)*8;
    
        //certs_len -= cert_len;
        //printf("\n");
        //break;
#endif
    }
}

#if 0
static void tls_san_parse (const void *x, int len, struct tls_certificate *r) {
    unsigned short num_san = 0;
    unsigned short tmp_len;
    const unsigned char *y = x;
    int i;

    while (len > 0) {
        if (num_san >= MAX_SAN) {
            break;
        }
        tmp_len = *(y+1);

        if (tmp_len == 0) {
            break;
        }

        if (tmp_len > 50) {
            break;
        }

        r->san[num_san] = malloc(tmp_len+1);
        memset(r->san[num_san], '\0', tmp_len+1);
        //((char *)r->san[num_san])[tmp_len] = '\0';
        memcpy(r->san[num_san], y+2, tmp_len);

        //printf("%s\n",r->san[num_san]);
        //printf("%i\n",tmp_len);

        for (i = 0; i < tmp_len; i++) {
            if (*(char *)(r->san[num_san]+i) < 48 || *(char *)(r->san[num_san]+i) > 126 ||
	            (*(char *)(r->san[num_san]+i) > 90 && *(char *)(r->san[num_san]+i) < 97) ||
	            (*(char *)(r->san[num_san]+i) > 57 && *(char *)(r->san[num_san]+i) < 65) ) {
	            if (*(char *)(r->san[num_san]+i) == 42) {
	                continue;
	            }
	            memset(r->san[num_san]+i, '.', 1);
            }
        }

        //printf("%s\n\n",r->san[num_san]);

        num_san += 1;
        y += tmp_len+2;
        len -= tmp_len+2;
    }
    r->num_san = num_san;
}
#endif

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

static void tls_server_hello_get_extensions (const void *x, int len,
    struct tls_information *r) {
    unsigned int session_id_len, compression_method_len;
    const unsigned char *y = x;
    unsigned short int extensions_len;
    unsigned int i = 0;
    unsigned char flag_tls13 = 0;

    len -= 4;

    /* Check the TLS version */
    if (!r->tls_v) {
        /* Unsupported version */
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
    const char *fingerprint_file = NULL;
    size_t i = 0;
    int rc = 1;

    if (tls_fingerprint_file != NULL) {
        /* Use the provided file path */
        fingerprint_file = tls_fingerprint_file;
    } else {
        /* Use the package source location */
        fingerprint_file = "tls_fingerprint.json";
    }

    /* Parse the Json file and validate */
    root_value = json_parse_file(fingerprint_file);
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
        uint16_t cs_count = 0;
        uint16_t ext_count = 0;
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

        if (cs_count + ext_count >= MAX_FINGERPRINT_LEN) {
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
            fp_local.fingerprint_len += 1;
        }
        for (k = 0; k < ext_count; k++) {
            extension_str = json_value_get_string(json_array_get_value(extensions, k));
            /* Convert the current hex string to a 2-byte value */
            sscanf(extension_str, "%hx", &ext_val);
            /* Copy into the functions local fingerprint */
            fp_local.fingerprint[fp_local.fingerprint_len] = ext_val;
            fp_local.fingerprint_len += 1;
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
 * If any matches are found, relevant data is copied
 * into the \p tls_info for later retrieval. The \p percent
 * represents the users required percent of confidence in
 * order for a match to occur, 0 to 100. 100 means an exact match
 * (100% of fingerprint must be matched). 70 means a partial
 * match (70% of fingerprint must be matched).
 *
 * @param tls_info The client TLS information
 * @param percent The callers required percent of fingerprint match.
 *
 * return 0 for match
 */
/* TODO re-enable this function for fingerprinting */
#if 0
static uint8_t tls_client_fingerprint_match(struct tls_information *tls_info,
                                            uint8_t percent) {
    fingerprint_t client_fingerprint;
    fingerprint_t *db_fingerprint = NULL;
    size_t cs_byte_count = 0;

    if (!tls_fingerprint_db_loaded) {
        /* The fingerprint database is empty, bail out */
        return 1;
    }

    const unsigned short int test_cs_vector[] = {57, 56, 53, 22, 19, 10, 51, 50,
                                                 47, 7, 102, 5, 4, 99, 98, 97,
                                                 21, 18, 9, 101, 100, 96, 20, 17,
                                                 8, 6, 3};
    cs_byte_count = sizeof(test_cs_vector);

    memset(&client_fingerprint, 0, sizeof(fingerprint_t));

    /*
     * Copy test data into client fingerprint.
     */
    memcpy(client_fingerprint.fingerprint, test_cs_vector, cs_byte_count);
    client_fingerprint.fingerprint_len = (cs_byte_count / sizeof(unsigned short int));

    if (percent == 100) {
        /* Find an exact database fingerprint match */
        db_fingerprint = fingerprint_db_match_exact(&tls_fingerprint_db,
                                                    &client_fingerprint);
    } else {
        fprintf(stderr, "api-error: partial matching not supported yet");
        return 1;
    }

    if (db_fingerprint != NULL) {
        /* Point to database entry in client tls info */
        tls_info->tls_fingerprint = db_fingerprint;

#if 0
        printf("FINGERPRINT MATCH!\n");
#endif
    }

    return 0;
}
#endif

#if 0
static unsigned int tls_handshake_get_length (const struct tls_handshake *H) {
    return H->lengthLo + ((unsigned int) H->lengthMid) * 0x100 
        + ((unsigned int) H->lengthHi) * 0x10000;
}
#endif

#if 0
static unsigned int packet_is_sslv2_hello (const void *data) {
    const unsigned char *d = data;
    unsigned char b[3];
  
    b[0] = d[0];
    b[1] = d[1];
    b[2] = d[2];

    if (b[0] & 0x80) {
        b[0] &= 0x7F;
        if (raw_to_unsigned_short(b) > 9) {
            if (b[2] == 0x01) {
	            return tls_sslv2;
            }
        }    
    }

    return tls_unknown;
}
#endif

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
    const void *start = payload;
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
  
    /* currently skipping jumbo frames */
    if (len > 3000) {
        return;
    }

    /* Allocate TLS info struct if needed and initialize */
    if (r == NULL) {
        r = malloc(sizeof(struct tls_information));
        if (r != NULL) {
            tls_init(r);
        }
    }

    /* Cast beginning of payload to a tls_header */
    tls = (const struct tls_header *)start;

    if (tls->content_type == TLS_CONTENT_HANDSHAKE && tls->handshake.msg_type == TLS_HANDSHAKE_SERVER_HELLO) {
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
        // FIXME
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

        if (r->certificate_offset && r->start_cert == 1 &&
            ((tls->content_type == TLS_CONTENT_APPLICATION_DATA) ||
             (tls->content_type == TLS_CONTENT_CHANGE_CIPHER_SPEC) ||
             (tls->content_type == TLS_CONTENT_ALERT) ||
             (r->certificate_offset >= MAX_CERTIFICATE_BUFFER - 300))) {
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

        if (tls->content_type == TLS_CONTENT_APPLICATION_DATA) {
            if (!r->tls_v) {
                /* Write the TLS version to record if empty */
                if (tls_header_version_capture(r, tls)) {
                    /* TLS version sanity check failed */
                    return;
                }
            }
        } else if (tls->content_type == TLS_CONTENT_HANDSHAKE) {
            /*
             * Check if handshake type is valid.
             */
            if (((tls->handshake.msg_type > 2) && (tls->handshake.msg_type < 11)) ||
                ((tls->handshake.msg_type > 16) && (tls->handshake.msg_type < 20)) ||
                (tls->handshake.msg_type > 20)) {
	              /*
	               * We encountered an unknown HandshakeType, so this packet is
	               * not actually a TLS handshake, so we bail on decoding it.
	               */
	              return;
            }

            /*
             * Match to a handshake type we are interested in.
             */
            if (tls->handshake.msg_type == TLS_HANDSHAKE_CLIENT_HELLO) {
                /*
                 * Handshake: ClientHello
                 */
                if (!r->tls_v) {
                    /* Write the TLS version to record if empty */
                    if (tls_handshake_hello_get_version(r, &tls->handshake.body)) {
                        /* TLS version sanity check failed */
                        return;
                    }
                }

                r->role = role_client;
                tls_client_hello_get_ciphersuites(&tls->handshake.body, tls_len, r);
                tls_client_hello_get_extensions(&tls->handshake.body, tls_len, r);

                /* TODO enable fingerprint matching */
#if 0
                tls_client_fingerprint_match(r, 100);
#endif
            } else if (tls->handshake.msg_type == TLS_HANDSHAKE_SERVER_HELLO) {
                /*
                 * Handshake: ServerHello
                 */
                if (!r->tls_v) {
                    /* Write the TLS version to record if empty */
                    if (tls_handshake_hello_get_version(r, &tls->handshake.body)) {
                        /* TLS version sanity check failed */
                        return;
                    }
                }

                r->role = role_server;
                tls_server_hello_get_ciphersuite(&tls->handshake.body, tls_len, r);
                tls_server_hello_get_extensions(&tls->handshake.body, (int)tls_len, r);
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

        tls_len += 5; /* Advance over header */
        start += tls_len;
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
static int tls_certificate_process (const void *data,
                                    int data_len,
                                    struct tls_information *tls_info) {
    const struct tls_header *tls_hdr;
    unsigned int tls_len;

    while (data_len > 200) {
        tls_hdr = data;

        if (tls_hdr->content_type != TLS_CONTENT_HANDSHAKE) {
            break;
        }

        /* Get the length of the handshake portion of the message */
        tls_len = tls_header_get_length(tls_hdr);

        /* Only parse Certificate message types */
        if (tls_hdr->handshake.msg_type == TLS_HANDSHAKE_CERTIFICATE) {
            tls_server_certificate_parse(&tls_hdr->handshake.body, tls_len, tls_info);
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

#if 0
static void printf_raw_as_hex_tls (const void *data, unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    if (data == NULL) { /* special case for nfv9 TLS export */
        printf("\"");   /* quotes needed for JSON */
        printf("\"");
        return ;
    }
  
    printf("\"");   /* quotes needed for JSON */
    while (x < end) {
        printf("%02x", *x++);
    }
    printf("\"");
}
#endif

static void zprintf_raw_as_hex_tls (zfile f, const void *data, unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

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
	      pkt_len, dir, timeval_to_milliseconds_tls(ts), type.content,
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
	                timer_sub_tls(&time[i], &time[i-1], &ts);
	            } else {
	                timer_clear_tls(&ts);
	            }
	            print_bytes_dir_time_tls(len[i], OUT, ts, type[i], ",", f);
            }
            if (i == 0) {        /* this code could be simplified */ 	
	            timer_clear_tls(&ts);  
            } else {
	            timer_sub_tls(&time[i], &time[i-1], &ts);
            }
            print_bytes_dir_time_tls(len[i], OUT, ts, type[i], "", f);
        }
        zprintf(f, "]"); 
    } else {

        if (timer_lt_tls(time, time2)) {
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

	            if (timer_lt_tls(&time[i], &time2[j])) {
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
            timer_sub_tls(&ts, &ts_last, &tmp);
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
    int j;

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
	        zprintf(f, "{\"entry_id\": \"%s\",", data->extensions[j].id);
	        zprintf(f, "\"entry_data\": ");
	        zprintf_raw_as_hex_tls(f, data->extensions[j].data, data->extensions[j].data_length);
	        zprintf(f, "}");
            if (j == (data->num_subject_items - 1)) {
                zprintf(f, "]");
            } else {
                zprintf(f, ",");
            }
        }
    }
    
    if (data->validity_not_before) {
        zprintf(f, ",\"validity_not_before\":");
        zprintf_raw_as_hex_tls(f, data->validity_not_before, data->validity_not_before_length);
    }
    if (data->validity_not_after) {
        zprintf(f, ",\"validity_not_after\":");
        zprintf_raw_as_hex_tls(f, data->validity_not_after, data->validity_not_after_length);
    }
    
    if (*data->subject_public_key_algorithm) {
        zprintf(f, ",\"subject_public_key_algorithm\": \"%s\"", data->subject_public_key_algorithm);
    }
    
    if (data->subject_public_key_size) {
        zprintf(f, ",\"subject_public_key_size\":%i", data->subject_public_key_size);
    }
}

void tls_unit_test() {
    loginfo("Unit test: TLS");
}

