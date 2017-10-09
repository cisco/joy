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
 * ike.c
 *
 * Internet Key Exchange (IKE) awareness for joy
 *
 */
#include <stdio.h>      /* for fprintf()           */
#include <stdlib.h>     /* for malloc, realloc, free */
#include <stdint.h>     /* for uint32_t            */

#ifdef WIN32
# include "Ws2tcpip.h"
# define strtok_r strtok_s
#else
# include <arpa/inet.h>  /* for ntohl()             */
#endif

#include "ike.h"
#include "utils.h"      /* for enum role */
#include "p2f.h"        /* for zprintf_ ...        */
#include "err.h"        /* for logging             */

/*
 * \brief A vector is contains a pointer to a string of bytes of a specified length.
 */
struct vector {
    unsigned int len;
    unsigned char *bytes;
};

/*
 *
 * \brief Delete the memory of vector struct.
 *
 * \param vector_handle Contains vector structure to delete.
 *
 */
static void vector_delete(struct vector **vector_handle) {
    struct vector *vector = *vector_handle;

    if (vector == NULL) {
        return;
    }
    if (vector->bytes != NULL) {
        free(vector->bytes);
    }

    free(vector);
    *vector_handle = NULL;
}

/*
 *
 * \brief Initialize the memory of vector struct.
 *
 * \param vector_handle Contains vector structure to initialize.
 *
 */
static void vector_init(struct vector **vector_handle) {

    if (*vector_handle != NULL) {
        vector_delete(vector_handle);
    }

    *vector_handle = calloc(1, sizeof(struct vector));
    if (*vector_handle == NULL) {
        /* Allocation failed */
        joy_log_err("malloc failed");
        return;
    }
}

/*
 *
 * \brief Set the vector contents to the specified data, freeing the previous
 * vector contents. If the previous vector contents overlap in memory with the
 * new vector contents, the behavior is still defined since the free occurs
 * after the copy.
 *
 * \param vector Pointer to the vector to be set.
 * \param data Pointer to byte array to be copied.
 * \param len Length of the byte array to be copied.
 *
 */
static void vector_set(struct vector *vector,
                       const char *data,
                       unsigned int len) {
    unsigned char *tmpptr = NULL;

    tmpptr = malloc(len);
    if (tmpptr == NULL) {
        joy_log_err("malloc failed");
        return;
    }
    memcpy(tmpptr, data, len);
    if (vector->bytes != NULL) {
        free(vector->bytes);
    }
    vector->bytes = tmpptr;
    vector->len = len;
}

/*
 *
 * \brief Append the specified data to the current vector contents, even if the
 * vector is currently empty.
 *
 * \param vector Pointer to the vector to be appended to.
 * \param data Pointer to byte array to be appended.
 * \param len Length of the byte array to be appended.
 *
 */
static void vector_append(struct vector *vector,
                          const char *data,
                          unsigned int len) {
    unsigned char *tmpptr = NULL;

    tmpptr = malloc(vector->len + len);
    if (tmpptr == NULL) {
        joy_log_err("malloc failed");
        return;
    }
    memcpy(tmpptr, vector->bytes, vector->len);
    memcpy(tmpptr + vector->len, data, len);
    if (vector->bytes != NULL) {
        free(vector->bytes);
    }
    vector->bytes = tmpptr;
    vector->len += len;
}

/*
 * \brief Convert buffer to uint16_t
 */
static uint16_t raw_to_uint16(const char *x) {
    return (uint16_t)(x[0]&0xff) << 8 | (uint16_t)(x[1]&0xff);
}

/*
 * \brief Convert buffer to uint32_t
 */
static uint32_t raw_to_uint32(const char *x) {
    return (uint32_t)(x[0]&0xff) << 24 | (uint32_t)(x[1]&0xff) << 16 |
        (uint32_t)(x[2]&0xff) << 8 | (uint32_t)(x[3]&0xff);
}

/*
 * \brief Enumeration representing Payload Types
 */
enum ike_payload_type {
    IKE_NO_NEXT_PAYLOAD                         = 0,
    IKE_SECURITY_ASSOCIATION_V1                 = 1,
    IKE_PROPOSAL_V1                             = 2,
    IKE_TRANSFORM_V1                            = 3,
    IKE_KEY_EXCHANGE_V1                         = 4,
    IKE_IDENTIFICATION_V1                       = 5,
    IKE_CERTIFICATE_V1                          = 6,
    IKE_CERTIFICATE_REQUEST_V1                  = 7,
    IKE_HASH_V1                                 = 8,
    IKE_SIGNATURE_V1                            = 9,
    IKE_NONCE_V1                                = 10,
    IKE_NOTIFICATION_V1                         = 11,
    IKE_DELETE_V1                               = 12,
    IKE_VENDOR_ID_V1                            = 13,
    IKE_SA_KEK_PAYLOAD_V1                       = 15,
    IKE_SA_TEK_PAYLOAD_V1                       = 16,
    IKE_KEY_DOWNLOAD_V1                         = 17,
    IKE_SEQUENCE_NUMBER_V1                      = 18,
    IKE_PROOF_OF_POSSESSION_V1                  = 19,
    IKE_NAT_DISCOVERY_V1                        = 20,
    IKE_NAT_ORIGINAL_ADDRESS_V1                 = 21,
    IKE_GROUP_ASSOCIATED_POLICY_V1              = 22,
    IKE_SECURITY_ASSOCIATION_V2                 = 33,
    IKE_KEY_EXCHANGE_V2                         = 34,
    IKE_IDENTIFICATION_INITIATOR_V2             = 35,
    IKE_IDENTIFICATION_RESPONDER_V2             = 36,
    IKE_CERTIFICATE_V2                          = 37,
    IKE_CERTIFICATE_REQUEST_V2                  = 38,
    IKE_AUTHENTICATION_V2                       = 39,
    IKE_NONCE_V2                                = 40,
    IKE_NOTIFY_V2                               = 41,
    IKE_DELETE_V2                               = 42,
    IKE_VENDOR_ID_V2                            = 43,
    IKE_TRAFFIC_SELECTOR_INITIATOR_V2           = 44,
    IKE_TRAFFIC_SELECTOR_RESPONDER_V2           = 45,
    IKE_ENCRYPTED_V2                            = 46,
    IKE_CONFIGURATION_V2                        = 47,
    IKE_EXTENSIBLE_AUTHENTICATION_V2            = 48,
    IKE_GENERIC_SECURE_PASSWORD_METHOD_V2       = 49,
    IKE_GROUP_IDENTIFICATION_V2                 = 50,
    IKE_GROUP_SECURITY_ASSOCIATION_V2           = 51,
    IKE_KEY_DOWNLOAD_V2                         = 52,
    IKE_ENCRYPTED_AND_AUTHENTICATED_FRAGMENT_V2 = 53
};

/*
 * \brief Enumeration representing Exchange Types
 */
enum ike_exchange_type {
    IKE_EXCHANGE_TYPE_NONE_V1       = 0,
    IKE_BASE_V1                     = 1,
    IKE_IDENTITY_PROTECTION_V1      = 2,
    IKE_AUTHENTICATION_ONLY_V1      = 3,
    IKE_AGGRESSIVE_V1               = 4,
    IKE_INFORMATIONAL_V1            = 5,
    IKE_QUICK_MODE_V1               = 32,
    IKE_NEW_GROUP_MODE_V1           = 33,
    IKE_IKE_SA_INIT_V2              = 34,
    IKE_IKE_AUTH_V2                 = 35,
    IKE_CREATE_CHILD_SA_V2          = 36,
    IKE_INFORMATIONAL_V2            = 37,
    IKE_IKE_SESSION_RESUME_V2       = 38,
    IKE_GSA_AUTH_V2                 = 39,
    IKE_GSA_REGISTRATION_V2         = 40,
    IKE_GSA_REKEY_V2                = 41
};

/*
 * \brief Enumeration representing ISAKMP Domain of Interpretations (DOIs)
 */
enum ike_doi_v1 {
    IKE_ISAKMP_V1  = 0,
    IKE_IPSEC_V1   = 1,
    IKE_GDOI_V1    = 2
};

/*
 * \brief Enumeration representing Attribute Types
 */
enum ike_attribute_type {
    IKE_ENCRYPTION_ALGORITHM_V1                = 1,
    IKE_HASH_ALGORITHM_V1                      = 2,
    IKE_AUTHENTICATION_METHOD_V1               = 3,
    IKE_GROUP_DESCRIPTION_V1                   = 4,
    IKE_GROUP_TYPE_V1                          = 5,
    IKE_GROUP_PRIME_IRREDUCIBLE_POLYNOMIAL_V1  = 6,
    IKE_GROUP_GENERATOR_ONE_V1                 = 7,
    IKE_GROUP_GENERATOR_TWO_V1                 = 8,
    IKE_GROUP_CURVE_A_V1                       = 9,
    IKE_GROUP_CURVE_B_V1                       = 10,
    IKE_LIFE_TYPE_V1                           = 11,
    IKE_LIFE_DURATION_V1                       = 12,
    IKE_PRF_V1                                 = 13,
    IKE_KEY_LENGTH_V1                          = 14,
    IKE_FIELD_SIZE_V1                          = 15,
    IKE_GROUP_ORDER_V1                         = 16,
    IKE_KEY_LENGTH_V2                          = 14
};

/*
 * \brief Enumeration representing Transform Types
 */
enum ike_transform_type {
    IKE_ENCRYPTION_ALGORITHM_V2            = 1,
    IKE_PSEUDORANDOM_FUNCTION_V2           = 2,
    IKE_INTEGRITY_ALGORITHM_V2             = 3,
    IKE_DIFFIE_HELLMAN_GROUP_V2            = 4,
    IKE_EXTENDED_SEQUENCE_NUMBERS_V2       = 5
};

/*
 * \brief Enumeration representing IPsec ISAKMP Transform IDs
 */
enum ike_transform_id_v1 {
    IKE_KEY_IKE_V1                          = 1
};

/*
 * \brief Enumeration representing Encryption Algorithms
 */
enum ike_encryption_algorithm {
    IKE_ENCR_DES_CBC_V1                         = 1,
    IKE_ENCR_IDEA_CBC_V1                        = 2,
    IKE_ENCR_BLOWFISH_CBC_V1                    = 3,
    IKE_ENCR_RC5_R16_B64_CBC_V1                 = 4,
    IKE_ENCR_3DES_CBC_V1                        = 5,
    IKE_ENCR_CAST_CBC_V1                        = 6,
    IKE_ENCR_AES_CBC_V1                         = 7,
    IKE_ENCR_CAMELLIA_CBC_V1                    = 8,
    IKE_ENCR_DES_IV64_V2                        = 1,
    IKE_ENCR_DES_V2                             = 2,
    IKE_ENCR_3DES_V2                            = 3,
    IKE_ENCR_RC5_V2                             = 4,
    IKE_ENCR_IDEA_V2                            = 5,
    IKE_ENCR_CAST_V2                            = 6,
    IKE_ENCR_BLOWFISH_V2                        = 7,
    IKE_ENCR_3IDEA_V2                           = 8,
    IKE_ENCR_DES_32_V2                          = 9,
    IKE_ENCR_NULL_V2                            = 11,
    IKE_ENCR_AES_CBC_V2                         = 12,
    IKE_ENCR_AES_CTR_V2                         = 13,
    IKE_ENCR_AES_CCM_8_V2                       = 14,
    IKE_ENCR_AES_CCM_12_V2                      = 15,
    IKE_ENCR_AES_CCM_16_V2                      = 16,
    IKE_ENCR_AES_GCM_8_V2                       = 18, // requires key length attribute
    IKE_ENCR_AES_GCM_12_V2                      = 19, // requires key length attribute
    IKE_ENCR_AES_GCM_V2                         = 20,
    IKE_ENCR_NULL_AUTH_AES_GMAC_V2              = 21,
    IKE_ENCR_CAMELLIA_CBC_V2                    = 23,
    IKE_ENCR_CAMELLIA_CTR_V2                    = 24,
    IKE_ENCR_CAMELLIA_CCM_8_V2                  = 25,
    IKE_ENCR_CAMELLIA_CCM_12_V2                 = 26,
    IKE_ENCR_CAMELLIA_CCM_16_V2                 = 27,
    IKE_ENCR_CHACHA20_POLY1305_V2               = 28
};

/*
 * \brief Enumeration representing Hash Algorithms
 */
enum ike_hash_algorithm {
    IKE_MD5_V1                                  = 1,
    IKE_SHA_V1                                  = 2,
    IKE_TIGER_V1                                = 3,
    IKE_SHA2_256_V1                             = 4,
    IKE_SHA2_384_V1                             = 5,
    IKE_SHA2_512_V1                             = 6,
    IKE_SHA1_V2                                 = 1,
    IKE_SHA2_256_V2                             = 2,
    IKE_SHA2_384_V2                             = 3,
    IKE_SHA2_512_V2                             = 4
};

/*
 * \brief Enumeration representing Authentication Methods
 */
enum ike_authentication_method {
    IKE_PRE_SHARED_KEY_V1                                   = 1,
    IKE_DSS_SIGNATURES_V1                                   = 2,
    IKE_RSA_SIGNATURES_V1                                   = 3,
    IKE_ENCRYPTION_WITH_RSA_V1                              = 4,
    IKE_REVISED_ENCRYPTION_WITH_RSA_V1                      = 5,
    IKE_ECDSA_SHA256_P256_CURVE_V1                          = 9,
    IKE_ECDSA_SHA384_P384_CURVE_V1                          = 10,
    IKE_ECDSA_SHA512_P521_CURVE_V1                          = 11,
    IKE_RSA_DIGITAL_SIGNATURE_V2                            = 1,
    IKE_SHARED_KEY_MESSAGE_INTEGRITY_CODE_V2                = 2,
    IKE_DSSDIGITAL_SIGNATURE_V2                             = 3,
    IKE_ECDSA_SHA256_P256_V2                                = 9,
    IKE_ECDSA_SHA384_P384_V2                                = 10,
    IKE_ECDSA_SHA512_P512_V2                                = 11,
    IKE_GENERIC_SECURE_PASSWORD_AUTHENTICATION_METHOD_V2    = 12,
    IKE_NULL_AUTHENTICATION_V2                              = 13,
    IKE_DIGITAL_SIGNATURE_V2                                = 14
};

/*
 * \brief Enumeration representing Diffie-Hellman Groups
 */
enum ike_diffie_hellman_group {
    IKE_DH_GROUP_NONE_V1                   = 0,
    IKE_DH_MODP768_V1                      = 1,
    IKE_DH_MODP1024_V1                     = 2,
    IKE_DH_T155_V1                         = 3,
    IKE_DH_T185_V1                         = 4,
    IKE_DH_MODP1536_V1                     = 5,
    IKE_DH_T163R1_V1                       = 6,
    IKE_DH_T163K1_V1                       = 7,
    IKE_DH_T283R1_V1                       = 8,
    IKE_DH_T283K1_V1                       = 9,
    IKE_DH_T409R1_V1                       = 10,
    IKE_DH_T409K1_V1                       = 11,
    IKE_DH_T571R1_V1                       = 12,
    IKE_DH_T571K1_V1                       = 13,
    IKE_DH_MODP2048_V1                     = 14,
    IKE_DH_MODP3072_V1                     = 15,
    IKE_DH_MODP4096_V1                     = 16,
    IKE_DH_MODP6144_V1                     = 17,
    IKE_DH_MODP8192_V1                     = 18,
    IKE_DH_P256_V1                         = 19,
    IKE_DH_P384_V1                         = 20,
    IKE_DH_P521_V1                         = 21,
    IKE_DH_MODP1024_S160_V1                = 22,
    IKE_DH_MODP2048_S224_V1                = 23,
    IKE_DH_MODP2048_S256_V1                = 24,
    IKE_DH_P192_V1                         = 25,
    IKE_DH_P224_V1                         = 26,
    IKE_DH_BRAINPOOL_P224_V1               = 27,
    IKE_DH_BRAINPOOL_P256_V1               = 28,
    IKE_DH_BRAINPOOL_P384_V1               = 29,
    IKE_DH_BRAINPOOL_P512_V1               = 30,
    IKE_DH_CURVE25519_V1                   = 31,
    IKE_DH_CURVE448_V1                     = 32,
    IKE_DH_GROUP_NONE_V2                   = 0,
    IKE_DH_MODP768_V2                      = 1,
    IKE_DH_MODP1024_V2                     = 2,
    IKE_DH_MODP1536_V2                     = 5,
    IKE_DH_MODP2048_V2                     = 14,
    IKE_DH_MODP3072_V2                     = 15,
    IKE_DH_MODP4096_V2                     = 16,
    IKE_DH_MODP6144_V2                     = 17,
    IKE_DH_MODP8192_V2                     = 18,
    IKE_DH_P256_V2                         = 19,
    IKE_DH_P384_V2                         = 20,
    IKE_DH_P521_V2                         = 21,
    IKE_DH_MODP1024_S160_V2                = 22,
    IKE_DH_MODP2048_S224_V2                = 23,
    IKE_DH_MODP2048_S256_V2                = 24,
    IKE_DH_P192_V2                         = 25,
    IKE_DH_P224_V2                         = 26,
    IKE_DH_BRAINPOOL_P224_V2               = 27,
    IKE_DH_BRAINPOOL_P256_V2               = 28,
    IKE_DH_BRAINPOOL_P384_V2               = 29,
    IKE_DH_BRAINPOOL_P512_V2               = 30,
    IKE_DH_CURVE25519_V2                   = 31,
    IKE_DH_CURVE448_V2                     = 32
};

/*
 * \brief Enumeration representing Group Types
 */
enum ike_group_type {
    IKE_MODP_V1 = 1,
    IKE_ECP_V1  = 2,
    IKE_EC2N_V1 = 3
};

/*
 * \brief Enumeration representing Life Types
 */
enum ike_life_type {
    IKE_SECONDS_V1          = 1,
    IKE_KILIBYTES_V1        = 2
};

/*
 * \brief Enumeration representing Pseudo-Random Functions
 */
enum ike_pseudorandom_function {
    IKE_PRF_HMAC_MD5_V2      = 1,
    IKE_PRF_HMAC_SHA1_V2     = 2,
    IKE_PRF_HMAC_TIGER_V2    = 3,
    IKE_PRF_AES128_XCBC_V2   = 4,
    IKE_PRF_HMAC_SHA2_256_V2 = 5,
    IKE_PRF_HMAC_SHA2_384_V2 = 6,
    IKE_PRF_HMAC_SHA2_512_V2 = 7,
    IKE_PRF_AES128_CMAC_V2   = 8
};

/*
 * \brief Enumeration representing Identification Types
 */
enum ike_identification_type {
    IKE_ID_IPV4_ADDR_V1         = 1,
    IKE_ID_FQDN_V1              = 2,
    IKE_ID_USER_FQDN_V1         = 3,
    IKE_ID_IPV4_ADDR_SUBNET_V1  = 4,
    IKE_ID_IPV6_ADDR_V1         = 5,
    IKE_ID_IPV6_ADDR_SUBNET_V1  = 6,
    IKE_ID_IPV4_ADDR_RANGE_V1   = 7,
    IKE_ID_IPV6_ADDR_RANGE_V1   = 8,
    IKE_ID_DER_ASN1_DN_V1       = 9,
    IKE_ID_DER_ASN1_GN_V1       = 10,
    IKE_ID_KEY_ID_V1            = 11,
    IKE_ID_IPV4_ADDR_V2         = 1,
    IKE_ID_FQDN_V2              = 2,
    IKE_ID_RFC822_ADDR_V2       = 3,
    IKE_ID_IPV6_ADDR_V2         = 5,
    IKE_ID_DER_ASN1_DN_V2       = 9,
    IKE_ID_DER_ASN1_GN_V2       = 10,
    IKE_ID_KEY_ID_V2            = 11,
    IKE_ID_FC_NAME_V2           = 12,
    IKE_ID_NULL_V2              = 13
};

/*
 * \brief Enumeration representing Situation bitmap flags
 */
enum ike_situation_flags {
    IKE_SIT_IDENTITY_ONLY_V1 = 0x01,
    IKE_SIT_SECRECY_V1       = 0x02,
    IKE_SIT_INTEGRITY_V1     = 0x04
};

/*
 * \brief Enumeration representing ISAKMP header flags
 */
enum ike_header_flags {
    IKE_ENCRYPTION_BIT_V1           = 0x01,
    IKE_COMMIT_BIT_V1               = 0x02,
    IKE_AUTHENTICATION_BIT_V1       = 0x04,
    IKE_INITIATOR_BIT_V2            = 0x08,
    IKE_VERSION_BIT_V2              = 0x10,
    IKE_RESPONSE_BIT_V2             = 0x20
};

/*
 * \brief Enumeration representing Notify Types
 */
enum ike_notify_type {
    /* error types */
    IKE_INVALID_PAYLOAD_TYPE_V1                = 1,
    IKE_DOI_NOT_SUPPORTED_V1                   = 2,
    IKE_SITUATION_NOT_SUPPORTED_V1             = 3,
    IKE_INVALID_COOKIE_V1                      = 4,
    IKE_INVALID_MAJOR_VERSION_V1               = 5,
    IKE_INVALID_MINOR_VERSION_V1               = 6,
    IKE_INVALID_EXCHANGE_TYPE_V1               = 7,
    IKE_INVALID_FLAGS_V1                       = 8,
    IKE_INVALID_MESSAGE_ID_V1                  = 9,
    IKE_INVALID_PROTOCOL_ID_V1                 = 10,
    IKE_INVALID_SPI_V1                         = 11,
    IKE_INVALID_TRANSFORM_ID_V1                = 12,
    IKE_ATTRIBUTES_NOT_SUPPORTED_V1            = 13,
    IKE_NO_PROPOSAL_CHOSEN_V1                  = 14,
    IKE_BAD_PROPOSAL_SYNTAX_V1                 = 15,
    IKE_PAYLOAD_MALFORMED_V1                   = 16,
    IKE_INVALID_KEY_INFORMATION_V1             = 17,
    IKE_INVALID_ID_INFORMATION_V1              = 18,
    IKE_INVALID_CERT_ENCODING_V1               = 19,
    IKE_INVALID_CERTIFICATE_V1                 = 20,
    IKE_CERT_TYPE_UNSUPPORTED_V1               = 21,
    IKE_INVALID_CERT_AUTHORITY_V1              = 22,
    IKE_INVALID_HASH_INFORMATION_V1            = 23,
    IKE_AUTHENTICATION_FAILED_V1               = 24,
    IKE_INVALID_SIGNATURE_V1                   = 25,
    IKE_ADDRESS_NOTIFICATION_V1                = 26,
    IKE_NOTIFY_SA_LIFETIME_V1                  = 27,
    IKE_CERTIFICATE_UNAVAILABLE_V1             = 28,
    IKE_UNSUPPORTED_EXCHANGE_TYPE_V1           = 29,
    IKE_UNEQUAL_PAYLOAD_LENGTHS_V1             = 30,
    IKE_UNSUPPORTED_CRITICAL_PAYLOAD_V2        = 1,
    IKE_INVALID_IKE_SPI_V2                     = 4,
    IKE_INVALID_MAJOR_VERSION_V2               = 5,
    IKE_INVALID_SYNTAX_V2                      = 7,
    IKE_INVALID_MESSAGE_ID_V2                  = 9,
    IKE_INVALID_SPI_V2                         = 11,
    IKE_NO_PROPOSAL_CHOSEN_V2                  = 14,
    IKE_INVALID_KE_PAYLOAD_V2                  = 17,
    IKE_AUTHENTICATION_FAILED_V2               = 24,
    IKE_SINGLE_PAIR_REQUIRED_V2                = 34,
    IKE_NO_ADDITIONAL_SAS_V2                   = 35,
    IKE_INTERNAL_ADDRESS_FAILURE_V2            = 36,
    IKE_FAILED_CP_REQUIRED_V2                  = 37,
    IKE_TS_UNACCEPTABLE_V2                     = 38,
    IKE_INVALID_SELECTORS_V2                   = 39,
    IKE_UNACCEPTABLE_ADDRESSES_V2              = 40,
    IKE_UNEXPECTED_NAT_DETECTED_V2             = 41,
    IKE_USE_ASSIGNED_HoA_V2                    = 42,
    IKE_TEMPORARY_FAILURE_V2                   = 43,
    IKE_CHILD_SA_NOT_FOUND_V2                  = 44,
    IKE_INVALID_GROUP_ID_V2                    = 45,
    IKE_AUTHORIZATION_FAILED_V2                = 46,
    /* status types */
    IKE_CONNECTED_V1                           = 16384,
    IKE_INITIAL_CONTACT_V2                     = 16384,
    IKE_SET_WINDOW_SIZE_V2                     = 16385,
    IKE_ADDITIONAL_TS_POSSIBLE_V2              = 16386,
    IKE_IPCOMP_SUPPORTED_V2                    = 16387,
    IKE_NAT_DETECTION_SOURCE_IP_V2             = 16388,
    IKE_NAT_DETECTION_DESTINATION_IP_V2        = 16389,
    IKE_COOKIE_V2                              = 16390,
    IKE_USE_TRANSPORT_MODE_V2                  = 16391,
    IKE_HTTP_CERT_LOOKUP_SUPPORTED_V2          = 16392,
    IKE_REKEY_SA_V2                            = 16393,
    IKE_ESP_TFC_PADDING_NOT_SUPPORTED_V2       = 16394,
    IKE_NON_FIRST_FRAGMENTS_ALSO_V2            = 16395,
    IKE_MOBIKE_SUPPORTED_V2                    = 16396,
    IKE_ADDITIONAL_IP4_ADDRESS_V2              = 16397,
    IKE_ADDITIONAL_IP6_ADDRESS_V2              = 16398,
    IKE_NO_ADDITIONAL_ADDRESSES_V2             = 16399,
    IKE_UPDATE_SA_ADDRESSES_V2                 = 16400,
    IKE_COOKIE2_V2                             = 16401,
    IKE_NO_NATS_ALLOWED_V2                     = 16402,
    IKE_AUTH_LIFETIME_V2                       = 16403,
    IKE_MULTIPLE_AUTH_SUPPORTED_V2             = 16404,
    IKE_ANOTHER_AUTH_FOLLOWS_V2                = 16405,
    IKE_REDIRECT_SUPPORTED_V2                  = 16406,
    IKE_REDIRECT_V2                            = 16407,
    IKE_REDIRECTED_FROM_V2                     = 16408,
    IKE_TICKET_LT_OPAQUE_V2                    = 16409,
    IKE_TICKET_REQUEST_V2                      = 16410,
    IKE_TICKET_ACK_V2                          = 16411,
    IKE_TICKET_NACK_V2                         = 16412,
    IKE_TICKET_OPAQUE_V2                       = 16413,
    IKE_LINK_ID_V2                             = 16414,
    IKE_USE_WESP_MODE_V2                       = 16415,
    IKE_ROHC_SUPPORTED_V2                      = 16416,
    IKE_EAP_ONLY_AUTHENTICATION_V2             = 16417,
    IKE_CHILDLESS_IKEV2_SUPPORTED_V2           = 16418,
    IKE_QUICK_CRASH_DETECTION_V2               = 16419,
    IKE_IKEV2_MESSAGE_ID_SYNC_SUPPORTED_V2     = 16420,
    IKE_IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED_V2 = 16421,
    IKE_IKEV2_MESSAGE_ID_SYNC_V2               = 16422,
    IKE_IPSEC_REPLAY_COUNTER_SYNC_V2           = 16423,
    IKE_SECURE_PASSWORD_METHODS_V2             = 16424,
    IKE_PSK_PERSIST_V2                         = 16425,
    IKE_PSK_CONFIRM_V2                         = 16426,
    IKE_ERX_SUPPORTED_V2                       = 16427,
    IKE_IFOM_CAPABILITY_V2                     = 16428,
    IKE_SENDER_REQUEST_ID_V2                   = 16429,
    IKE_IKEV2_FRAGMENTATION_SUPPORTED_V2       = 16430,
    IKE_SIGNATURE_HASH_ALGORITHMS_V2           = 16431,
    IKE_CLONE_IKE_SA_SUPPORTED_V2              = 16432,
    IKE_CLONE_IKE_SA_V2                        = 16433
};

/*
 * \brief Enumeration representing Security Protocol Identifiers
 */
enum ike_protocol_id {
    IKE_PROTO_RESERVED_V1       = 0,
    IKE_PROTO_ISAKMP_V1         = 1,
    IKE_PROTO_IPSEC_AH_V1       = 2,
    IKE_PROTO_IPSEC_ESP_V1      = 3,
    IKE_PROTO_IPCOMP_V1         = 4,
    IKE_PROTO_GIGABEAM_RADIO_V1 = 5,
    IKE_PROTO_RESERVED_V2       = 0,
    IKE_IKE_V2                  = 1,
    IKE_AH_V2                   = 2,
    IKE_ESP_V2                  = 3,
    IKE_FC_ESP_HEADER_V2        = 4,
    IKE_FC_CT_AUTHENTICATION_V2 = 5
};

/*
 * \brief Enumeration representing Integrity Algorithms
 */
enum ike_integrity_algorithm {
    IKE_AUTH_NONE_V2              = 0,
    IKE_AUTH_HMAC_MD5_96_V2       = 1,
    IKE_AUTH_HMAC_SHA1_96_V2      = 2,
    IKE_AUTH_DES_MAC_V2           = 3,
    IKE_AUTH_KPDK_MD5_V2          = 4,
    IKE_AUTH_AES_XCBC_96_V2       = 5,
    IKE_AUTH_HMAC_MD5_128_V2      = 6,
    IKE_AUTH_HMAC_SHA1_160_V2     = 7,
    IKE_AUTH_AES_CMAC_96_V2       = 8,
    IKE_AUTH_AES_128_GMAC_V2      = 9,
    IKE_AUTH_AES_192_GMAC_V2      = 10,
    IKE_AUTH_AES_256_GMAC_V2      = 11,
    IKE_AUTH_HMAC_SHA2_256_128_V2 = 12,
    IKE_AUTH_HMAC_SHA2_384_192_V2 = 13,
    IKE_AUTH_HMAC_SHA2_512_256_V2 = 14
};

/*
 * \brief Enumeration representing Extended Sequence Numbers Options
 */
enum ike_extended_sequence_numbers {
    IKE_NO_EXTENDED_SEQUENCE_NUMBERS_V2  = 0,
    IKE_YES_EXTENDED_SEQUENCE_NUMBERS_V2 = 1
};


/*
 * \brief Enumeration representing Certificate Encodings
 */
enum ike_certificate_encoding {
    IKE_PKCS7_WRAPPED_X509_CERTIFICATE_V2   = 1,
    IKE_PGP_CERTIFICATE_V2                  = 2,
    IKE_DNS_SIGNED_KEY_V2                   = 3,
    IKE_X509_CERTIFICATE_SIGNATURE_V2       = 4,
    IKE_KERBEROS_TOKEN_V2                   = 6,
    IKE_CERTIFICATE_REVOCATION_LIST_V2      = 7,
    IKE_AUTHORITY_REVOCATION_LIST_V2        = 8,
    IKE_SPKI_CERTIFICATE_V2                 = 9,
    IKE_X509_CERTIFICATE_ATTRIBUTE_V2       = 10,
    IKE_RAW_RSA_KEY_V2                      = 11,
    IKE_HASH_AND_URL_OF_X509_CERTIFICATE_V2 = 12,
    IKE_HASH_AND_URL_OF_X509_BUNDLE_V2      = 13,
    IKE_OCSP_CONTENT_V2                     = 14,
    IKE_RAW_PUBLIC_KEY_V2                   = 15
};

/*
 * \brief Enumeration representing Notification IPCOMP Options
 */
enum ike_notify_ipcomp {
    IKE_IPCOMP_OUI_V2     = 1,
    IKE_IPCOMP_DEFLATE_V2 = 2,
    IKE_IPCOMP_LZS_V2     = 3,
    IKE_IPCOMP_LZJH_V2    = 4
};

/*
 * \brief Enumeration representing Traffic Selectors
 */
enum ike_traffic_selector {
    IKE_TS_IPV4_ADDR_RANGE_V2 = 7,
    IKE_TS_IPV6_ADDR_RANGE_V2 = 8,
    IKE_TS_FC_ADDR_RANGE_V2   = 9
};

/*
 * \brief Enumeration representing Configuration Payload CFG Types
 */
enum ike_configuration_cfg_type {
    IKE_CFG_REQUEST_V2 = 1,
    IKE_CFG_REPLY_V2   = 2,
    IKE_CFG_SET_V2     = 3,
    IKE_CFG_ACK_V2     = 4
};

/*
 * \brief Enumeration representing Configuration Payload Attribute Types
 */
enum ike_configuration_attribute {
    IKE_INTERNAL_IP4_ADDRESS_V2         = 1,
    IKE_INTERNAL_IP4_NETMASK_V2         = 2,
    IKE_INTERNAL_IP4_DNS_V2             = 3,
    IKE_INTERNAL_IP4_NBNS_V2            = 4,
    IKE_INTERNAL_IP4_DHCP_V2            = 6,
    IKE_APPLICATION_VERSION_V2          = 7,
    IKE_INTERNAL_IP6_ADDRESS_V2         = 8,
    IKE_INTERNAL_IP6_DNS_V2             = 10,
    IKE_INTERNAL_IP6_DHCP_V2            = 12,
    IKE_INTERNAL_IP4_SUBNET_V2          = 13,
    IKE_SUPPORTED_ATTRIBUTES_V2         = 14,
    IKE_INTERNAL_IP6_SUBNET_V2          = 15,
    IKE_MIP6_HOME_PREFIX_V2             = 16,
    IKE_INTERNAL_IP6_LINK_V2            = 17,
    IKE_INTERNAL_IP6_PREFIX_V2          = 18,
    IKE_HOME_AGENT_ADDRESS_V2           = 19,
    IKE_P_CSCF_IP4_ADDRESS_V2           = 20,
    IKE_P_CSCF_IP6_ADDRESS_V2           = 21,
    IKE_FTT_KAT_V2                      = 22,
    IKE_EXTERNAL_SOURCE_IP4_NAT_INFO_V2 = 23
};

/*
 * \brief Enumeration representing Gateway Identities
 */
enum ike_gateway_identity {
    IKE_IPV4_V2 = 1,
    IKE_IPV6_V2 = 2,
    IKE_FQDN_V2 = 3
};

/*
 * \brief Enumeration representing ROHC Attributes
 */
enum ike_rohc_attribute {
    IKE_MAXIMUM_CONTEXT_IDENTIFIER_V2           = 1,
    IKE_ROHC_PROFILE_V2                         = 2,
    IKE_ROHC_INTEGRITY_ALGORITHM_V2             = 3,
    IKE_ROHC_ICV_LENGTH_IN_BYTES_V2             = 4,
    IKE_MAXIMUM_RECONSTRUCTED_RECEPTION_UNIT_V2 = 5
};

/*
 * \brief Enumeration representing Secure Password Methods
 */
enum ike_secure_password_methods {
    IKE_PACE_V2                      = 1,
    IKE_AUGPAKE_V2                   = 2,
    IKE_SECURE_PSK_AUTHENTICATION_V2 = 3
};

/*
 * \brief Database of vendor IDs
 */
static struct {
    char *desc;
    unsigned int len;
    char *id;
} ike_vendor_ids[] = {
    {"strongSwan", 16, 
      "\x88\x2f\xe5\x6d\x6f\xd2\x0d\xbc\x22\x51\x61\x3b\x2e\xbe\x5b\xeb"},
    {"XAuth", 8, 
      "\x09\x00\x26\x89\xdf\xd6\xb7\x12"},
    {"Dead Peer Detection", 16, 
      "\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00"},
    {"Cisco Unity", 16, 
      "\x12\xf5\xf2\x8c\x45\x71\x68\xa9\x70\x2d\x9f\xe2\x74\xcc\x01\x00"},
    {"FRAGMENTATION", 20, 
      "\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x80\x00\x00\x00"},
    {"MS NT5 ISAKMPOAKLEY", 20, 
      "\x1e\x2b\x51\x69\x05\x99\x1c\x7d\x7c\x96\xfc\xbf\xb5\x87\xe4\x61\x00\x00\x00\x00"},
    {"NAT-T (RFC 3947)", 16, 
      "\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f"},
      {"draft-ietf-ipsec-nat-t-ike-03", 16,
      "\x7d\x94\x19\xa6\x53\x10\xca\x6f\x2c\x17\x9d\x92\x15\x52\x9d\x56"},
    { "draft-ietf-ipsec-nat-t-ike-02", 16,
       "\xcd\x60\x46\x43\x35\xdf\x21\xf8\x7c\xfd\xb2\xfc\x68\xb6\xa4\x48"},
    { "draft-ietf-ipsec-nat-t-ike-02\\n", 16,
      "\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f"},
    { "draft-ietf-ipsec-nat-t-ike-08", 16,
      "\x8f\x8d\x83\x82\x6d\x24\x6b\x6f\xc7\xa8\xa6\xa4\x28\xc1\x1d\xe8"},
    { "draft-ietf-ipsec-nat-t-ike-07", 16,
      "\x43\x9b\x59\xf8\xba\x67\x6c\x4c\x77\x37\xae\x22\xea\xb8\xf5\x82"},
    { "draft-ietf-ipsec-nat-t-ike-06", 16,
      "\x4d\x1e\x0e\x13\x6d\xea\xfa\x34\xc4\xf3\xea\x9f\x02\xec\x72\x85"},
    { "draft-ietf-ipsec-nat-t-ike-05", 16,
      "\x80\xd0\xbb\x3d\xef\x54\x56\x5e\xe8\x46\x45\xd4\xc8\x5c\xe3\xee"},
    { "draft-ietf-ipsec-nat-t-ike-04", 16,
      "\x99\x09\xb6\x4e\xed\x93\x7c\x65\x73\xde\x52\xac\xe9\x52\xfa\x6b"},
    { "draft-ietf-ipsec-nat-t-ike-00", 16,
      "\x44\x85\x15\x2d\x18\xb6\xbb\xcd\x0b\xe8\xa8\x46\x95\x79\xdd\xcc"},
    { "draft-ietf-ipsec-nat-t-ike", 16,
      "\x4d\xf3\x79\x28\xe9\xfc\x4f\xd1\xb3\x26\x21\x70\xd5\x15\xc6\x62"},
    { "draft-stenberg-ipsec-nat-traversal-02", 16,
      "\x61\x05\xc4\x22\xe7\x68\x47\xe4\x3f\x96\x84\x80\x12\x92\xae\xcd"},
    { "draft-stenberg-ipsec-nat-traversal-01", 16,
      "\x27\xba\xb5\xdc\x01\xea\x07\x60\xea\x4e\x31\x90\xac\x27\xc0\xd0"}
};


static char *ike_payload_type_string(enum ike_payload_type s) {

    switch(s) {
    case IKE_NO_NEXT_PAYLOAD:
        return "no_next_payload";
    case IKE_SECURITY_ASSOCIATION_V1:
        return "security_association";
    case IKE_PROPOSAL_V1:
        return "proposal";
    case IKE_TRANSFORM_V1:
        return "transform";
    case IKE_KEY_EXCHANGE_V1:
        return "key_exchange";
    case IKE_IDENTIFICATION_V1:
        return "identification";
    case IKE_CERTIFICATE_V1:
        return "certificate";
    case IKE_CERTIFICATE_REQUEST_V1:
        return "certificate_request";
    case IKE_HASH_V1:
        return "hash";
    case IKE_SIGNATURE_V1:
        return "signature";
    case IKE_NONCE_V1:
        return "nonce";
    case IKE_NOTIFICATION_V1:
        return "notification";
    case IKE_DELETE_V1:
        return "delete";
    case IKE_VENDOR_ID_V1:
        return "vendor_id";
    case IKE_SA_KEK_PAYLOAD_V1:
        return "sa_kek_payload";
    case IKE_SA_TEK_PAYLOAD_V1:
        return "sa_tek_payload";
    case IKE_KEY_DOWNLOAD_V1:
        return "key_download";
    case IKE_SEQUENCE_NUMBER_V1:
        return "sequence_number";
    case IKE_PROOF_OF_POSSESSION_V1:
        return "proof_of_possession";
    case IKE_NAT_DISCOVERY_V1:
        return "nat_discovery";
    case IKE_NAT_ORIGINAL_ADDRESS_V1:
        return "nat_original_address";
    case IKE_GROUP_ASSOCIATED_POLICY_V1:
        return "group_associated_policy";
    case IKE_SECURITY_ASSOCIATION_V2:
        return "security_association";
    case IKE_KEY_EXCHANGE_V2:
        return "key_exchange";
    case IKE_IDENTIFICATION_INITIATOR_V2:
        return "identification_intiator";
    case IKE_IDENTIFICATION_RESPONDER_V2:
        return "identification_responder";
    case IKE_CERTIFICATE_V2:
        return "certificate";
    case IKE_CERTIFICATE_REQUEST_V2:
        return "certificate_request";
    case IKE_AUTHENTICATION_V2:
        return "authentication";
    case IKE_NONCE_V2:
        return "nonce";
    case IKE_NOTIFY_V2:
        return "notify";
    case IKE_DELETE_V2:
        return "delete";
    case IKE_VENDOR_ID_V2:
        return "vendor_id";
    case IKE_TRAFFIC_SELECTOR_INITIATOR_V2:
        return "traffic_selector_initiator";
    case IKE_TRAFFIC_SELECTOR_RESPONDER_V2:
        return "traffic_selector_responder";
    case IKE_ENCRYPTED_V2:
        return "encrypted";
    case IKE_CONFIGURATION_V2:
        return "configuration";
    case IKE_EXTENSIBLE_AUTHENTICATION_V2:
        return "extensible_authentication";
    case IKE_GENERIC_SECURE_PASSWORD_METHOD_V2:
        return "generic_secure_password_method";
    case IKE_GROUP_IDENTIFICATION_V2:
        return "group_identification";
    case IKE_GROUP_SECURITY_ASSOCIATION_V2:
        return "group_security_association";
    case IKE_KEY_DOWNLOAD_V2:
        return "key_download";
    case IKE_ENCRYPTED_AND_AUTHENTICATED_FRAGMENT_V2:
        return "encrypted_and_authenticated_fragment";
    default:
        return "unknown";
    }
}

static char *ike_exchange_type_string(enum ike_exchange_type s) {

    switch(s) {
    case IKE_EXCHANGE_TYPE_NONE_V1:
        return "exchange_type_none";
    case IKE_BASE_V1:
        return "base";
    case IKE_IDENTITY_PROTECTION_V1:
        return "identity_protection";
    case IKE_AUTHENTICATION_ONLY_V1:
        return "authentication_only";
    case IKE_AGGRESSIVE_V1:
        return "aggressive";
    case IKE_INFORMATIONAL_V1:
        return "informational";
    case IKE_QUICK_MODE_V1:
        return "quick_mode";
    case IKE_NEW_GROUP_MODE_V1:
        return "new_group_mode";
    case IKE_IKE_SA_INIT_V2:
        return "ike_sa_init";
    case IKE_IKE_AUTH_V2:
        return "ike_auth";
    case IKE_CREATE_CHILD_SA_V2:
        return "create_child_sa";
    case IKE_INFORMATIONAL_V2:
        return "informational";
    case IKE_IKE_SESSION_RESUME_V2:
        return "ike_session_resume";
    case IKE_GSA_AUTH_V2:
        return "gsa_auth";
    case IKE_GSA_REGISTRATION_V2:
        return "gsa_registration";
    case IKE_GSA_REKEY_V2:
        return "gsa_rekey";
    default:
        return "unknown";
    }
}

static char *ike_attribute_type_string(enum ike_attribute_type s) {

    switch (s) {
    case IKE_KEY_LENGTH_V2:
        return "key_length";
    default:
        return "unknown";
    }
}

static char *ike_attribute_type_v1_string(enum ike_attribute_type s) {

    switch (s) {
    case IKE_ENCRYPTION_ALGORITHM_V1:
        return "encryption_algorithm";
    case IKE_HASH_ALGORITHM_V1:
        return "hash_algorithm";
    case IKE_AUTHENTICATION_METHOD_V1:
        return "authentication_method";
    case IKE_GROUP_DESCRIPTION_V1:
        return "group_description";
    case IKE_GROUP_TYPE_V1:
        return "group_type";
    case IKE_GROUP_PRIME_IRREDUCIBLE_POLYNOMIAL_V1:
        return "group_prime_irreducible_polynomial";
    case IKE_GROUP_GENERATOR_ONE_V1:
        return "group_generator_one";
    case IKE_GROUP_GENERATOR_TWO_V1:
        return "group_generator_two";
    case IKE_GROUP_CURVE_A_V1:
        return "group_curve_a";
    case IKE_GROUP_CURVE_B_V1:
        return "group_curve_b";
    case IKE_LIFE_TYPE_V1:
        return "life_type";
    case IKE_LIFE_DURATION_V1:
        return "life_duration";
    case IKE_PRF_V1:
        return "prf";
    case IKE_KEY_LENGTH_V1:
        return "key_length";
    case IKE_FIELD_SIZE_V1:
        return "field_size";
    case IKE_GROUP_ORDER_V1:
        return "group_order";
    default:
        return "unknown";
    }
}

static char *ike_hash_algorithm_string(enum ike_hash_algorithm s) {

    switch (s) {
    case IKE_SHA1_V2:
        return "sha1";
    case IKE_SHA2_256_V2:
        return "sha2_256";
    case IKE_SHA2_384_V2:
        return "sha2_384";
    case IKE_SHA2_512_V2:
        return "sha2_512";
    default:
        return "unknown";
    }
}

static char *ike_hash_algorithm_v1_string(enum ike_hash_algorithm s) {

    switch (s) {
    case IKE_MD5_V1:
        return "md5";
    case IKE_SHA_V1:
        return "sha";
    case IKE_TIGER_V1:
        return "tiger";
    case IKE_SHA2_256_V1:
        return "sha2_256";
    case IKE_SHA2_384_V1:
        return "sha2_384";
    case IKE_SHA2_512_V1:
        return "sha2_512";
    default:
        return "unknown";
    }
}

static char *ike_authentication_method_string(enum ike_authentication_method s) {

    switch (s) {
    case IKE_RSA_DIGITAL_SIGNATURE_V2:
        return "rsa_digital_signature";
    case IKE_SHARED_KEY_MESSAGE_INTEGRITY_CODE_V2:
        return "shared_key_message_integrity_code";
    case IKE_DSSDIGITAL_SIGNATURE_V2:
        return "dssdigital_signature";
    case IKE_ECDSA_SHA256_P256_V2:
        return "ecdsa_sha256_p256";
    case IKE_ECDSA_SHA384_P384_V2:
        return "ecdsa_sha384_p384";
    case IKE_ECDSA_SHA512_P512_V2:
        return "ecdsa_sha512_p512";
    case IKE_GENERIC_SECURE_PASSWORD_AUTHENTICATION_METHOD_V2:
        return "generic_secure_password_authentication_method";
    case IKE_NULL_AUTHENTICATION_V2:
        return "null_authentication";
    case IKE_DIGITAL_SIGNATURE_V2:
        return "digital_signature";
    default:
        return "unknown";
    }
}

static char *ike_authentication_method_v1_string(enum ike_authentication_method s) {

    switch (s) {
    case IKE_PRE_SHARED_KEY_V1:
        return "pre_shared_key";
    case IKE_DSS_SIGNATURES_V1:
        return "dss_signatures";
    case IKE_RSA_SIGNATURES_V1:
        return "rsa_signatures";
    case IKE_ENCRYPTION_WITH_RSA_V1:
        return "encryption_with_rsa";
    case IKE_REVISED_ENCRYPTION_WITH_RSA_V1:
        return "revised_encryption_with_rsa";
    case IKE_ECDSA_SHA256_P256_CURVE_V1:
        return "ecdsa_sha256_p256_curve";
    case IKE_ECDSA_SHA384_P384_CURVE_V1:
        return "ecdsa_sha384_p384_curve";
    case IKE_ECDSA_SHA512_P521_CURVE_V1:
        return "ecdsa_sha512_p521_curve";
    default:
        return "unknown";
    }
}

static char *ike_encryption_algorithm_string(enum ike_encryption_algorithm s) {

    switch(s) {
    case IKE_ENCR_DES_IV64_V2:
        return "encr_des_iv64";
    case IKE_ENCR_DES_V2:
        return "encr_des";
    case IKE_ENCR_3DES_V2:
        return "encr_3des";
    case IKE_ENCR_RC5_V2:
        return "encr_rc5";
    case IKE_ENCR_IDEA_V2:
        return "encr_idea";
    case IKE_ENCR_CAST_V2:
        return "encr_cast";
    case IKE_ENCR_BLOWFISH_V2:
        return "encr_blowfish";
    case IKE_ENCR_3IDEA_V2:
        return "encr_3idea";
    case IKE_ENCR_DES_32_V2:
        return "encr_des_32";
    case IKE_ENCR_NULL_V2:
        return "encr_null";
    case IKE_ENCR_AES_CBC_V2:
        return "encr_aes_cbc";
    case IKE_ENCR_AES_CTR_V2:
        return "encr_aes_ctr";
    case IKE_ENCR_AES_CCM_8_V2:
        return "encr_aes_ccm_8";
    case IKE_ENCR_AES_CCM_12_V2:
        return "encr_aes_ccm_12";
    case IKE_ENCR_AES_CCM_16_V2:
        return "encr_aes_ccm_16";
    case IKE_ENCR_AES_GCM_8_V2:
        return "encr_aes_gcm_8";
    case IKE_ENCR_AES_GCM_12_V2:
        return "encr_aes_gcm_12";
    case IKE_ENCR_AES_GCM_V2:
        return "encr_aes_gcm";
    case IKE_ENCR_NULL_AUTH_AES_GMAC_V2:
        return "encr_null_auth_aes_gmac";
    case IKE_ENCR_CAMELLIA_CBC_V2:
        return "encr_camellia_cbc";
    case IKE_ENCR_CAMELLIA_CTR_V2:
        return "encr_camellia_ctr";
    case IKE_ENCR_CAMELLIA_CCM_8_V2:
        return "encr_camellia_ccm_8";
    case IKE_ENCR_CAMELLIA_CCM_12_V2:
        return "encr_camellia_ccm_12";
    case IKE_ENCR_CAMELLIA_CCM_16_V2:
        return "encr_camellia_ccm_16";
    case IKE_ENCR_CHACHA20_POLY1305_V2:
        return "encr_chacha20_poly1305";
    default:
        return "unknown";
    }
}

static char *ike_encryption_algorithm_v1_string(enum ike_encryption_algorithm s) {

    switch (s) {
    case IKE_ENCR_DES_CBC_V1:
        return "encr_des_cbc";
    case IKE_ENCR_IDEA_CBC_V1:
        return "encr_idea_cbc";
    case IKE_ENCR_BLOWFISH_CBC_V1:
        return "encr_blowfish_cbc";
    case IKE_ENCR_RC5_R16_B64_CBC_V1:
        return "encr_rc5_r16_b64_cbc";
    case IKE_ENCR_3DES_CBC_V1:
        return "encr_3des_cbc";
    case IKE_ENCR_CAST_CBC_V1:
        return "encr_cast_cbc";
    case IKE_ENCR_AES_CBC_V1:
        return "encr_aes_cbc";
    case IKE_ENCR_CAMELLIA_CBC_V1:
        return "encr_camellia_cbc";
    default:
        return "unknown";
    }
}

static char *ike_pseudorandom_function_string(enum ike_pseudorandom_function s) {

    switch(s) {
    case IKE_PRF_HMAC_MD5_V2:
        return "prf_hmac_md5";
    case IKE_PRF_HMAC_SHA1_V2:
        return "prf_hmac_sha1";
    case IKE_PRF_HMAC_TIGER_V2:
        return "prf_hmac_tiger";
    case IKE_PRF_AES128_XCBC_V2:
        return "prf_aes128_xcbc";
    case IKE_PRF_HMAC_SHA2_256_V2:
        return "prf_hmac_sha2_256";
    case IKE_PRF_HMAC_SHA2_384_V2:
        return "prf_hmac_sha2_384";
    case IKE_PRF_HMAC_SHA2_512_V2:
        return "prf_hmac_sha2_512";
    case IKE_PRF_AES128_CMAC_V2:
        return "prf_aes128_cmac";
    default:
        return "unknown";
    }
}

static char *ike_pseudorandom_function_v1_string(enum ike_pseudorandom_function s) {

    switch(s) {
    default:
        return "unknown";
    }
}

static char *ike_integrity_algorithm_string(enum ike_integrity_algorithm s) {

    switch(s) {
    case IKE_AUTH_NONE_V2:
        return "auth_none";
    case IKE_AUTH_HMAC_MD5_96_V2:
        return "auth_hmac_md5_96";
    case IKE_AUTH_HMAC_SHA1_96_V2:
        return "auth_hmac_sha1_96";
    case IKE_AUTH_DES_MAC_V2:
        return "auth_des_mac";
    case IKE_AUTH_KPDK_MD5_V2:
        return "auth_kpdk_md5";
    case IKE_AUTH_AES_XCBC_96_V2:
        return "auth_aes_xcbc_96";
    case IKE_AUTH_HMAC_MD5_128_V2:
        return "auth_hmac_md5_128";
    case IKE_AUTH_HMAC_SHA1_160_V2:
        return "auth_hmac_sha1_160";
    case IKE_AUTH_AES_CMAC_96_V2:
        return "auth_aes_cmac_96";
    case IKE_AUTH_AES_128_GMAC_V2:
        return "auth_aes_128_gmac";
    case IKE_AUTH_AES_192_GMAC_V2:
        return "auth_aes_192_gmac";
    case IKE_AUTH_AES_256_GMAC_V2:
        return "auth_aes_256_gmac";
    case IKE_AUTH_HMAC_SHA2_256_128_V2:
        return "auth_hmac_sha2_256_128";
    case IKE_AUTH_HMAC_SHA2_384_192_V2:
        return "auth_hmac_sha2_384_192";
    case IKE_AUTH_HMAC_SHA2_512_256_V2:
        return "auth_hmac_sha2_512_256";
    default:
        return "unknown";
    }
}

static char *ike_diffie_hellman_group_string(enum ike_diffie_hellman_group s) {

    switch(s) {
    case IKE_DH_GROUP_NONE_V2:
        return "dh_group_none";
    case IKE_DH_MODP768_V2:
        return "dh_modp768";
    case IKE_DH_MODP1024_V2:
        return "dh_modp1024";
    case IKE_DH_MODP1536_V2:
        return "dh_modp1536";
    case IKE_DH_MODP2048_V2:
        return "dh_modp2048";
    case IKE_DH_MODP3072_V2:
        return "dh_modp3072";
    case IKE_DH_MODP4096_V2:
        return "dh_modp4096";
    case IKE_DH_MODP6144_V2:
        return "dh_modp6144";
    case IKE_DH_MODP8192_V2:
        return "dh_modp8192";
    case IKE_DH_P256_V2:
        return "dh_p256";
    case IKE_DH_P384_V2:
        return "dh_p384";
    case IKE_DH_P521_V2:
        return "dh_p521";
    case IKE_DH_MODP1024_S160_V2:
        return "dh_modp1024_s160";
    case IKE_DH_MODP2048_S224_V2:
        return "dh_modp2048_s224";
    case IKE_DH_MODP2048_S256_V2:
        return "dh_modp2048_s256";
    case IKE_DH_P192_V2:
        return "dh_p192";
    case IKE_DH_P224_V2:
        return "dh_p224";
    case IKE_DH_BRAINPOOL_P224_V2:
        return "dh_brainpool_p224";
    case IKE_DH_BRAINPOOL_P256_V2:
        return "dh_brainpool_p256";
    case IKE_DH_BRAINPOOL_P384_V2:
        return "dh_brainpool_p384";
    case IKE_DH_BRAINPOOL_P512_V2:
        return "dh_brainpool_p512";
    case IKE_DH_CURVE25519_V2:
        return "dh_curve25519";
    case IKE_DH_CURVE448_V2:
        return "dh_curve448";
    default:
        return "unknown";
    }
}

static char *ike_diffie_hellman_group_v1_string(enum ike_diffie_hellman_group s) {

    switch(s) {
    case IKE_DH_GROUP_NONE_V1:
        return "dh_group_none";
    case IKE_DH_MODP768_V1:
        return "dh_modp768";
    case IKE_DH_MODP1024_V1:
        return "dh_modp1024";
    case IKE_DH_T155_V1:
        return "dh_t155";
    case IKE_DH_T185_V1:
        return "dh_t185";
    case IKE_DH_MODP1536_V1:
        return "dh_modp1536";
    case IKE_DH_T163R1_V1:
        return "dh_t163r1";
    case IKE_DH_T163K1_V1:
        return "dh_t163k1";
    case IKE_DH_T283R1_V1:
        return "dh_t283r1";
    case IKE_DH_T283K1_V1:
        return "dh_t283k1";
    case IKE_DH_T409R1_V1:
        return "dh_t409r1";
    case IKE_DH_T409K1_V1:
        return "dh_t409k1";
    case IKE_DH_T571R1_V1:
        return "dh_t571r1";
    case IKE_DH_T571K1_V1:
        return "dh_t571k1";
    case IKE_DH_MODP2048_V1:
        return "dh_modp2048";
    case IKE_DH_MODP3072_V1:
        return "dh_modp3072";
    case IKE_DH_MODP4096_V1:
        return "dh_modp4096";
    case IKE_DH_MODP6144_V1:
        return "dh_modp6144";
    case IKE_DH_MODP8192_V1:
        return "dh_modp8192";
    case IKE_DH_P256_V1:
        return "dh_p256";
    case IKE_DH_P384_V1:
        return "dh_p384";
    case IKE_DH_P521_V1:
        return "dh_p521";
    case IKE_DH_MODP1024_S160_V1:
        return "dh_modp1024_s160";
    case IKE_DH_MODP2048_S224_V1:
        return "dh_modp2048_s224";
    case IKE_DH_MODP2048_S256_V1:
        return "dh_modp2048_s256";
    case IKE_DH_P192_V1:
        return "dh_p192";
    case IKE_DH_P224_V1:
        return "dh_p224";
    case IKE_DH_BRAINPOOL_P224_V1:
        return "dh_brainpool_p224";
    case IKE_DH_BRAINPOOL_P256_V1:
        return "dh_brainpool_p256";
    case IKE_DH_BRAINPOOL_P384_V1:
        return "dh_brainpool_p384";
    case IKE_DH_BRAINPOOL_P512_V1:
        return "dh_brainpool_p512";
    default:
        return "unknown";
    }
}

static char *ike_extended_sequence_numbers_string(enum ike_extended_sequence_numbers s) {

    switch(s) {
    case IKE_NO_EXTENDED_SEQUENCE_NUMBERS_V2:
        return "no_extended_sequence_numbers";
    case IKE_YES_EXTENDED_SEQUENCE_NUMBERS_V2:
        return "yes_extended_sequence_numbers";
    default:
        return "unknown";
    }
}

static char *ike_transform_type_string(enum ike_transform_type s) {

    switch (s) {
    case IKE_ENCRYPTION_ALGORITHM_V2:
        return "encryption_algorithm";
    case IKE_PSEUDORANDOM_FUNCTION_V2:
        return "pseudorandom_function";
    case IKE_INTEGRITY_ALGORITHM_V2:
        return "integrity_algorithm";
    case IKE_DIFFIE_HELLMAN_GROUP_V2:
        return "diffie_hellman_group";
    case IKE_EXTENDED_SEQUENCE_NUMBERS_V2:
        return "extended_sequence_numbers";
    default:
        return "unknown";
    }
}

static char *ike_transform_id_string(enum ike_transform_type s, uint16_t id) {

    switch (s) {
    case IKE_ENCRYPTION_ALGORITHM_V2:
        return ike_encryption_algorithm_string(id);
    case IKE_PSEUDORANDOM_FUNCTION_V2:
        return ike_pseudorandom_function_string(id);
    case IKE_INTEGRITY_ALGORITHM_V2:
        return ike_integrity_algorithm_string(id);
    case IKE_DIFFIE_HELLMAN_GROUP_V2:
        return ike_diffie_hellman_group_string(id);
    case IKE_EXTENDED_SEQUENCE_NUMBERS_V2:
        return ike_extended_sequence_numbers_string(id);
    default:
        return "unknown";
    }
}

static char *ike_transform_id_v1_string(enum ike_transform_id_v1 s) {

    switch (s) {
    case IKE_KEY_IKE_V1:
        return "key_ike";
    default:
        return "unknown";
    }
}

static char *ike_identification_type_string(enum ike_identification_type s) {

    switch (s) {
    case IKE_ID_IPV4_ADDR_V2:
        return "id_ipv4_addr";
    case IKE_ID_FQDN_V2:
        return "id_fqdn";
    case IKE_ID_RFC822_ADDR_V2:
        return "id_rfc822_addr";
    case IKE_ID_IPV6_ADDR_V2:
        return "id_ipv6_addr";
    case IKE_ID_DER_ASN1_DN_V2:
        return "id_der_asn1_dn";
    case IKE_ID_DER_ASN1_GN_V2:
        return "id_der_asn1_gn";
    case IKE_ID_KEY_ID_V2:
        return "id_key_id";
    case IKE_ID_FC_NAME_V2:
        return "id_fc_name";
    case IKE_ID_NULL_V2:
        return "id_null";
    default:
        return "unknown";
    }
}

static char *ike_identification_type_v1_string(enum ike_identification_type s) {

    switch (s) {
    case IKE_ID_IPV4_ADDR_V1:
        return "id_ipv4_addr";
    case IKE_ID_FQDN_V1:
        return "id_fqdn";
    case IKE_ID_USER_FQDN_V1:
        return "id_user_fqdn";
    case IKE_ID_IPV4_ADDR_SUBNET_V1:
        return "id_ipv4_addr_subnet";
    case IKE_ID_IPV6_ADDR_V1:
        return "id_ipv6_addr";
    case IKE_ID_IPV6_ADDR_SUBNET_V1:
        return "id_ipv6_addr_subnet";
    case IKE_ID_IPV4_ADDR_RANGE_V1:
        return "id_ipv4_addr_range";
    case IKE_ID_IPV6_ADDR_RANGE_V1:
        return "id_ipv6_addr_range";
    case IKE_ID_DER_ASN1_DN_V1:
        return "id_der_asn1_dn";
    case IKE_ID_DER_ASN1_GN_V1:
        return "id_der_asn1_gn";
    case IKE_ID_KEY_ID_V1:
        return "id_key_id";
    default:
        return "unknown";
    }
}

static char *ike_certificate_encoding_string(enum ike_certificate_encoding s) {

    switch (s) {
    case IKE_PKCS7_WRAPPED_X509_CERTIFICATE_V2:
        return "pkcs7_wrapped_x509_certificate";
    case IKE_PGP_CERTIFICATE_V2:
        return "pgp_certificate";
    case IKE_DNS_SIGNED_KEY_V2:
        return "dns_signed_key";
    case IKE_X509_CERTIFICATE_SIGNATURE_V2:
        return "x509_certificate_signature";
    case IKE_KERBEROS_TOKEN_V2:
        return "kerberos_token";
    case IKE_CERTIFICATE_REVOCATION_LIST_V2:
        return "certificate_revocation_list";
    case IKE_AUTHORITY_REVOCATION_LIST_V2:
        return "authority_revocation_list";
    case IKE_SPKI_CERTIFICATE_V2:
        return "spki_certificate";
    case IKE_X509_CERTIFICATE_ATTRIBUTE_V2:
        return "x509_certificate_attribute";
    case IKE_RAW_RSA_KEY_V2:
        return "raw_rsa_key";
    case IKE_HASH_AND_URL_OF_X509_CERTIFICATE_V2:
        return "hash_and_url_of_x509_certificate";
    case IKE_HASH_AND_URL_OF_X509_BUNDLE_V2:
        return "hash_and_url_of_x509_bundle";
    case IKE_OCSP_CONTENT_V2:
        return "ocsp_content";
    case IKE_RAW_PUBLIC_KEY_V2:
        return "raw_public_key";
    default:
        return "unknown";
    }
}

static char *ike_protocol_id_string(enum ike_protocol_id s) {

    switch (s) {
    case IKE_PROTO_RESERVED_V2:
        return "reserved";
    case IKE_IKE_V2:
        return "ike";
    case IKE_AH_V2:
        return "ah";
    case IKE_ESP_V2:
        return "esp";
    case IKE_FC_ESP_HEADER_V2:
        return "fc_esp_header";
    case IKE_FC_CT_AUTHENTICATION_V2:
        return "fc_ct_authentication";
    default:
        return "unknown";
    }
}

static char *ike_protocol_id_v1_string(enum ike_protocol_id s) {

    switch (s) {
    case IKE_PROTO_RESERVED_V1:
        return "reserved";
    case IKE_PROTO_ISAKMP_V1:
        return "proto_isakmp";
    case IKE_PROTO_IPSEC_AH_V1:
        return "proto_ipsec_ah";
    case IKE_PROTO_IPSEC_ESP_V1:
        return "proto_ipsec_esp";
    case IKE_PROTO_IPCOMP_V1:
        return "proto_ipcomp";
    case IKE_PROTO_GIGABEAM_RADIO_V1:
        return "proto_gigabeam_radio";
    default:
        return "unknown";
    }
}

static char *ike_notify_string(enum ike_notify_type s) {

    switch (s) {
    case IKE_UNSUPPORTED_CRITICAL_PAYLOAD_V2:
        return "unsupported_critical_payload";
    case IKE_INVALID_IKE_SPI_V2:
        return "invalid_ike_spi";
    case IKE_INVALID_MAJOR_VERSION_V2:
        return "invalid_major_version";
    case IKE_INVALID_SYNTAX_V2:
        return "invalid_syntax";
    case IKE_INVALID_MESSAGE_ID_V2:
        return "invalid_message_id";
    case IKE_INVALID_SPI_V2:
        return "invalid_spi";
    case IKE_NO_PROPOSAL_CHOSEN_V2:
        return "no_proposal_chosen";
    case IKE_INVALID_KE_PAYLOAD_V2:
        return "invalid_ke_payload";
    case IKE_AUTHENTICATION_FAILED_V2:
        return "authentication_failed";
    case IKE_SINGLE_PAIR_REQUIRED_V2:
        return "single_pair_required";
    case IKE_NO_ADDITIONAL_SAS_V2:
        return "no_additional_sas";
    case IKE_INTERNAL_ADDRESS_FAILURE_V2:
        return "internal_address_failure";
    case IKE_FAILED_CP_REQUIRED_V2:
        return "failed_cp_required";
    case IKE_TS_UNACCEPTABLE_V2:
        return "ts_unacceptable";
    case IKE_INVALID_SELECTORS_V2:
        return "invalid_selectors";
    case IKE_UNACCEPTABLE_ADDRESSES_V2:
        return "unacceptable_addresses";
    case IKE_UNEXPECTED_NAT_DETECTED_V2:
        return "unexpected_nat_detected";
    case IKE_USE_ASSIGNED_HoA_V2:
        return "use_assigned_hoa";
    case IKE_TEMPORARY_FAILURE_V2:
        return "temporary_failure";
    case IKE_CHILD_SA_NOT_FOUND_V2:
        return "child_sa_not_found";
    case IKE_INVALID_GROUP_ID_V2:
        return "invalid_group_id";
    case IKE_AUTHORIZATION_FAILED_V2:
        return "authorization_failed";
    case IKE_INITIAL_CONTACT_V2:
        return "initial_contact";
    case IKE_SET_WINDOW_SIZE_V2:
        return "set_window_size";
    case IKE_ADDITIONAL_TS_POSSIBLE_V2:
        return "additional_ts_possible";
    case IKE_IPCOMP_SUPPORTED_V2:
        return "ipcomp_supported";
    case IKE_NAT_DETECTION_SOURCE_IP_V2:
        return "nat_detection_source_ip";
    case IKE_NAT_DETECTION_DESTINATION_IP_V2:
        return "nat_detection_destination_ip";
    case IKE_COOKIE_V2:
        return "cookie";
    case IKE_USE_TRANSPORT_MODE_V2:
        return "use_transport_mode";
    case IKE_HTTP_CERT_LOOKUP_SUPPORTED_V2:
        return "http_cert_lookup_supported";
    case IKE_REKEY_SA_V2:
        return "rekey_sa";
    case IKE_ESP_TFC_PADDING_NOT_SUPPORTED_V2:
        return "esp_tfc_padding_not_supported";
    case IKE_NON_FIRST_FRAGMENTS_ALSO_V2:
        return "non_first_fragments_also";
    case IKE_MOBIKE_SUPPORTED_V2:
        return "mobike_supported";
    case IKE_ADDITIONAL_IP4_ADDRESS_V2:
        return "additional_ip4_address";
    case IKE_ADDITIONAL_IP6_ADDRESS_V2:
        return "additional_ip6_address";
    case IKE_NO_ADDITIONAL_ADDRESSES_V2:
        return "no_additional_addresses";
    case IKE_UPDATE_SA_ADDRESSES_V2:
        return "update_sa_addresses";
    case IKE_COOKIE2_V2:
        return "cookie2";
    case IKE_NO_NATS_ALLOWED_V2:
        return "no_nats_allowed";
    case IKE_AUTH_LIFETIME_V2:
        return "auth_lifetime";
    case IKE_MULTIPLE_AUTH_SUPPORTED_V2:
        return "multiple_auth_supported";
    case IKE_ANOTHER_AUTH_FOLLOWS_V2:
        return "another_auth_follows";
    case IKE_REDIRECT_SUPPORTED_V2:
        return "redirect_supported";
    case IKE_REDIRECT_V2:
        return "redirect";
    case IKE_REDIRECTED_FROM_V2:
        return "redirected_from";
    case IKE_TICKET_LT_OPAQUE_V2:
        return "ticket_lt_opaque";
    case IKE_TICKET_REQUEST_V2:
        return "ticket_request";
    case IKE_TICKET_ACK_V2:
        return "ticket_ack";
    case IKE_TICKET_NACK_V2:
        return "ticket_nack";
    case IKE_TICKET_OPAQUE_V2:
        return "ticket_opaque";
    case IKE_LINK_ID_V2:
        return "link_id";
    case IKE_USE_WESP_MODE_V2:
        return "use_wesp_mode";
    case IKE_ROHC_SUPPORTED_V2:
        return "rohc_supported";
    case IKE_EAP_ONLY_AUTHENTICATION_V2:
        return "eap_only_authentication";
    case IKE_CHILDLESS_IKEV2_SUPPORTED_V2:
        return "childless_ikev2_supported";
    case IKE_QUICK_CRASH_DETECTION_V2:
        return "quick_crash_detection";
    case IKE_IKEV2_MESSAGE_ID_SYNC_SUPPORTED_V2:
        return "ikev2_message_id_sync_supported";
    case IKE_IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED_V2:
        return "ipsec_replay_counter_sync_supported";
    case IKE_IKEV2_MESSAGE_ID_SYNC_V2:
        return "ikev2_message_id_sync";
    case IKE_IPSEC_REPLAY_COUNTER_SYNC_V2:
        return "ipsec_replay_counter_sync";
    case IKE_SECURE_PASSWORD_METHODS_V2:
        return "secure_password_methods";
    case IKE_PSK_PERSIST_V2:
        return "psk_persist";
    case IKE_PSK_CONFIRM_V2:
        return "psk_confirm";
    case IKE_ERX_SUPPORTED_V2:
        return "erx_supported";
    case IKE_IFOM_CAPABILITY_V2:
        return "ifom_capability";
    case IKE_SENDER_REQUEST_ID_V2:
        return "sender_request_id";
    case IKE_IKEV2_FRAGMENTATION_SUPPORTED_V2:
        return "ikev2_fragmentation_supported";
    case IKE_SIGNATURE_HASH_ALGORITHMS_V2:
        return "signature_hash_algorithms";
    case IKE_CLONE_IKE_SA_SUPPORTED_V2:
        return "clone_ike_sa_supported";
    case IKE_CLONE_IKE_SA_V2:
        return "clone_ike_sa";
    default:
        return "unknown";
    }
}

static char *ike_notify_v1_string(enum ike_notify_type s) {

    switch (s) {
    case IKE_INVALID_PAYLOAD_TYPE_V1:
        return "invalid_payload_type";
    case IKE_DOI_NOT_SUPPORTED_V1:
        return "doi_not_supported";
    case IKE_SITUATION_NOT_SUPPORTED_V1:
        return "situation_not_supported";
    case IKE_INVALID_COOKIE_V1:
        return "invalid_cookie";
    case IKE_INVALID_MAJOR_VERSION_V1:
        return "invalid_major_version";
    case IKE_INVALID_MINOR_VERSION_V1:
        return "invalid_minor_version";
    case IKE_INVALID_EXCHANGE_TYPE_V1:
        return "invalid_exchange_type";
    case IKE_INVALID_FLAGS_V1:
        return "invalid_flags";
    case IKE_INVALID_MESSAGE_ID_V1:
        return "invalid_message_id";
    case IKE_INVALID_PROTOCOL_ID_V1:
        return "invalid_protocol_id";
    case IKE_INVALID_SPI_V1:
        return "invalid_spi";
    case IKE_INVALID_TRANSFORM_ID_V1:
        return "invalid_transform_id";
    case IKE_ATTRIBUTES_NOT_SUPPORTED_V1:
        return "attributes_not_supported";
    case IKE_NO_PROPOSAL_CHOSEN_V1:
        return "no_proposal_chosen";
    case IKE_BAD_PROPOSAL_SYNTAX_V1:
        return "bad_proposal_syntax";
    case IKE_PAYLOAD_MALFORMED_V1:
        return "payload_malformed";
    case IKE_INVALID_KEY_INFORMATION_V1:
        return "invalid_key_information";
    case IKE_INVALID_ID_INFORMATION_V1:
        return "invalid_id_information";
    case IKE_INVALID_CERT_ENCODING_V1:
        return "invalid_cert_encoding";
    case IKE_INVALID_CERTIFICATE_V1:
        return "invalid_certificate";
    case IKE_CERT_TYPE_UNSUPPORTED_V1:
        return "cert_type_unsupported";
    case IKE_INVALID_CERT_AUTHORITY_V1:
        return "invalid_cert_authority";
    case IKE_INVALID_HASH_INFORMATION_V1:
        return "invalid_hash_information";
    case IKE_AUTHENTICATION_FAILED_V1:
        return "authentication_failed";
    case IKE_INVALID_SIGNATURE_V1:
        return "invalid_signature";
    case IKE_ADDRESS_NOTIFICATION_V1:
        return "address_notification";
    case IKE_NOTIFY_SA_LIFETIME_V1:
        return "notify_sa_lifetime";
    case IKE_CERTIFICATE_UNAVAILABLE_V1:
        return "certificate_unavailable";
    case IKE_UNSUPPORTED_EXCHANGE_TYPE_V1:
        return "unsupported_exchange_type";
    case IKE_UNEQUAL_PAYLOAD_LENGTHS_V1:
        return "unequal_payload_lengths";
    case IKE_CONNECTED_V1:
        return "connected";
    default:
        return "unknown";
    }
}

static char *ike_doi_v1_string(enum ike_doi_v1 s) {

    switch (s) {
    case IKE_ISAKMP_V1:
        return "isakmp";
    case IKE_IPSEC_V1:
        return "ipsec";
    case IKE_GDOI_V1:
        return "gdoi";
    default:
        return "unknown";
    }
}

static char *ike_life_type_v1_string(enum ike_life_type s) {

    switch (s) {
    case IKE_SECONDS_V1:
        return "seconds";
    case IKE_KILIBYTES_V1:
        return "kilobytes";
    default:
        return "unknown";
    }
}

static char *ike_group_type_v1_string(enum ike_group_type s) {

    switch (s) {
    case IKE_MODP_V1:
        return "modp";
    case IKE_ECP_V1:
        return "ecp";
    case IKE_EC2N_V1:
        return "ec2n";
    default:
        return "unknown";
    }
}

static void ike_attribute_print_json(struct ike_attribute *s, zfile f) {
    uint16_t value;
    
    if (s->encoding == 1) {
        value = raw_to_uint16((char *)s->data->bytes);
    }

    zprintf(f, "{");
    zprintf(f, "\"type\":[%u,\"%s\"]", s->type, ike_attribute_type_string(s->type));
    zprintf(f, ",\"data\":[");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, ",\"");
    switch (s->type) {
    case IKE_KEY_LENGTH_V2:
        zprintf(f, "%u bits", value);
        break;
    default:
        break;
    }
    zprintf(f, "\"]}");
}

static void ike_attribute_v1_print_json(struct ike_attribute *s, zfile f) {
    uint16_t value;

    if (s->encoding == 1) {
        value = raw_to_uint16((char *)s->data->bytes);
    }
    zprintf(f, "{");
    zprintf(f, "\"type\":[%u,\"%s\"]", s->type, ike_attribute_type_v1_string(s->type));
    zprintf(f, ",\"data\":[");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, ",\"");
    switch (s->type) {
    /* fixed-length encoding */
    case IKE_ENCRYPTION_ALGORITHM_V1:
        zprintf(f, "%s", ike_encryption_algorithm_v1_string(value));
        break;
    case IKE_HASH_ALGORITHM_V1:
        zprintf(f, "%s", ike_hash_algorithm_v1_string(value));
        break;
    case IKE_AUTHENTICATION_METHOD_V1:
        zprintf(f, "%s", ike_authentication_method_v1_string(value));
        break;
    case IKE_GROUP_DESCRIPTION_V1:
        zprintf(f, "%s", ike_diffie_hellman_group_v1_string(value));
        break;
    case IKE_GROUP_TYPE_V1:
        zprintf(f, "%s", ike_group_type_v1_string(value));
        break;
    case IKE_LIFE_TYPE_V1:
        zprintf(f, "%s", ike_life_type_v1_string(value));
        break;
    case IKE_PRF_V1:
        zprintf(f, "%s", ike_pseudorandom_function_v1_string(value));
        break;
    case IKE_KEY_LENGTH_V1:
        zprintf(f, "%u bits", value);
        break;
    case IKE_FIELD_SIZE_V1:
        zprintf(f, "%u bits", value);
        break;
    /* variable-length encoding */
    case IKE_GROUP_PRIME_IRREDUCIBLE_POLYNOMIAL_V1:
        break;
    case IKE_GROUP_GENERATOR_ONE_V1:
        break;
    case IKE_GROUP_GENERATOR_TWO_V1:
        break;
    case IKE_GROUP_CURVE_A_V1:
        break;
    case IKE_GROUP_CURVE_B_V1:
        break;
    case IKE_LIFE_DURATION_V1:
        break;
    case IKE_GROUP_ORDER_V1:
        break;
    default:
        break;
    }
    zprintf(f, "\"]}");
}

static void ike_attribute_delete(struct ike_attribute **s_handle) {
    struct ike_attribute *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_attribute_init(struct ike_attribute **s_handle) {
    
    if (*s_handle != NULL) {
        ike_attribute_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_attribute));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_attribute_unmarshal(struct ike_attribute *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;

    if (len < 4) {
        joy_log_err("len %u < 4", len);
        return 0;
    }

    s->encoding = (x[offset]&0x80) >> 7; // first bit determines TLV (0) or TV (1) encoding
    s->type = (raw_to_uint16(x+offset) & 0x7fff); offset+=2;
    vector_init(&s->data);

    if (s->encoding == 0) {
        // TLV format
        length = raw_to_uint16(x+offset); offset+=2;
        if (length > len-offset) {
            joy_log_err("length %u > len-offset %u", length, len-offset)
            return 0;
        }
        vector_set(s->data, x+offset, length); offset+=length;
    } else {
        // TV format
        if (len-offset < 2) {
            joy_log_err("len-offset %u < 2", len-offset);
            return 0;
        }
        vector_set(s->data, x+offset, 2); offset+=2;
    }

    return offset;
}

static void ike_transform_print_json(struct ike_transform *s, zfile f) {
    int i;

    zprintf(f, "{");
    zprintf(f, "\"type\":[%u,\"%s\"]", s->type, ike_transform_type_string(s->type));
    zprintf(f, ",\"id\":[%u,\"%s\"]", s->id, ike_transform_id_string(s->type, s->id));
    for (i = 0; i < s->num_attributes; i++) {
        if (i == 0) {
            zprintf(f, ",\"attributes\":[");
        } else {
            zprintf(f, ",");
        }
        ike_attribute_print_json(s->attributes[i], f);
        if (i == s->num_attributes-1) {
            zprintf(f, "]");
        }
    }
    zprintf(f, "}");
}

static void ike_transform_v1_print_json(struct ike_transform *s, zfile f) {
    int i;

    zprintf(f, "{");
    zprintf(f, "\"id\":[%u,\"%s\"]", s->id_v1, ike_transform_id_v1_string(s->id_v1));
    zprintf(f, ",\"num\":\"%u\"", s->num_v1);
    for (i = 0; i < s->num_attributes; i++) {
        if (i == 0) {
            zprintf(f, ",\"attributes\":[");
        } else {
            zprintf(f, ",");
        }
        ike_attribute_v1_print_json(s->attributes[i], f);
        if (i == s->num_attributes-1) {
            zprintf(f, "]");
        }
    }
    zprintf(f, "}");
}

static void ike_transform_delete(struct ike_transform **s_handle) {
    struct ike_transform *s = *s_handle;
    int i;

    if (s == NULL) {
        return;
    }
    for (i = 0; i < s->num_attributes; i++) {
        ike_attribute_delete(&s->attributes[i]);
    }

    free(s);
    *s_handle = NULL;
}

static void ike_transform_init(struct ike_transform **s_handle) {

    if (*s_handle != NULL) {
        ike_transform_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_transform));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_transform_unmarshal(struct ike_transform *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;

    if (len < 8) {
        joy_log_err("len %u < 8", len);
        return 0;
    }
    s->last = x[offset]; offset++;
    offset++; /* reserved */
    s->length = raw_to_uint16(x+offset); offset+=2;
    s->type = x[offset]; offset++;
    offset++; /* reserved */
    s->id = raw_to_uint16(x+offset); offset+=2;

    if (s->length > len) {
        joy_log_err("s->length %u > len %u", s->length, len);
        return 0;
    }

    /* parse attributes */
    s->num_attributes = 0;
    while(offset < s->length && s->num_attributes < IKE_MAX_ATTRIBUTES) {
        ike_attribute_init(&s->attributes[s->num_attributes]);
        length = ike_attribute_unmarshal(s->attributes[s->num_attributes], x+offset, len-offset);
        if (length == 0) {
            joy_log_err("unable to unmarshal attribute");
            return 0;
        }

        offset += length;
        s->num_attributes++;
    }

    /* check that the length matches exactly */
    if (offset != s->length) {
        joy_log_err("offset %u != s->length %u", offset, s->length)
        return 0;
    }

    return offset;
}

static unsigned int ike_transform_v1_unmarshal(struct ike_transform *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;

    if (len < 8) {
        joy_log_err("len %u < 8", len);
        return 0;
    }

    s->last = x[offset]; offset++;
    offset++; /* reserved */
    s->length = raw_to_uint16(x+offset); offset+=2;
    s->num_v1 = x[offset]; offset++;
    s->id_v1 = x[offset]; offset++;
    offset+=2; /* reserved */

    if (s->length > len) {
        joy_log_err("s->length %u > len %u", s->length, len);
        return 0;
    }

    /* parse attributes */
    s->num_attributes = 0;
    while(offset < s->length && s->num_attributes < IKE_MAX_ATTRIBUTES) {
        ike_attribute_init(&s->attributes[s->num_attributes]);
        length = ike_attribute_unmarshal(s->attributes[s->num_attributes], x+offset, len-offset);
        if (length == 0) {
            joy_log_err("unable to unmarshal attribute");
            return 0;
        }

        offset += length;
        s->num_attributes++;
    }

    /* check that the length matches exactly */
    if (offset != s->length) {
        joy_log_err("offset %u != s->length %u", offset, s->length)
        return 0;
    }

    return offset;
}

static void ike_proposal_print_json(struct ike_proposal *s, zfile f) {
    int i;

    zprintf(f, "{");
    zprintf(f, "\"num\":%u", s->num);
    zprintf(f, ",\"protocol_id\":[%u,\"%s\"]", s->protocol_id, ike_protocol_id_string(s->protocol_id));
    zprintf(f, ",\"spi\":");
    zprintf_raw_as_hex(f, s->spi->bytes, s->spi->len);
    if (s->num_transforms > 0) {
        zprintf(f, ",\"transforms\":[");
        for (i = 0; i < s->num_transforms; i++) {
            if (i > 0) {
                zprintf(f, ",");
            }
            ike_transform_print_json(s->transforms[i], f);
        }
        zprintf(f, "]");
    }
    zprintf(f, "}");
}

static void ike_proposal_v1_print_json(struct ike_proposal *s, zfile f) {
    int i;

    zprintf(f, "{");
    zprintf(f, "\"num\":%u", s->num);
    zprintf(f, ",\"protocol_id\":[%u,\"%s\"]", s->protocol_id, ike_protocol_id_v1_string(s->protocol_id));
    zprintf(f, ",\"spi\":");
    zprintf_raw_as_hex(f, s->spi->bytes, s->spi->len);
    if (s->num_transforms > 0) {
        zprintf(f, ",\"transforms\":[");
        for (i = 0; i < s->num_transforms; i++) {
            if (i > 0) {
                zprintf(f, ",");
            }
            ike_transform_v1_print_json(s->transforms[i], f);
        }
        zprintf(f, "]");
    }
    zprintf(f, "}");
}

static void ike_proposal_delete(struct ike_proposal **s_handle) {
    struct ike_proposal *s = *s_handle;
    int i;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->spi);
    for (i = 0; i < s->num_transforms; i++) {
        ike_transform_delete(&s->transforms[i]);
    }
    
    free(s);
    *s_handle = NULL;
}

static void ike_proposal_init(struct ike_proposal **s_handle) {

    if (*s_handle != NULL) {
        ike_proposal_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_proposal));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_proposal_unmarshal(struct ike_proposal *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;
    unsigned int spi_size;
    unsigned int num_transforms;
    unsigned int last_transform;
    
    if (len < 8) {
        return 0;
    }
    
    s->last = x[offset]; offset++;
    offset++; /* reserved */
    s->length = raw_to_uint16(x+offset); offset+=2;
    s->num = x[offset]; offset++;
    s->protocol_id = x[offset]; offset++;
    spi_size = x[offset]; offset++;
    num_transforms = x[offset]; offset++;
    
    if (s->length > len) {
        return 0;
    }
    
    /* parse spi */
    if (spi_size > len-offset) {
        return 0;
    }
    vector_init(&s->spi);
    vector_set(s->spi, x+offset, spi_size);
    offset += spi_size;
    
    if (num_transforms > IKE_MAX_TRANSFORMS) {
        return 0;
    }
    
    /* parse transforms */
    s->num_transforms = 0;
    last_transform = 3;
    while(offset < len && s->num_transforms < num_transforms && last_transform == 3) {
        ike_transform_init(&s->transforms[s->num_transforms]);
        length = ike_transform_unmarshal(s->transforms[s->num_transforms], x+offset, len-offset);
        if (length == 0) {
            return 0;
        }
    
        offset += length;
        last_transform = s->transforms[s->num_transforms]->last;
        s->num_transforms++;
    }
    
    if (s->num_transforms != num_transforms || offset != s->length) {
        return 0;
    }
    
    return offset;
}

static unsigned int ike_proposal_v1_unmarshal(struct ike_proposal *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;
    unsigned int spi_size;
    unsigned int num_transforms;
    unsigned int last_transform;

    if (len < 8) {
        joy_log_err("len %u < 8", len);
        return 0;
    }

    s->last = x[offset]; offset++;
    offset++; /* reserved */
    s->length = raw_to_uint16(x+offset); offset+=2;
    s->num = x[offset]; offset++;
    s->protocol_id = x[offset]; offset++;
    spi_size = x[offset]; offset++;
    num_transforms = x[offset]; offset++;

    if (s->length > len) {
        joy_log_err("s->length %u > len %u", s->length, len);
        return 0;
    }

    /* parse spi */
    if (spi_size > len-offset) {
        joy_log_err("spi_size %u > len-offset %u", spi_size, len-offset);
        return 0;
    }
    vector_init(&s->spi);
    vector_set(s->spi, x+offset, spi_size);
    offset += spi_size;

    if (num_transforms > IKE_MAX_TRANSFORMS) {
        joy_log_err("num_transforms %u > IKE_MAX_TRANSFORMS %u", num_transforms, IKE_MAX_TRANSFORMS);
        return 0;
    }
    
    /* parse transforms */
    s->num_transforms = 0;
    last_transform = 3;
    while(offset < len && s->num_transforms < num_transforms && last_transform == 3) {
        ike_transform_init(&s->transforms[s->num_transforms]);
        length = ike_transform_v1_unmarshal(s->transforms[s->num_transforms], x+offset, len-offset);
        if (length == 0) {
            joy_log_err("unable to unmarshal transform");
            return 0;
        }

        offset += length;
        last_transform = s->transforms[s->num_transforms]->last;
        s->num_transforms++;
    }

    if (s->num_transforms != num_transforms) {
        joy_log_err("s->num_transforms %u != num_transforms %u", s->num_transforms, num_transforms);
        return 0;
    }
    if (offset != s->length) {
        joy_log_err("offset %u != s->length %u", offset, s->length);
        return 0;
    }
    
    return offset;
}

static void ike_sa_print_json(struct ike_sa *s, zfile f) {
    int i;
    
    zprintf(f, "{");
    for(i = 0; i < s->num_proposals; i++) {
        if (i == 0) {
            zprintf(f, "\"proposals\":[");
        } else {
            zprintf(f, ",");
        }
        ike_proposal_print_json(s->proposals[i], f);
        if (i == s->num_proposals-1) {
            zprintf(f, "]");
        }
    }
    zprintf(f, "}");
}

static void ike_sa_v1_print_json(struct ike_sa *s, zfile f) {
    int i;

    zprintf(f, "{");
    zprintf(f, "\"doi\":[%u,\"%s\"]", s->doi_v1, ike_doi_v1_string(s->doi_v1));
    zprintf(f, ",\"situation\":%u", s->situation_v1);
    if (s->doi_v1 == IKE_IPSEC_V1) {
        if (s->situation_v1 & (IKE_SIT_SECRECY_V1 | IKE_SIT_INTEGRITY_V1)) {
            zprintf(f, ",\"labeled_domain_identifier\":%u", s->ldi_v1);
        }
        if (s->situation_v1 & IKE_SIT_SECRECY_V1) {
            zprintf(f, ",\"secrecy_level\":");
            zprintf_raw_as_hex(f, s->secrecy_level_v1->bytes, s->secrecy_level_v1->len);
            zprintf(f, ",\"secrecy_category\":");
            zprintf_raw_as_hex(f, s->secrecy_category_v1->bytes, s->secrecy_category_v1->len);
        }
        if (s->situation_v1 & IKE_SIT_INTEGRITY_V1) {
            zprintf(f, ",\"integrity_level\":");
            zprintf_raw_as_hex(f, s->integrity_level_v1->bytes, s->integrity_level_v1->len);
            zprintf(f, ",\"integrity_category\":");
            zprintf_raw_as_hex(f, s->integrity_category_v1->bytes, s->integrity_category_v1->len);
        }
    }

    for(i = 0; i < s->num_proposals; i++) {
        if (i == 0) {
            zprintf(f, ",\"proposals\":[");
        } else {
            zprintf(f, ",");
        }
        ike_proposal_v1_print_json(s->proposals[i], f);
        if (i == s->num_proposals-1) {
            zprintf(f, "]");
        }
    }
    zprintf(f, "}");
}

static void ike_sa_delete(struct ike_sa **s_handle) {
    struct ike_sa *s = *s_handle;
    int i;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->secrecy_level_v1);
    vector_delete(&s->secrecy_category_v1);
    vector_delete(&s->integrity_level_v1);
    vector_delete(&s->integrity_category_v1);
    for (i = 0; i < s->num_proposals; i++) {
        ike_proposal_delete(&s->proposals[i]);
    }

    free(s);
    *s_handle = NULL;
}

static void ike_sa_init(struct ike_sa **s_handle) {

    if (*s_handle != NULL) {
        ike_sa_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_sa));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_sa_unmarshal(struct ike_sa *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;
    unsigned int last_proposal;

    /* parse proposals */
    s->num_proposals = 0;
    last_proposal = 2;
    while(offset < len && s->num_proposals < IKE_MAX_PROPOSALS && last_proposal == 2) {
        ike_proposal_init(&s->proposals[s->num_proposals]);
        length = ike_proposal_unmarshal(s->proposals[s->num_proposals], x+offset, len-offset);
        if (length == 0) {
            return 0;
        }

        offset += length;
        last_proposal = s->proposals[s->num_proposals]->last;
        s->num_proposals++;
    }

    return offset;
}

static unsigned int ike_sa_v1_unmarshal(struct ike_sa *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;
    unsigned int last_proposal;

    s->doi_v1 = raw_to_uint32(x+offset); offset+=4;
    s->situation_v1 = raw_to_uint32(x+offset); offset+=4;

    if (s->doi_v1 == IKE_GDOI_V1) {
        if (s->situation_v1 != 0) {
            joy_log_err("doi GDOI but situation %u != 0", s->situation_v1);
            return 0;
        }
    } else if (s->doi_v1 == IKE_IPSEC_V1) {
        /* SIT_IDENTITY_ONLY is required for IPSEC DOI implementations */ 
        if ( ! (s->situation_v1 & IKE_SIT_IDENTITY_ONLY_V1)) {
            joy_log_err("SIT_IDENTITY_ONLY bit not set");
            return 0;
        }

        /* Labeled Domain Information */
        if (s->situation_v1 & (IKE_SIT_SECRECY_V1 | IKE_SIT_INTEGRITY_V1)) {
            s->ldi_v1 = raw_to_uint32(x+offset); offset+=4;
        }
        
        /* SIT_SECRECY */
        if (s->situation_v1 & IKE_SIT_SECRECY_V1) {
            length = raw_to_uint16(x+offset); offset+=2;
            offset += 2; /* reserved */
            vector_init(&s->secrecy_level_v1);
            vector_set(s->secrecy_level_v1, x+offset, length);
            offset += length;

            length = raw_to_uint16(x+offset); offset+=2;
            offset += 2; /* reserved */
            vector_init(&s->secrecy_category_v1);
            vector_set(s->secrecy_category_v1, x+offset, (length+7)/8); /* length is in bits for bitmap */
        }

        /* SIT_INTEGRITY */
        if (s->situation_v1 & IKE_SIT_INTEGRITY_V1) {
            length = raw_to_uint16(x+offset); offset+=2;
            offset += 2; /* reserved */
            vector_init(&s->integrity_level_v1);
            vector_set(s->integrity_level_v1, x+offset, length);
            offset += length;

            length = raw_to_uint16(x+offset); offset+=2;
            offset += 2; /* reserved */
            vector_init(&s->integrity_category_v1);
            vector_set(s->integrity_category_v1, x+offset, (length+7)/8); /* length is in bits for bitmap */
        }
    } else {
        joy_log_err("DOI %u not supported", s->doi_v1);
        return 0;
    }

    /* parse proposals */
    s->num_proposals = 0;
    last_proposal = 2;
    while(offset < len && s->num_proposals < IKE_MAX_PROPOSALS && last_proposal == 2) {
        ike_proposal_init(&s->proposals[s->num_proposals]);
        length = ike_proposal_v1_unmarshal(s->proposals[s->num_proposals], x+offset, len-offset);
        if (length == 0) {
            joy_log_err("unable to parse proposal");
            return 0;
        }

        offset += length;
        last_proposal = s->proposals[s->num_proposals]->last;
        s->num_proposals++;
    }

    return offset;
}

static void ike_ke_print_json(struct ike_ke *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"group\":[%u,\"%s\"]", s->group, ike_diffie_hellman_group_string(s->group));
    zprintf(f, ",\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_ke_v1_print_json(struct ike_ke *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_ke_delete(struct ike_ke **s_handle) {
    struct ike_ke *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_ke_init(struct ike_ke **s_handle) {

    if (*s_handle != NULL) {
        ike_ke_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_ke));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_ke_unmarshal(struct ike_ke *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    if (len < 4) {
        return 0;
    }

    s->group = raw_to_uint16(x+offset); offset+=2;
    offset+=2; /* reserved */

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

    return offset;
}

static unsigned int ike_ke_v1_unmarshal(struct ike_ke *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

    return offset;
}

static void ike_id_print_json(struct ike_id *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"type\":[%u,\"%s\"]", s->type, ike_identification_type_string(s->type));
    zprintf(f, ",\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_id_v1_print_json(struct ike_id *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"type\":[%u,\"%s\"]", s->type, ike_identification_type_v1_string(s->type));
    zprintf(f, ",\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_id_delete(struct ike_id **s_handle) {
    struct ike_id *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_id_init(struct ike_id **s_handle) {

    if (*s_handle != NULL) {
        ike_id_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_id));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_id_unmarshal(struct ike_id *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    if (len < 4) {
        return 0;
    }

    s->type = x[offset]; offset++;
    offset+=3; /* reserved */

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

    return offset;
}

static void ike_cert_print_json(struct ike_cert *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"encoding\":[%u,\"%s\"]", s->encoding, ike_certificate_encoding_string(s->encoding));
    zprintf(f, ",\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_cert_delete(struct ike_cert **s_handle) {
    struct ike_cert *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_cert_init(struct ike_cert **s_handle) {

    if (*s_handle != NULL) {
        ike_cert_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_cert));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_cert_unmarshal(struct ike_cert *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    if (len < 1) {
        return 0;
    }

    s->encoding = x[offset]; offset++;

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

    return offset;
}

static void ike_cr_print_json(struct ike_cr *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"encoding\":[%u,\"%s\"]", s->encoding, ike_certificate_encoding_string(s->encoding));
    zprintf(f, ",\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_cr_delete(struct ike_cr **s_handle) {
    struct ike_cr *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_cr_init(struct ike_cr **s_handle) {

    if (*s_handle != NULL) {
        ike_cr_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_cr));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_cr_unmarshal(struct ike_cr *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    if (len < 1) {
        return 0;
    }

    s->encoding = x[offset]; offset++;

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

    return offset;
}

static void ike_auth_print_json(struct ike_auth *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"method\":[%u,\"%s\"]", s->method, ike_authentication_method_string(s->method));
    zprintf(f, ",\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_auth_delete(struct ike_auth **s_handle) {
    struct ike_auth *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_auth_init(struct ike_auth **s_handle) {

    if (*s_handle != NULL) {
        ike_auth_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_auth));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_auth_unmarshal(struct ike_auth *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    if (len < 4) {
        return 0;
    }

    s->method = x[offset]; offset++;
    offset+=3; /* reserved */

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

    return offset;
}

static void ike_hash_v1_print_json(struct ike_hash_v1 *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_hash_v1_delete(struct ike_hash_v1 **s_handle) {
    struct ike_hash_v1 *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_hash_v1_init(struct ike_hash_v1 **s_handle) {

    if (*s_handle != NULL) {
        ike_hash_v1_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_hash_v1));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_hash_v1_unmarshal(struct ike_hash_v1 *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

    return offset;
}

static void ike_notify_print_json(struct ike_notify *s, zfile f) {
    int i;
    uint16_t id;

    zprintf(f, "{");
    zprintf(f, "\"protocol_id\":[%u,\"%s\"]", s->protocol_id, ike_protocol_id_string(s->protocol_id));
    zprintf(f, ",\"type\":[%u,\"%s\"]", s->type, ike_notify_string(s->type));
    zprintf(f, ",\"spi\":");
    zprintf_raw_as_hex(f, s->spi->bytes, s->spi->len);
    zprintf(f, ",\"data\":[");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, ",\"");
    switch (s->type) {
    case IKE_SIGNATURE_HASH_ALGORITHMS_V2:
        for (i = 0; i < s->data->len/2; i++) {
            if (i != 0) {
                zprintf(f, ",");
            }
            id = raw_to_uint16((char *)s->data->bytes+2*i);
            zprintf(f, "%s", ike_hash_algorithm_string(id));
        }
        break;
    default:
        break;
    }
    zprintf(f, "\"]}");
}

static void ike_notify_v1_print_json(struct ike_notify *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"doi\":[%u,\"%s\"]", s->doi_v1, ike_doi_v1_string(s->doi_v1));
    zprintf(f, ",\"protocol_id\":[%u,\"%s\"]", s->protocol_id, ike_protocol_id_v1_string(s->protocol_id));
    zprintf(f, ",\"type\":[%u,\"%s\"]", s->type, ike_notify_v1_string(s->type));
    zprintf(f, ",\"spi\":");
    zprintf_raw_as_hex(f, s->spi->bytes, s->spi->len);
    zprintf(f, ",\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_notify_delete(struct ike_notify **s_handle) {
    struct ike_notify *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->spi);
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_notify_init(struct ike_notify **s_handle) {

    if (*s_handle != NULL) {
        ike_notify_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_notify));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_notify_unmarshal(struct ike_notify *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int spi_size;

    if (len < 4) {
        return 0;
    }

    s->protocol_id = x[offset]; offset++;
    spi_size = x[offset]; offset++;
    s->type = raw_to_uint16(x+offset); offset+=2;

    if (spi_size > len-offset) {
        return 0;
    }

    vector_init(&s->spi);
    vector_set(s->spi, x+offset, spi_size);
    offset += spi_size;

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

    return offset;
}

static unsigned int ike_notify_v1_unmarshal(struct ike_notify *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int spi_size;

    if (len < 8) {
        joy_log_err("len %u < 8", len);
        return 0;
    }

    s->doi_v1 = raw_to_uint32(x+offset); offset+=4;
    s->protocol_id = x[offset]; offset++;
    spi_size = x[offset]; offset++;
    s->type = raw_to_uint16(x+offset); offset+=2;

    if (spi_size > len-offset) {
        joy_log_err("spi_size %u > len-offset %u", spi_size, len-offset);
        return 0;
    }

    vector_init(&s->spi);
    vector_set(s->spi, x+offset, spi_size);
    offset += spi_size;

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

    return offset;
}

static void ike_nonce_print_json(struct ike_nonce *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"data\":");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, "}");
}

static void ike_nonce_delete(struct ike_nonce **s_handle) {
    struct ike_nonce *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_nonce_init(struct ike_nonce **s_handle) {

    if (*s_handle != NULL) {
        ike_nonce_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_nonce));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_nonce_unmarshal(struct ike_nonce *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

    return offset;
}

static void ike_vendor_id_print_json(struct ike_vendor_id *s, zfile f) {
    int i;

    zprintf(f, "{");
    zprintf(f, "\"data\":[");
    zprintf_raw_as_hex(f, s->data->bytes, s->data->len);
    zprintf(f, ",\"");
    for (i = 0; i < sizeof(ike_vendor_ids); i++) {
        if (s->data->len == ike_vendor_ids[i].len) {
            if (memcmp(s->data->bytes, ike_vendor_ids[i].id, s->data->len) == 0) {
                zprintf(f, "%s", ike_vendor_ids[i].desc);
                break;
            }
        }
    }
    if (i == sizeof(ike_vendor_ids)) {
        zprintf(f, "unknown");
    }
    zprintf(f, "\"]}");
}

static void ike_vendor_id_delete(struct ike_vendor_id **s_handle) {
    struct ike_vendor_id *s = *s_handle;

    if (s == NULL) {
        return;
    }
    vector_delete(&s->data);

    free(s);
    *s_handle = NULL;
}

static void ike_vendor_id_init(struct ike_vendor_id **s_handle) {

    if (*s_handle != NULL) {
        ike_vendor_id_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_vendor_id));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_vendor_id_unmarshal(struct ike_vendor_id *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    vector_init(&s->data);
    vector_set(s->data, x+offset, len-offset);
    offset += len-offset;

    return offset;
}

static void ike_payload_print_json(struct ike_payload *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"type\":[%d,\"%s\"]", s->type, ike_payload_type_string(s->type));

    /* print payload body */
    zprintf(f, ",\"body\":[");
    switch(s->type) {
        case IKE_SECURITY_ASSOCIATION_V2:
            ike_sa_print_json(s->body->sa, f);
            break;
        case IKE_SECURITY_ASSOCIATION_V1:
            ike_sa_v1_print_json(s->body->sa, f);
            break;
        case IKE_KEY_EXCHANGE_V2:
            ike_ke_print_json(s->body->ke, f);
            break;
        case IKE_KEY_EXCHANGE_V1:
            ike_ke_v1_print_json(s->body->ke, f);
            break;
        case IKE_IDENTIFICATION_INITIATOR_V2:
        case IKE_IDENTIFICATION_RESPONDER_V2:
            ike_id_print_json(s->body->id, f);
            break;
        case IKE_IDENTIFICATION_V1:
            ike_id_v1_print_json(s->body->id, f);
            break;
        case IKE_CERTIFICATE_V2:
        case IKE_CERTIFICATE_V1:
            ike_cert_print_json(s->body->cert, f);
            break;
        case IKE_CERTIFICATE_REQUEST_V2:
        case IKE_CERTIFICATE_REQUEST_V1:
            ike_cr_print_json(s->body->cr, f);
            break;
        case IKE_AUTHENTICATION_V2:
            ike_auth_print_json(s->body->auth, f);
            break;
        case IKE_HASH_V1:
            ike_hash_v1_print_json(s->body->hash_v1, f);
            break;
        case IKE_NONCE_V2:
        case IKE_NONCE_V1:
            ike_nonce_print_json(s->body->nonce, f);
            break;
        case IKE_NOTIFY_V2:
            ike_notify_print_json(s->body->notify, f);
            break;
        case IKE_NOTIFICATION_V1:
            ike_notify_v1_print_json(s->body->notify, f);
            break;
        case IKE_VENDOR_ID_V2:
        case IKE_VENDOR_ID_V1:
            ike_vendor_id_print_json(s->body->vendor_id, f);
            break;
        default:
            break;
    }
    zprintf(f, "]}");
}

static void ike_payload_delete(struct ike_payload **s_handle) {
    struct ike_payload *s = *s_handle;

    if (s == NULL) {
        return;
    }

    /* delete payload body */
    switch(s->type) {
        case IKE_SECURITY_ASSOCIATION_V2:
        case IKE_SECURITY_ASSOCIATION_V1:
            ike_sa_delete(&s->body->sa);
            break;
        case IKE_KEY_EXCHANGE_V2:
        case IKE_KEY_EXCHANGE_V1:
            ike_ke_delete(&s->body->ke);
            break;
        case IKE_IDENTIFICATION_INITIATOR_V2:
        case IKE_IDENTIFICATION_RESPONDER_V2:
        case IKE_IDENTIFICATION_V1:
            ike_id_delete(&s->body->id);
            break;
        case IKE_CERTIFICATE_V2:
        case IKE_CERTIFICATE_V1:
            ike_cert_delete(&s->body->cert);
            break;
        case IKE_CERTIFICATE_REQUEST_V2:
        case IKE_CERTIFICATE_REQUEST_V1:
            ike_cr_delete(&s->body->cr);
            break;
        case IKE_AUTHENTICATION_V2:
            ike_auth_delete(&s->body->auth);
            break;
        case IKE_HASH_V1:
            ike_hash_v1_delete(&s->body->hash_v1);
            break;
        case IKE_NONCE_V2:
        case IKE_NONCE_V1:
            ike_nonce_delete(&s->body->nonce);
            break;
        case IKE_NOTIFY_V2:
        case IKE_NOTIFICATION_V1:
            ike_notify_delete(&s->body->notify);
            break;
        case IKE_VENDOR_ID_V2:
        case IKE_VENDOR_ID_V1:
            ike_vendor_id_delete(&s->body->vendor_id);
            break;
        default:
            break;
    }

    free(s->body);
    free(s);
    *s_handle = NULL;
}

static void ike_payload_init(struct ike_payload **s_handle) {

    if (*s_handle != NULL) {
        ike_payload_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_payload));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
    (*s_handle)->body = calloc(1, sizeof(union ike_payload_body));
    if ((*s_handle)->body == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_payload_unmarshal(struct ike_payload *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;

    /* parse generic payload header */
    s->next_payload = x[offset]; offset++;
    offset++; /* reserved */
    s->length = raw_to_uint16(x+offset); offset+=2;

    if (s->length > len) {
        joy_log_err("s->length %u > len %u", s->length, len);
        return 0;
    }

    length = s->length-offset;

    /* parse payload body */
    switch(s->type) {
        case IKE_SECURITY_ASSOCIATION_V2:
            ike_sa_init(&s->body->sa);
            length = ike_sa_unmarshal(s->body->sa, x+offset, length);
            break;
        case IKE_SECURITY_ASSOCIATION_V1:
            ike_sa_init(&s->body->sa);
            length = ike_sa_v1_unmarshal(s->body->sa, x+offset, length);
            break;
        case IKE_KEY_EXCHANGE_V2:
            ike_ke_init(&s->body->ke);
            length = ike_ke_unmarshal(s->body->ke, x+offset, length);
            break;
        case IKE_KEY_EXCHANGE_V1:
            ike_ke_init(&s->body->ke);
            length = ike_ke_v1_unmarshal(s->body->ke, x+offset, length);
            break;
        case IKE_IDENTIFICATION_INITIATOR_V2:
        case IKE_IDENTIFICATION_RESPONDER_V2:
        case IKE_IDENTIFICATION_V1:
            ike_id_init(&s->body->id);
            length = ike_id_unmarshal(s->body->id, x+offset, length);
            break;
        case IKE_CERTIFICATE_V2:
        case IKE_CERTIFICATE_V1:
            ike_cert_init(&s->body->cert);
            length = ike_cert_unmarshal(s->body->cert, x+offset, length);
            break;
        case IKE_CERTIFICATE_REQUEST_V2:
        case IKE_CERTIFICATE_REQUEST_V1:
            ike_cr_init(&s->body->cr);
            length = ike_cr_unmarshal(s->body->cr, x+offset, length);
            break;
        case IKE_AUTHENTICATION_V2:
            ike_auth_init(&s->body->auth);
            length = ike_auth_unmarshal(s->body->auth, x+offset, length);
            break;
        case IKE_HASH_V1:
            ike_hash_v1_init(&s->body->hash_v1);
            length = ike_hash_v1_unmarshal(s->body->hash_v1, x+offset, length);
            break;
        case IKE_NONCE_V2:
        case IKE_NONCE_V1:
            ike_nonce_init(&s->body->nonce);
            length = ike_nonce_unmarshal(s->body->nonce, x+offset, length);
            break;
        case IKE_NOTIFY_V2:
            ike_notify_init(&s->body->notify);
            length = ike_notify_unmarshal(s->body->notify, x+offset, length);
            break;
        case IKE_NOTIFICATION_V1:
            ike_notify_init(&s->body->notify);
            length = ike_notify_v1_unmarshal(s->body->notify, x+offset, length);
            break;
        case IKE_VENDOR_ID_V2:
        case IKE_VENDOR_ID_V1:
            ike_vendor_id_init(&s->body->vendor_id);
            length = ike_vendor_id_unmarshal(s->body->vendor_id, x+offset, length);
            break;
        default:
            break;
    }

    /* the lengths must match exacctly */
    if (length != s->length-offset) {
        joy_log_err("length %u != length-offset %u", s->length, length-offset);
        return 0;
    }
    offset += length;

    return offset;
}

static void ike_header_print_json(struct ike_header *s, zfile f) {

    zprintf(f, "{");
    zprintf(f, "\"init_spi\":");
    zprintf_raw_as_hex(f, s->init_spi, sizeof(s->init_spi));
    zprintf(f, ",\"resp_spi\":");
    zprintf_raw_as_hex(f, s->resp_spi, sizeof(s->resp_spi));
    zprintf(f, ",\"major\":%u", s->major);
    zprintf(f, ",\"minor\":%u", s->minor);
    zprintf(f, ",\"exchange_type\":[%u,\"%s\"]", s->exchange_type, ike_exchange_type_string(s->exchange_type));
    zprintf(f, ",\"flags\":[%u,\"", s->flags);
    if (s->major == 1) {
        zprintf(f, (s->flags & IKE_ENCRYPTION_BIT_V1)? "encryption": "no_encryption");
        zprintf(f, (s->flags & IKE_COMMIT_BIT_V1)? ",commit": ",no_commit");
        zprintf(f, (s->flags & IKE_AUTHENTICATION_BIT_V1)? ",authentication": ",no_authentication");
    }
    if (s->major == 2) {
        zprintf(f, (s->flags & IKE_INITIATOR_BIT_V2) ? ",initiator": ",responder");
        zprintf(f, (s->flags & IKE_VERSION_BIT_V2) ? ",no_higher_version": ",higher_version");
        zprintf(f, (s->flags & IKE_RESPONSE_BIT_V2) ? "response": "request");
    }
    zprintf(f, "\"]");
    zprintf(f, ",\"message_id\":%u", s->message_id);
    zprintf(f, ",\"length\":%u", s->length);
    zprintf(f, "}");
}

static void ike_header_delete(struct ike_header **s_handle) {
    struct ike_header *s = *s_handle;

    if (s == NULL) {
        return;
    }

    free(s);
    *s_handle = NULL;
}

static void ike_header_init(struct ike_header **s_handle) {

    if (*s_handle != NULL) {
        ike_header_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_header));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_header_unmarshal(struct ike_header *s, const char *x, unsigned int len) {
    unsigned int offset = 0;

    if (s == NULL || x == NULL) {
        return 0;
    }

    if (len < sizeof(struct ike_header)) {
        return 0;
    }
    memcpy(s->init_spi, x+offset, 8); offset+=8;
    memcpy(s->resp_spi, x+offset, 8); offset+=8;
    s->next_payload = x[offset]; offset++;
    s->major = (x[offset] & 0xf0) >> 4; 
    s->minor = (x[offset] & 0x0f); offset++;
    s->exchange_type = x[offset]; offset++;
    s->flags = x[offset]; offset++;
    s->message_id = raw_to_uint32(x+offset); offset+=4;
    s->length = raw_to_uint32(x+offset); offset+=4;

    return offset;
}

static void ike_message_print_json(struct ike_message *s, zfile f) {
    int i;

    zprintf(f, "{");
    zprintf(f, "\"header\":");
    ike_header_print_json(s->header, f);
    for (i = 0; i < s->num_payloads; i++) {
        if (i == 0) {
            zprintf(f, ",\"payloads\":[");
        } else {
            zprintf(f, ",");
        }
        ike_payload_print_json(s->payloads[i], f);
        if (i == s->num_payloads-1) {
            zprintf(f, "]");
        }
    }
    zprintf(f, "}");
}

static void ike_message_delete(struct ike_message **s_handle) {
    struct ike_message *s = *s_handle;
    int i;

    if (s == NULL) {
        return;
    }
    ike_header_delete(&s->header);
    for (i = 0; i < s->num_payloads; i++) {
        ike_payload_delete(&s->payloads[i]);
    }
    
    free(s);
    *s_handle = NULL;
}

static void ike_message_init(struct ike_message **s_handle) {

    if (*s_handle != NULL) {
        ike_message_delete(s_handle);
    }

    *s_handle = calloc(1, sizeof(struct ike_message));
    if (*s_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
}

static unsigned int ike_message_unmarshal(struct ike_message *s, const char *x, unsigned int len) {
    unsigned int offset = 0;
    unsigned int length;
    uint8_t next_payload;

    /* parse header */
    ike_header_init(&s->header);
    length = ike_header_unmarshal(s->header, x+offset, len-offset);
    if (length == 0) {
        joy_log_err("unable to unmarshal header");
        return 0;
    }
    if (s->header->length > IKE_MAX_MESSAGE_LEN) {
        joy_log_err("header length %u > IKE_MAX_MESSAGE_LEN %u", s->header->length, IKE_MAX_MESSAGE_LEN);
        return 0;
    }
    offset += length;

    if (s->header->flags & IKE_ENCRYPTION_BIT_V1) {
        /* all payloads following the header are encrypted */
        return s->header->length;
    }

    /* parse payloads */
    next_payload = s->header->next_payload;
    s->num_payloads = 0;
    while(offset < s->header->length && s->num_payloads < IKE_MAX_PAYLOADS && next_payload != IKE_NO_NEXT_PAYLOAD) {
        ike_payload_init(&s->payloads[s->num_payloads]);
        s->payloads[s->num_payloads]->type = next_payload;
        length = ike_payload_unmarshal(s->payloads[s->num_payloads], x+offset, len-offset);
        if (length == 0) {
            joy_log_err("unable to unmarshal payload");
            return 0;
        }

        offset += length;
        next_payload = s->payloads[s->num_payloads]->next_payload;
        s->num_payloads++;
    }

    /* check that the length matches exactly */
    if (offset != s->header->length) {
        joy_log_err("offset %u != header length %u", offset, s->header->length);
        return 0;
    }

    return offset;
}

/*
 * \brief Return the most recent security association payload in the ike transcript
 */
static struct ike_sa *ike_sa_get(struct ike *ike) {
    int i, j;

    for (i = ike->num_messages-1; i >= 0; i--) {
        for (j = 0; j < ike->messages[i]->num_payloads; j++) {
            switch (ike->messages[i]->payloads[j]->type) {
            case IKE_SECURITY_ASSOCIATION_V1:
            case IKE_SECURITY_ASSOCIATION_V2:
                return ike->messages[i]->payloads[j]->body->sa;
            }
        }
    }

    return NULL;
}

/*
 * \brief Check that the initiator and responder attributes match
 */
static int ike_attribute_match(struct ike_attribute *a, struct ike_attribute *b) {

    if (a->type != b->type) {
        return 0;
    }
    if (a->encoding != b->encoding) {
        return 0;
    }
    if (a->data->len != b->data->len) {
        return 0;
    }
    if (memcmp(a->data->bytes, b->data->bytes, a->data->len) != 0) {
        return 0;
    }
    return 1;
}

/*
 * \brief Check that the initiator and responder transforms match, and that
 * each attribute in the responder transform is unique and matches an attribute
 * in the initiator transform
 */
static int ike_transform_match(struct ike_transform *init_transform, struct ike_transform *resp_transform) {
    int init_i, resp_i, resp_j;

    if (init_transform->type != resp_transform->type) {
        return 0;
    }
    if (init_transform->id != resp_transform->id) {
        return 0;
    }
    if (init_transform->num_v1 != resp_transform->num_v1) {
        return 0;
    }
    if (init_transform->id_v1 != resp_transform->id_v1) {
        return 0;
    }

    /* check that each attribute type in the responder transform is unique */
    for (resp_i = 0; resp_i < resp_transform->num_attributes; resp_i++) {
        for (resp_j = 0; resp_j < resp_transform->num_attributes; resp_j++) {
            if (resp_i != resp_j && resp_transform->attributes[resp_i]->type == resp_transform->attributes[resp_j]->type) {
                joy_log_err("responder transform contains multiple attributes of type %u", 
                        resp_transform->attributes[resp_i]->type);
                return 0;
            }
        }
    }

    /* check that each attribute in the respondor transform matches an attribute in the initiator transform */
    for (resp_i = 0; resp_i < resp_transform->num_attributes; resp_i++) {
        for (init_i = 0; init_i < init_transform->num_attributes; init_i++) {
            if (ike_attribute_match(init_transform->attributes[init_i], resp_transform->attributes[resp_i])) {
                break;
            }
        }
        if (init_i == init_transform->num_attributes) {
            joy_log_err("responder attribute of type %u does not match initiator attributes", resp_transform->attributes[resp_i]->type);
            return 0;
        }
    }

    return 1;
}

/*
 * \brief Check that the initiator and responder proposals match, and that
 * each transform in the responder proposal is unique and matches a transform
 * in the initiator proposal
 */
static int ike_proposal_match(struct ike_proposal *init_proposal, struct ike_proposal *resp_proposal) {
    int init_i, resp_i, resp_j;

    if (init_proposal->num != resp_proposal->num) {
        return 0;
    }
    if (init_proposal->protocol_id != resp_proposal->protocol_id) {
        return 0;
    }

    /* check that each transform type in the responder proposal is unique */
    for (resp_i = 0; resp_i < resp_proposal->num_transforms; resp_i++) {
        for (resp_j = 0; resp_j < resp_proposal->num_transforms; resp_j++) {
            if (resp_i != resp_j && resp_proposal->transforms[resp_i]->type == resp_proposal->transforms[resp_j]->type) {
                joy_log_err("responder proposal contains multiple transforms of type %u", resp_proposal->transforms[resp_i]->type);
                return 0;
            }
        }
    }

    /* check that each transform in the respondor proposal matches a transform in the initiator proposal */
    for (resp_i = 0; resp_i < resp_proposal->num_transforms; resp_i++) {
        for (init_i = 0; init_i < init_proposal->num_transforms; init_i++) {
            if (ike_transform_match(init_proposal->transforms[init_i], resp_proposal->transforms[resp_i])) {
                break;
            }
        }
        if (init_i == init_proposal->num_transforms) {
            joy_log_err("responder transform of type %u does not match initiator transforms", resp_proposal->transforms[resp_i]->type);
            return 0;
        }
    }

    return 1;
}

/*
 * \brief Check that the initiator and responder security associations match,
 * and that each proposal in the responder security association is unique and
 * matches a proposal in the initiator security association
 */
static int ike_sa_match(struct ike_sa *init_sa, struct ike_sa *resp_sa) {
    int init_i;

    if (init_sa->doi_v1 != resp_sa->doi_v1) {
        return 0;
    }
    if (init_sa->situation_v1 != resp_sa->situation_v1) {
        return 0;
    }
    if (init_sa->ldi_v1 != resp_sa->ldi_v1) {
        return 0;
    }

    /* check that the proposal in the respondor security association matches a
     * proposal in the initiator security association */
    if (resp_sa->num_proposals != 1) {
        return 0;
    }

    for (init_i = 0; init_i < init_sa->num_proposals; init_i++) {
        if (ike_proposal_match(init_sa->proposals[init_i], resp_sa->proposals[0])) {
            break;
        }
    }
    if (init_i == init_sa->num_proposals) {
        joy_log_err("responder proposal num %u does not match initiator proposals", resp_sa->proposals[0]->num);
        return 0;
    }

    return 1;
}

static void ike_process(struct ike *init,
                        struct ike *resp) {
    struct ike_sa *init_sa, *resp_sa;

    if (init == NULL || resp == NULL) {
        return;
    }

    /* Check that the Secrutiy Association payload received from the responder
     * matches one of the proposals sent my the initiator */
    init_sa = ike_sa_get(init);
    resp_sa = ike_sa_get(resp);
    if (init_sa == NULL || resp_sa == NULL) {
        return;
    }

    if ( ! ike_sa_match(init_sa, resp_sa)) {
        joy_log_err("responder security association does not match initiator security association");
    }
}

/*
 * start of ike feature functions
 */

inline void ike_init(struct ike **ike_handle) {

    if (*ike_handle != NULL) {
        ike_delete(ike_handle);
    }

    *ike_handle = calloc(1, sizeof(struct ike));
    if (*ike_handle == NULL) {
        joy_log_err("malloc failed");
        return;
    }
    vector_init(&(*ike_handle)->buffer);
}

void ike_update(struct ike *ike,
        const struct pcap_pkthdr *header,
        const void *data,
        unsigned int len,
        unsigned int report_ike) {
    unsigned int length;
    const char *data_ptr = (const char *)data;

    if (len == 0) {
    return;        /* skip zero-length messages */
    }

    /*
     * If a NAT is detected between the Initiator and the Responder, then
     * subsequent IKE packets are sent over UDP port 4500 with four bytes of
     * zero at the start of the UDP payload, and ESP packets are sent out over
     * UDP port 4500.  Some peers default to using UDP encapsulation even when
     * no NAT is detected on the path, as some middleboxes do not support IP
     * protocols other than TCP and UDP (RFC 3948).
     *
     * TCP encapsulation uses a similar four zero byte non-ESP marker, but the
     * marker is preceeded by a 2-byte length field (RFC 8229).
     */
    if (len >= 4 && memcmp(data_ptr, "\x00\x00\x00\x00", 4) == 0) {
        len -= 4;
        data_ptr += 4;
    }

    if (report_ike) {

    /* append application-layer data to buffer (to deal with IP fragmentation) */
    vector_append(ike->buffer, data_ptr, len);
    data_ptr = (const char *)ike->buffer->bytes;
    len = ike->buffer->len;

    while (len > 0 && ike->num_messages < IKE_MAX_MESSAGES) { /* parse all messages in the buffer */
        ike_message_init(&ike->messages[ike->num_messages]);
        length = ike_message_unmarshal(ike->messages[ike->num_messages], data_ptr, len);
        if (length == 0) {
            /* unable to parse message */
            joy_log_err("unable to parse message");
            break;
        }

        /* skip to the next message in the buffer */
        len -= length;
        data_ptr += length;
        ike->num_messages++;
    }

    /* update buffer */
    vector_set(ike->buffer, data_ptr, len);

    } /* report_ike */
}

void ike_print_json(const struct ike *x1,
                    const struct ike *x2,
                    zfile f) {
    struct ike *init = NULL, *resp = NULL;
    int i;

    init = (struct ike*)x1;
    resp = (struct ike*)x2;

    ike_process(init, resp);

    zprintf(f, ",\"ike\":{");
    if (init != NULL) {
        zprintf(f, "\"init\":{");
        for (i = 0; i < init->num_messages; i++) {
            if (i == 0) {
                zprintf(f, "\"messages\":[");
            } else {
                zprintf(f, ",");
            }
            ike_message_print_json(init->messages[i], f);
            if (i == init->num_messages-1) {
                zprintf(f, "]");
            }
        }
        zprintf(f, "}");
    }
    if (resp != NULL) {
        if (init != NULL) {
            zprintf(f, ",");
        }
        zprintf(f, "\"resp\":{");
        for (i = 0; i < resp->num_messages; i++) {
            if (i == 0) {
                zprintf(f, "\"messages\":[");
            } else {
                zprintf(f, ",");
            }
            ike_message_print_json(resp->messages[i], f);
            if (i == resp->num_messages-1) {
                zprintf(f, "]");
            }
        }
        zprintf(f, "}");
    }
    zprintf(f, "}");
}

void ike_delete(struct ike **ike_handle) {
    struct ike *ike= *ike_handle;
    int i;

    if (ike == NULL) {
        return;
    }
    for (i = 0; i < ike->num_messages; i++) {
        ike_message_delete(&ike->messages[i]);
    }

    vector_delete(&ike->buffer);
    free(ike);
    *ike_handle = NULL;
}

static int ike_test_v1_handshake() {
    struct ike *init = NULL, *resp = NULL;
    int num_fails = 0;

    /* input data */
    char init_main_sa[] = { 
        0xc6, 0xd1, 0x45, 0x92, 0x85, 0x15, 0x0c, 0x7e, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xfc, 0x0d, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x80, 0x0b, 0x00, 0x01,
        0x80, 0x0c, 0x1e, 0x78, 0x80, 0x01, 0x00, 0x05, 0x80, 0x02, 0x00, 0x02,
        0x80, 0x03, 0x00, 0x01, 0x80, 0x04, 0x00, 0x02, 0x0d, 0x00, 0x00, 0x14,
        0x88, 0x2f, 0xe5, 0x6d, 0x6f, 0xd2, 0x0d, 0xbc, 0x22, 0x51, 0x61, 0x3b,
        0x2e, 0xbe, 0x5b, 0xeb, 0x0d, 0x00, 0x00, 0x14, 0x12, 0xf5, 0xf2, 0x8c,
        0x45, 0x71, 0x68, 0xa9, 0x70, 0x2d, 0x9f, 0xe2, 0x74, 0xcc, 0x01, 0x00,
        0x0d, 0x00, 0x00, 0x0c, 0x09, 0x00, 0x26, 0x89, 0xdf, 0xd6, 0xb7, 0x12,
        0x0d, 0x00, 0x00, 0x14, 0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9,
        0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57, 0x01, 0x00, 0x0d, 0x00, 0x00, 0x14,
        0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5c, 0x57, 0x28, 0xf2,
        0x0e, 0x95, 0x45, 0x2f, 0x0d, 0x00, 0x00, 0x14, 0x7d, 0x94, 0x19, 0xa6,
        0x53, 0x10, 0xca, 0x6f, 0x2c, 0x17, 0x9d, 0x92, 0x15, 0x52, 0x9d, 0x56,
        0x0d, 0x00, 0x00, 0x14, 0xcd, 0x60, 0x46, 0x43, 0x35, 0xdf, 0x21, 0xf8,
        0x7c, 0xfd, 0xb2, 0xfc, 0x68, 0xb6, 0xa4, 0x48, 0x0d, 0x00, 0x00, 0x14,
        0x90, 0xcb, 0x80, 0x91, 0x3e, 0xbb, 0x69, 0x6e, 0x08, 0x63, 0x81, 0xb5,
        0xec, 0x42, 0x7b, 0x1f, 0x00, 0x00, 0x00, 0x14, 0x44, 0x85, 0x15, 0x2d,
        0x18, 0xb6, 0xbb, 0xcd, 0x0b, 0xe8, 0xa8, 0x46, 0x95, 0x79, 0xdd, 0xcc 
    };

    char resp_main_sa[] = {
        0xc6, 0xd1, 0x45, 0x92, 0x85, 0x15, 0x0c, 0x7e, 0x6e, 0x96, 0x1f, 0x01,
        0xbf, 0x17, 0x9b, 0x35, 0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xac, 0x0d, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x80, 0x0b, 0x00, 0x01,
        0x80, 0x0c, 0x1e, 0x78, 0x80, 0x01, 0x00, 0x05, 0x80, 0x02, 0x00, 0x02,
        0x80, 0x03, 0x00, 0x01, 0x80, 0x04, 0x00, 0x02, 0x0d, 0x00, 0x00, 0x14,
        0x88, 0x2f, 0xe5, 0x6d, 0x6f, 0xd2, 0x0d, 0xbc, 0x22, 0x51, 0x61, 0x3b,
        0x2e, 0xbe, 0x5b, 0xeb, 0x0d, 0x00, 0x00, 0x14, 0x12, 0xf5, 0xf2, 0x8c,
        0x45, 0x71, 0x68, 0xa9, 0x70, 0x2d, 0x9f, 0xe2, 0x74, 0xcc, 0x01, 0x00,
        0x0d, 0x00, 0x00, 0x0c, 0x09, 0x00, 0x26, 0x89, 0xdf, 0xd6, 0xb7, 0x12,
        0x0d, 0x00, 0x00, 0x14, 0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9,
        0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14,
        0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5c, 0x57, 0x28, 0xf2,
        0x0e, 0x95, 0x45, 0x2f
    };

    char init_main_notify[] = {
        0xc6, 0xd1, 0x45, 0x92, 0x85, 0x15, 0x0c, 0x7e, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0b, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01,
        0x01, 0x00, 0x00, 0x0e
    };

    char resp_main_sa_2[] = {
        0xc6, 0xd1, 0x45, 0x92, 0x85, 0x15, 0x0c, 0x7e, 0x6e, 0x96, 0x1f, 0x01,
        0xbf, 0x17, 0x9b, 0x35, 0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xac, 0x0d, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x80, 0x0b, 0x00, 0x01,
        0x80, 0x0c, 0x1e, 0x78, 0x80, 0x01, 0x00, 0x05, 0x80, 0x02, 0x00, 0x02,
        0x80, 0x03, 0x00, 0x01, 0x80, 0x04, 0x00, 0x02, 0x0d, 0x00, 0x00, 0x14,
        0x88, 0x2f, 0xe5, 0x6d, 0x6f, 0xd2, 0x0d, 0xbc, 0x22, 0x51, 0x61, 0x3b,
        0x2e, 0xbe, 0x5b, 0xeb, 0x0d, 0x00, 0x00, 0x14, 0x12, 0xf5, 0xf2, 0x8c,
        0x45, 0x71, 0x68, 0xa9, 0x70, 0x2d, 0x9f, 0xe2, 0x74, 0xcc, 0x01, 0x00,
        0x0d, 0x00, 0x00, 0x0c, 0x09, 0x00, 0x26, 0x89, 0xdf, 0xd6, 0xb7, 0x12,
        0x0d, 0x00, 0x00, 0x14, 0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9,
        0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14,
        0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5c, 0x57, 0x28, 0xf2,
        0x0e, 0x95, 0x45, 0x2f
    };

    char init_main_ke[] = {
        0xc6, 0xd1, 0x45, 0x92, 0x85, 0x15, 0x0c, 0x7e, 0x6e, 0x96, 0x1f, 0x01,
        0xbf, 0x17, 0x9b, 0x35, 0x04, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xe4, 0x0a, 0x00, 0x00, 0x84, 0xa8, 0x12, 0xa5, 0xfb,
        0xfc, 0xba, 0xe8, 0x2c, 0x7d, 0xf0, 0xde, 0xae, 0xc2, 0x12, 0x0f, 0xe8,
        0xa9, 0xb7, 0xe8, 0x2f, 0xc1, 0xce, 0x7a, 0xd1, 0x6e, 0x38, 0xe0, 0x68,
        0x7d, 0x3e, 0xb0, 0x4f, 0x4c, 0x9a, 0xb8, 0x8f, 0xe3, 0xd3, 0xba, 0xed,
        0x7d, 0xa3, 0xcb, 0xf3, 0xdd, 0xec, 0x86, 0xcf, 0x95, 0xb0, 0xdd, 0xe8,
        0x7e, 0xe0, 0x86, 0xab, 0x23, 0x6e, 0x06, 0xd1, 0x7c, 0x45, 0x9f, 0xef,
        0x8e, 0x2f, 0xc9, 0x4d, 0x80, 0x4b, 0xe9, 0xaf, 0x45, 0xe7, 0x44, 0xc2,
        0x07, 0xef, 0x98, 0x75, 0x12, 0xd6, 0x8d, 0xd2, 0xed, 0xf1, 0xca, 0x57,
        0xe9, 0x1c, 0x98, 0xdc, 0x26, 0x88, 0xf7, 0x7a, 0x57, 0x90, 0x0a, 0xed,
        0x18, 0xf3, 0x68, 0xcb, 0xfb, 0x8d, 0x4b, 0x46, 0xbe, 0xa5, 0xe4, 0x8a,
        0x53, 0xcb, 0x88, 0xcd, 0x51, 0x5a, 0x17, 0xdd, 0x1d, 0x03, 0x2d, 0x1c,
        0x79, 0x54, 0x0f, 0x86, 0x14, 0x00, 0x00, 0x14, 0x74, 0x83, 0xe9, 0x64,
        0xd5, 0x59, 0x37, 0x8a, 0x55, 0x55, 0x77, 0x74, 0x64, 0xad, 0x7a, 0xd9,
        0x14, 0x00, 0x00, 0x18, 0x70, 0x48, 0xb1, 0x70, 0xa5, 0x4f, 0xa1, 0xc1,
        0x65, 0x82, 0xdc, 0xe0, 0x08, 0xd0, 0x59, 0xde, 0x92, 0x95, 0xd7, 0xd3,
        0x00, 0x00, 0x00, 0x18, 0xc9, 0xe4, 0x6d, 0xdd, 0xfc, 0xc2, 0x9d, 0x4e,
        0xf7, 0x2b, 0xa4, 0xda, 0x66, 0xd4, 0x72, 0x06, 0x87, 0xe4, 0x69, 0xe5
    };

    char resp_main_ke[] = {
        0xc6, 0xd1, 0x45, 0x92, 0x85, 0x15, 0x0c, 0x7e, 0x6e, 0x96, 0x1f, 0x01,
        0xbf, 0x17, 0x9b, 0x35, 0x04, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xe4, 0x0a, 0x00, 0x00, 0x84, 0x0a, 0x63, 0x93, 0xc0,
        0xc2, 0xb7, 0xaf, 0x92, 0x77, 0xe6, 0xc3, 0x6e, 0x41, 0x11, 0xea, 0x88,
        0xb8, 0x7d, 0xad, 0x6b, 0x50, 0x09, 0xb9, 0x09, 0xa0, 0xaa, 0x66, 0x10,
        0x1d, 0x7b, 0x3d, 0x70, 0x91, 0x82, 0x93, 0x4b, 0x0f, 0x0b, 0xca, 0x9f,
        0x77, 0xc9, 0xca, 0xaf, 0xf3, 0x3f, 0x00, 0x6d, 0xc4, 0x8d, 0xdd, 0x91,
        0x8c, 0xbc, 0x31, 0xe2, 0x7a, 0x64, 0x49, 0x2f, 0x0a, 0xeb, 0xa7, 0x32,
        0x2d, 0x54, 0xe1, 0x35, 0x95, 0x09, 0xde, 0x1b, 0x44, 0xee, 0x04, 0x84,
        0x00, 0xc7, 0xbd, 0x0f, 0x66, 0xd2, 0x22, 0xac, 0xc1, 0xa1, 0xa4, 0xf5,
        0xd1, 0xcb, 0xb7, 0x9c, 0xfa, 0x44, 0x36, 0x0a, 0x56, 0x66, 0xe9, 0x06,
        0x03, 0x12, 0x1d, 0xb6, 0x6f, 0x28, 0x3c, 0xe1, 0x67, 0x62, 0x8e, 0xb1,
        0xe9, 0xf5, 0xa9, 0x65, 0x1b, 0x79, 0x8f, 0x6a, 0xa3, 0x80, 0xbe, 0x24,
        0x12, 0xe2, 0xc0, 0xd4, 0x14, 0x00, 0x00, 0x14, 0x63, 0xda, 0xc2, 0x21,
        0x7d, 0x2d, 0x1e, 0xad, 0x62, 0xdd, 0x9c, 0x89, 0x7c, 0x62, 0x6a, 0x62,
        0x14, 0x00, 0x00, 0x18, 0xc9, 0xe4, 0x6d, 0xdd, 0xfc, 0xc2, 0x9d, 0x4e,
        0xf7, 0x2b, 0xa4, 0xda, 0x66, 0xd4, 0x72, 0x06, 0x87, 0xe4, 0x69, 0xe5,
        0x00, 0x00, 0x00, 0x18, 0x70, 0x48, 0xb1, 0x70, 0xa5, 0x4f, 0xa1, 0xc1,
        0x65, 0x82, 0xdc, 0xe0, 0x08, 0xd0, 0x59, 0xde, 0x92, 0x95, 0xd7, 0xd3
    };

    char init_main_id[] = {
        0xc6, 0xd1, 0x45, 0x92, 0x85, 0x15, 0x0c, 0x7e, 0x6e, 0x96, 0x1f, 0x01,
        0xbf, 0x17, 0x9b, 0x35, 0x05, 0x10, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x44, 0xbe, 0x02, 0x70, 0x0f, 0x1d, 0xb3, 0xd6, 0x2c,
        0xd7, 0x67, 0x6c, 0x70, 0x7e, 0x6b, 0x9b, 0xe9, 0xbc, 0x0a, 0xd1, 0x6e,
        0x12, 0x48, 0xa5, 0xf8, 0x3b, 0x7d, 0xee, 0xc8, 0x2d, 0x79, 0xcb, 0xcc,
        0xc7, 0x2d, 0x1e, 0x20, 0xd5, 0xaf, 0x89, 0xdd
    };

    char resp_main_id[] = {
        0xc6, 0xd1, 0x45, 0x92, 0x85, 0x15, 0x0c, 0x7e, 0x6e, 0x96, 0x1f, 0x01,
        0xbf, 0x17, 0x9b, 0x35, 0x05, 0x10, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x44, 0xeb, 0x53, 0xa6, 0x19, 0xf9, 0x00, 0xa6, 0x00,
        0xd0, 0x6b, 0xde, 0x3b, 0x07, 0x87, 0x82, 0xaa, 0xce, 0x00, 0x67, 0x64,
        0x7d, 0x66, 0x19, 0x05, 0x8e, 0x10, 0xbb, 0x74, 0x1d, 0x34, 0x0d, 0xee,
        0x52, 0xd9, 0xa5, 0xe8, 0x88, 0xb1, 0xcc, 0xf6
    };

    char init_main_hash[] = {
        0xc6, 0xd1, 0x45, 0x92, 0x85, 0x15, 0x0c, 0x7e, 0x6e, 0x96, 0x1f, 0x01,
        0xbf, 0x17, 0x9b, 0x35, 0x08, 0x10, 0x20, 0x01, 0x22, 0x1f, 0xaf, 0x3c,
        0x00, 0x00, 0x00, 0x9c, 0xce, 0xea, 0xd5, 0xcd, 0x87, 0x1e, 0xdd, 0x2d,
        0xc4, 0x82, 0xe0, 0x43, 0x2d, 0xc0, 0x71, 0x9e, 0x2a, 0x0f, 0x42, 0x18,
        0x7b, 0xfb, 0x79, 0xb3, 0x49, 0xe5, 0x69, 0xf2, 0x76, 0xf2, 0xbe, 0x2a,
        0x68, 0x96, 0x47, 0x74, 0xc3, 0x06, 0x59, 0x54, 0x94, 0x73, 0xa1, 0xbb,
        0xf8, 0x1d, 0x98, 0x3e, 0x39, 0xa1, 0x0e, 0xf4, 0x39, 0x81, 0x34, 0x12,
        0x83, 0x19, 0x54, 0xa2, 0xb7, 0x73, 0xeb, 0x8e, 0x63, 0x82, 0x22, 0x92,
        0xac, 0x8a, 0xac, 0x5f, 0xd4, 0x53, 0xd5, 0x2c, 0x70, 0xf3, 0x92, 0xeb,
        0x54, 0x22, 0xa5, 0xd6, 0xfc, 0x81, 0x73, 0xf9, 0xc8, 0x6c, 0xdd, 0x72,
        0x13, 0x13, 0xe1, 0x8c, 0x87, 0xc1, 0xc2, 0x24, 0x0e, 0x20, 0x42, 0x21,
        0x57, 0x8d, 0x1c, 0x89, 0xad, 0x30, 0x23, 0xee, 0xa9, 0xa9, 0x27, 0xaa,
        0x3c, 0xe2, 0x93, 0x44, 0x1f, 0xbe, 0x34, 0x1b, 0xfc, 0x2d, 0xf8, 0x61
    };

    char resp_main_hash[] = {
        0xc6, 0xd1, 0x45, 0x92, 0x85, 0x15, 0x0c, 0x7e, 0x6e, 0x96, 0x1f, 0x01,
        0xbf, 0x17, 0x9b, 0x35, 0x08, 0x10, 0x20, 0x01, 0x22, 0x1f, 0xaf, 0x3c,
        0x00, 0x00, 0x00, 0x9c, 0x10, 0x24, 0xa6, 0xb6, 0x4c, 0xe3, 0xa2, 0x1d,
        0x79, 0xe0, 0x1f, 0x9c, 0xf6, 0x17, 0x9e, 0xe2, 0x31, 0x15, 0x57, 0xe5,
        0x60, 0x5d, 0xed, 0x7b, 0x89, 0xca, 0xf5, 0xb2, 0xa3, 0x76, 0xae, 0xb4,
        0x86, 0x9c, 0x04, 0x80, 0x0e, 0x33, 0x41, 0x7e, 0x31, 0x1c, 0x9f, 0xac,
        0x05, 0x27, 0x91, 0x8c, 0x13, 0x1f, 0xeb, 0x46, 0x38, 0xd3, 0xc3, 0x4d,
        0x02, 0x12, 0xcf, 0xdc, 0x75, 0x62, 0x25, 0x42, 0x8d, 0x4e, 0x6e, 0xe4,
        0x38, 0x1b, 0xdb, 0x82, 0xec, 0x57, 0x7e, 0x8f, 0x41, 0x76, 0x30, 0x45,
        0x39, 0xeb, 0x19, 0x73, 0xf8, 0xfe, 0x57, 0x71, 0xc1, 0x84, 0x9a, 0xa6,
        0x6d, 0x28, 0xc6, 0x7f, 0xcd, 0x23, 0xec, 0x87, 0xd8, 0x93, 0xdf, 0xe9,
        0x4e, 0x4d, 0x23, 0x7a, 0x53, 0x07, 0x5b, 0x9a, 0x99, 0xb2, 0x26, 0xd8,
        0xe3, 0xe0, 0x74, 0x6e, 0xe8, 0x65, 0x18, 0xec, 0x03, 0x09, 0x7f, 0x42
    };

    char init_main_hash_2[] = {
        0xc6, 0xd1, 0x45, 0x92, 0x85, 0x15, 0x0c, 0x7e, 0x6e, 0x96, 0x1f, 0x01,
        0xbf, 0x17, 0x9b, 0x35, 0x08, 0x10, 0x20, 0x01, 0x22, 0x1f, 0xaf, 0x3c,
        0x00, 0x00, 0x00, 0x34, 0xb8, 0xd5, 0x8d, 0x91, 0x8b, 0x06, 0x31, 0x23,
        0xb2, 0xf1, 0xb9, 0xfa, 0xdf, 0x28, 0xb5, 0x09, 0x36, 0x19, 0x50, 0x99,
        0x8b, 0xdb, 0x53, 0x5a
    };

    /* expected output data */
    char init_ke_value[] = {
        0xa8, 0x12, 0xa5, 0xfb, 0xfc, 0xba, 0xe8, 0x2c, 0x7d, 0xf0, 0xde, 0xae,
        0xc2, 0x12, 0x0f, 0xe8, 0xa9, 0xb7, 0xe8, 0x2f, 0xc1, 0xce, 0x7a, 0xd1,
        0x6e, 0x38, 0xe0, 0x68, 0x7d, 0x3e, 0xb0, 0x4f, 0x4c, 0x9a, 0xb8, 0x8f,
        0xe3, 0xd3, 0xba, 0xed, 0x7d, 0xa3, 0xcb, 0xf3, 0xdd, 0xec, 0x86, 0xcf,
        0x95, 0xb0, 0xdd, 0xe8, 0x7e, 0xe0, 0x86, 0xab, 0x23, 0x6e, 0x06, 0xd1,
        0x7c, 0x45, 0x9f, 0xef, 0x8e, 0x2f, 0xc9, 0x4d, 0x80, 0x4b, 0xe9, 0xaf,
        0x45, 0xe7, 0x44, 0xc2, 0x07, 0xef, 0x98, 0x75, 0x12, 0xd6, 0x8d, 0xd2,
        0xed, 0xf1, 0xca, 0x57, 0xe9, 0x1c, 0x98, 0xdc, 0x26, 0x88, 0xf7, 0x7a,
        0x57, 0x90, 0x0a, 0xed, 0x18, 0xf3, 0x68, 0xcb, 0xfb, 0x8d, 0x4b, 0x46,
        0xbe, 0xa5, 0xe4, 0x8a, 0x53, 0xcb, 0x88, 0xcd, 0x51, 0x5a, 0x17, 0xdd,
        0x1d, 0x03, 0x2d, 0x1c, 0x79, 0x54, 0x0f, 0x86
    };

    char resp_ke_value[] = {
        0x0a, 0x63, 0x93, 0xc0, 0xc2, 0xb7, 0xaf, 0x92, 0x77, 0xe6, 0xc3, 0x6e,
        0x41, 0x11, 0xea, 0x88, 0xb8, 0x7d, 0xad, 0x6b, 0x50, 0x09, 0xb9, 0x09,
        0xa0, 0xaa, 0x66, 0x10, 0x1d, 0x7b, 0x3d, 0x70, 0x91, 0x82, 0x93, 0x4b,
        0x0f, 0x0b, 0xca, 0x9f, 0x77, 0xc9, 0xca, 0xaf, 0xf3, 0x3f, 0x00, 0x6d,
        0xc4, 0x8d, 0xdd, 0x91, 0x8c, 0xbc, 0x31, 0xe2, 0x7a, 0x64, 0x49, 0x2f,
        0x0a, 0xeb, 0xa7, 0x32, 0x2d, 0x54, 0xe1, 0x35, 0x95, 0x09, 0xde, 0x1b,
        0x44, 0xee, 0x04, 0x84, 0x00, 0xc7, 0xbd, 0x0f, 0x66, 0xd2, 0x22, 0xac,
        0xc1, 0xa1, 0xa4, 0xf5, 0xd1, 0xcb, 0xb7, 0x9c, 0xfa, 0x44, 0x36, 0x0a,
        0x56, 0x66, 0xe9, 0x06, 0x03, 0x12, 0x1d, 0xb6, 0x6f, 0x28, 0x3c, 0xe1,
        0x67, 0x62, 0x8e, 0xb1, 0xe9, 0xf5, 0xa9, 0x65, 0x1b, 0x79, 0x8f, 0x6a,
        0xa3, 0x80, 0xbe, 0x24, 0x12, 0xe2, 0xc0, 0xd4
    };

    ike_init(&init);
    ike_update(init, NULL, init_main_sa, sizeof(init_main_sa), 1);
    ike_update(init, NULL, init_main_notify, sizeof(init_main_notify), 1);
    ike_update(init, NULL, init_main_ke, sizeof(init_main_ke), 1);
    ike_update(init, NULL, init_main_id, sizeof(init_main_id), 1);
    ike_update(init, NULL, init_main_hash, sizeof(init_main_hash), 1);
    ike_update(init, NULL, init_main_hash_2, sizeof(init_main_hash_2), 1);

    ike_init(&resp);
    ike_update(resp, NULL, resp_main_sa, sizeof(resp_main_sa), 1);
    ike_update(resp, NULL, resp_main_sa_2, sizeof(resp_main_sa_2), 1);
    ike_update(resp, NULL, resp_main_ke, sizeof(resp_main_ke), 1);
    ike_update(resp, NULL, resp_main_id, sizeof(resp_main_id), 1);
    ike_update(resp, NULL, resp_main_hash, sizeof(resp_main_hash), 1);

    ike_process(init, resp);

    if (resp->messages[0]->payloads[0]->body->sa->proposals[0]->transforms[0]->id_v1 != IKE_KEY_IKE_V1) {
        joy_log_err("responder transform id");
        num_fails++;
    }

    if (resp->messages[0]->payloads[0]->body->sa->proposals[0]->transforms[0]->attributes[2]->type != IKE_ENCRYPTION_ALGORITHM_V1) {
        joy_log_err("responder attribute type");
        num_fails++;
    }

    if (raw_to_uint16((char *)resp->messages[0]->payloads[0]->body->sa->proposals[0]->transforms[0]->attributes[2]->data->bytes) != IKE_ENCR_3DES_CBC_V1) {
        joy_log_err("responder attribute value");
        num_fails++;
    }

    if (memcmp(init->messages[2]->payloads[0]->body->ke->data->bytes, init_ke_value, sizeof(init_ke_value)) != 0) {
        joy_log_err("initiator key exchange value");
        num_fails++;
    }

    if (memcmp(resp->messages[2]->payloads[0]->body->ke->data->bytes, resp_ke_value, sizeof(resp_ke_value)) != 0) {
        joy_log_err("responder key exchange value");
        num_fails++;
    }

    ike_delete(&init);
    ike_delete(&resp);
    return num_fails;
}

static int ike_test_v2_handshake() {
    struct ike *init = NULL, *resp = NULL;
    int num_fails = 0;

    /* input data */
    char init_sa[] = {
        0x81, 0xf2, 0x4c, 0x0a, 0xcd, 0x8f, 0xa5, 0x5c, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x21, 0x20, 0x22, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xf0, 0x22, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x2c,
        0x01, 0x01, 0x00, 0x04, 0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x0d,
        0x80, 0x0e, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0e,
        0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08,
        0x04, 0x00, 0x00, 0x13, 0x28, 0x00, 0x00, 0x48, 0x00, 0x13, 0x00, 0x00,
        0x22, 0x8a, 0x8d, 0xcf, 0xf0, 0x5f, 0x3d, 0xaa, 0x36, 0xd0, 0x63, 0x06,
        0xd6, 0x27, 0xc3, 0xf1, 0x00, 0x0b, 0xf1, 0xc1, 0x60, 0x3d, 0x01, 0x99,
        0x49, 0x2c, 0x3e, 0xdb, 0x8d, 0xe7, 0x31, 0xf4, 0xec, 0x89, 0x8c, 0x19,
        0xae, 0xb2, 0x8c, 0x87, 0x83, 0x1b, 0x67, 0xd8, 0xd7, 0x54, 0xbd, 0xe2,
        0x37, 0x7b, 0x90, 0xcd, 0xb0, 0x7f, 0x81, 0x98, 0xb2, 0x4a, 0xeb, 0xd3,
        0xcf, 0x49, 0xf2, 0x17, 0x29, 0x00, 0x00, 0x24, 0x68, 0x6e, 0x71, 0x3e,
        0x64, 0xa4, 0x19, 0xd5, 0x4f, 0x55, 0x49, 0x71, 0x52, 0xee, 0x97, 0x1c,
        0xfb, 0xe5, 0x61, 0x84, 0x8c, 0x68, 0x8b, 0x29, 0x29, 0x6e, 0xb6, 0xa5,
        0x83, 0xc0, 0x08, 0x5a, 0x29, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x04,
        0x1d, 0x52, 0x67, 0x7b, 0x25, 0x84, 0xe0, 0x88, 0x31, 0x9b, 0xab, 0xfb,
        0xdb, 0xaf, 0x8a, 0x20, 0xc4, 0x5f, 0x6b, 0x9b, 0x00, 0x00, 0x00, 0x1c,
        0x00, 0x00, 0x40, 0x05, 0xe8, 0x60, 0x67, 0x43, 0x52, 0x6b, 0xfb, 0xac,
        0x95, 0xc6, 0xaf, 0x46, 0x21, 0xd8, 0x7f, 0xa2, 0x95, 0x34, 0xb0, 0xb1
    };

    char resp_sa[] = {
        0x81, 0xf2, 0x4c, 0x0a, 0xcd, 0x8f, 0xa5, 0x5c, 0x19, 0x23, 0x83, 0x17,
        0x27, 0x24, 0xc7, 0x06, 0x21, 0x20, 0x22, 0x20, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xf8, 0x22, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x2c,
        0x01, 0x01, 0x00, 0x04, 0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x0d,
        0x80, 0x0e, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0e,
        0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08,
        0x04, 0x00, 0x00, 0x13, 0x28, 0x00, 0x00, 0x48, 0x00, 0x13, 0x00, 0x00,
        0x4d, 0xc1, 0x5d, 0x7d, 0xdd, 0x51, 0x78, 0x3c, 0x68, 0xd8, 0x42, 0x62,
        0x7e, 0xaa, 0x21, 0x39, 0xf4, 0xec, 0xba, 0xbc, 0xe7, 0x3c, 0xac, 0x7d,
        0xc2, 0x1b, 0x98, 0x48, 0xfc, 0xcb, 0xb4, 0xda, 0x9e, 0xb3, 0xa9, 0x6c,
        0x3a, 0xf5, 0x0c, 0x55, 0xa6, 0xe8, 0xd6, 0x44, 0xa0, 0x17, 0x86, 0x7a,
        0x62, 0xe5, 0x42, 0xde, 0x0b, 0x1d, 0x8f, 0x3e, 0x25, 0x25, 0xeb, 0x60,
        0x68, 0x6f, 0x60, 0xca, 0x29, 0x00, 0x00, 0x24, 0xdd, 0xad, 0x86, 0x2e,
        0x6d, 0x6f, 0x89, 0xd9, 0x6d, 0x9f, 0x14, 0x67, 0xc9, 0xdf, 0x63, 0x54,
        0x06, 0x87, 0x0a, 0x16, 0xbe, 0x3f, 0xd0, 0x1a, 0x8e, 0xec, 0xbc, 0xd2,
        0x0c, 0xa4, 0xd6, 0xeb, 0x29, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x04,
        0x3a, 0xf8, 0x06, 0xbc, 0xb2, 0xcd, 0xce, 0xed, 0x0b, 0x56, 0xb1, 0xf7,
        0xdc, 0xb2, 0x71, 0xcf, 0x3d, 0x13, 0x83, 0x07, 0x29, 0x00, 0x00, 0x1c,
        0x00, 0x00, 0x40, 0x05, 0xb7, 0x81, 0xd9, 0x18, 0xe5, 0xbe, 0xd4, 0x65,
        0xe9, 0x4c, 0x04, 0x47, 0x11, 0xe4, 0xd1, 0xb3, 0x54, 0xba, 0x3e, 0x02,
        0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x14
    };

    char init_auth[] = {
        0x81, 0xf2, 0x4c, 0x0a, 0xcd, 0x8f, 0xa5, 0x5c, 0x19, 0x23, 0x83, 0x17,
        0x27, 0x24, 0xc7, 0x06, 0x2e, 0x20, 0x23, 0x08, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x01, 0x05, 0x23, 0x00, 0x00, 0xe9, 0x8f, 0xd5, 0x6b, 0x80,
        0x8b, 0x82, 0xb1, 0xac, 0xae, 0x6d, 0x93, 0x91, 0x3f, 0xc1, 0xc7, 0x55,
        0x66, 0x7b, 0x2a, 0xc8, 0x44, 0xa5, 0xec, 0x1d, 0x6b, 0xec, 0xfe, 0xed,
        0xe0, 0x5b, 0x07, 0xed, 0xab, 0x5d, 0xe9, 0xb5, 0xea, 0x55, 0x4f, 0xc9,
        0xfc, 0x35, 0x42, 0x63, 0x72, 0x0d, 0xad, 0x7b, 0x76, 0x0a, 0xdf, 0x9a,
        0x54, 0x75, 0x74, 0x7d, 0x74, 0x7f, 0x60, 0x41, 0x42, 0xb4, 0xf5, 0xf3,
        0x19, 0x25, 0x21, 0x75, 0x58, 0x1e, 0xa3, 0x11, 0x01, 0x7a, 0x47, 0xc7,
        0x49, 0xed, 0x0b, 0x65, 0x58, 0xfd, 0x60, 0xca, 0xec, 0x8e, 0x89, 0xcc,
        0x27, 0xe0, 0xb5, 0x3c, 0x21, 0x02, 0xd2, 0x13, 0x5c, 0xd7, 0xbb, 0xfb,
        0x70, 0x96, 0xc5, 0xba, 0xb3, 0xf9, 0xd9, 0xdd, 0xa3, 0x83, 0x64, 0x58,
        0xff, 0x87, 0xb5, 0x82, 0x9e, 0x61, 0x1a, 0x91, 0x7a, 0x1f, 0xf7, 0xc8,
        0xa0, 0xcc, 0x41, 0xef, 0x73, 0x70, 0x2e, 0x8e, 0x89, 0xa8, 0x6d, 0xa2,
        0xb2, 0xbc, 0xfe, 0x28, 0x73, 0xed, 0x1c, 0x1e, 0x39, 0xb6, 0xc8, 0xfa,
        0x0e, 0xb3, 0xd9, 0x32, 0x39, 0xf0, 0x37, 0xae, 0x5a, 0xd4, 0x65, 0x32,
        0xb0, 0xbd, 0x0e, 0x29, 0xf6, 0xf9, 0x71, 0x6f, 0x68, 0x98, 0x90, 0xba,
        0x72, 0xdb, 0x1e, 0x68, 0xb4, 0x52, 0x91, 0xbe, 0xb5, 0xdb, 0x0a, 0x58,
        0xe1, 0x66, 0xea, 0x75, 0x7b, 0x7c, 0xfb, 0xcd, 0xe9, 0x78, 0xfb, 0x3d,
        0xfc, 0xae, 0x32, 0xb7, 0x66, 0xc0, 0x90, 0x29, 0x1d, 0xdc, 0x74, 0x76,
        0xe6, 0x40, 0x5c, 0x60, 0xe5, 0xa1, 0x91, 0x63, 0x0f, 0x3d, 0x3e, 0x8e,
        0x08, 0x76, 0xb1, 0x87, 0x1d, 0x85, 0xd3, 0x4b, 0x97
    };

    char resp_auth[] = {
        0x81, 0xf2, 0x4c, 0x0a, 0xcd, 0x8f, 0xa5, 0x5c, 0x19, 0x23, 0x83, 0x17,
        0x27, 0x24, 0xc7, 0x06, 0x2e, 0x20, 0x23, 0x20, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0xed, 0x24, 0x00, 0x00, 0xd1, 0x26, 0x7f, 0x9a, 0x27,
        0xaf, 0x8a, 0x94, 0x8a, 0x3e, 0xb5, 0xda, 0xad, 0xf3, 0x98, 0xc3, 0x42,
        0x49, 0x65, 0x0d, 0xc0, 0x4e, 0xe3, 0x09, 0x5d, 0x7c, 0xd0, 0x12, 0x21,
        0xd4, 0x80, 0xbc, 0x0b, 0xab, 0x04, 0x2e, 0x70, 0xa6, 0xbd, 0x24, 0x2c,
        0xca, 0xda, 0xff, 0x6d, 0x53, 0xf4, 0x47, 0x7a, 0x7b, 0x1e, 0xd1, 0xab,
        0x85, 0x4e, 0x5e, 0xd4, 0xd0, 0x73, 0x9a, 0x14, 0xee, 0xe7, 0x91, 0x5c,
        0x5f, 0xa5, 0x29, 0xf1, 0x72, 0x97, 0x79, 0x09, 0x7e, 0x8a, 0xb3, 0xce,
        0x33, 0xa1, 0xe5, 0x98, 0xcd, 0x7e, 0x28, 0xf2, 0x14, 0xac, 0x7a, 0xa7,
        0x8b, 0x52, 0xbc, 0x20, 0xf8, 0x21, 0x1d, 0xdb, 0xd3, 0x75, 0x35, 0x60,
        0x56, 0xd9, 0xad, 0x65, 0xa2, 0x55, 0x9a, 0xc2, 0x44, 0x3c, 0x06, 0xef,
        0x6a, 0xd3, 0x6b, 0xaa, 0xc1, 0xa1, 0x5b, 0x1b, 0x6a, 0x16, 0x49, 0x84,
        0x00, 0xc5, 0x6d, 0x22, 0x3b, 0x4b, 0x3e, 0x07, 0x2c, 0x5a, 0xb7, 0xa7,
        0x58, 0x14, 0xa5, 0x16, 0xcb, 0xad, 0xc3, 0x0e, 0xa6, 0x6f, 0x48, 0xaf,
        0x9d, 0x7e, 0x27, 0x51, 0x2a, 0xd1, 0x9d, 0xe7, 0xa2, 0x03, 0x71, 0x9c,
        0x06, 0x30, 0xac, 0xbb, 0x11, 0xec, 0xa3, 0xcd, 0x82, 0xa4, 0xae, 0xb5,
        0x51, 0x2b, 0xf6, 0x77, 0x00, 0xb3, 0xc4, 0xfa, 0x99, 0x31, 0x3a, 0x94,
        0xee, 0x79, 0xe3, 0x65, 0x3f, 0x51, 0x9d, 0xeb, 0x8e, 0xb9, 0x7b, 0x6b,
        0x06, 0x11, 0x3f, 0x92, 0xb5, 0xce, 0x8b, 0xeb, 0xd0
    };

    char init_info[] = {
        0x81, 0xf2, 0x4c, 0x0a, 0xcd, 0x8f, 0xa5, 0x5c, 0x19, 0x23, 0x83, 0x17,
        0x27, 0x24, 0xc7, 0x06, 0x2e, 0x20, 0x25, 0x08, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x51, 0x2a, 0x00, 0x00, 0x35, 0x33, 0x48, 0x63, 0xfb,
        0xb6, 0xf6, 0x33, 0xdf, 0x82, 0x51, 0x51, 0xae, 0x4d, 0x67, 0xc4, 0x54,
        0xb0, 0x76, 0x00, 0x02, 0xaa, 0x6f, 0x66, 0x5b, 0x62, 0xf9, 0x14, 0x19,
        0x79, 0x02, 0x93, 0xe8, 0x59, 0x1a, 0xe8, 0xbd, 0xaf, 0x39, 0x36, 0x4b,
        0x48, 0xc8, 0x0e, 0x88, 0x78, 0x33, 0x5d, 0xbc, 0xd6
    };

    char resp_info[] = {
        0x81, 0xf2, 0x4c, 0x0a, 0xcd, 0x8f, 0xa5, 0x5c, 0x19, 0x23, 0x83, 0x17,
        0x27, 0x24, 0xc7, 0x06, 0x2e, 0x20, 0x25, 0x20, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x00, 0x2d, 0x26, 0x7f, 0x9a, 0x24,
        0xaf, 0x8a, 0x94, 0x8a, 0xba, 0x0d, 0xfd, 0x95, 0x1b, 0x96, 0xc0, 0x5c,
        0x09, 0x14, 0x57, 0x2e, 0x37, 0xc5, 0xb9, 0x97, 0xdb, 0x67, 0x34, 0xfb,
        0x5b, 0x4d, 0xdf, 0x20, 0x18, 0x1c, 0x1f, 0xb7, 0x1a, 0xf5, 0xf0, 0x6e,
        0xfa
    };

    /* expected output data */
    char init_ke_value[] = {
        0x22, 0x8a, 0x8d, 0xcf, 0xf0, 0x5f, 0x3d, 0xaa, 0x36, 0xd0, 0x63, 0x06,
        0xd6, 0x27, 0xc3, 0xf1, 0x00, 0x0b, 0xf1, 0xc1, 0x60, 0x3d, 0x01, 0x99,
        0x49, 0x2c, 0x3e, 0xdb, 0x8d, 0xe7, 0x31, 0xf4, 0xec, 0x89, 0x8c, 0x19,
        0xae, 0xb2, 0x8c, 0x87, 0x83, 0x1b, 0x67, 0xd8, 0xd7, 0x54, 0xbd, 0xe2,
        0x37, 0x7b, 0x90, 0xcd, 0xb0, 0x7f, 0x81, 0x98, 0xb2, 0x4a, 0xeb, 0xd3,
        0xcf, 0x49, 0xf2, 0x17
    };

    char resp_ke_value[] = {
        0x4d, 0xc1, 0x5d, 0x7d, 0xdd, 0x51, 0x78, 0x3c, 0x68, 0xd8, 0x42, 0x62,
        0x7e, 0xaa, 0x21, 0x39, 0xf4, 0xec, 0xba, 0xbc, 0xe7, 0x3c, 0xac, 0x7d,
        0xc2, 0x1b, 0x98, 0x48, 0xfc, 0xcb, 0xb4, 0xda, 0x9e, 0xb3, 0xa9, 0x6c,
        0x3a, 0xf5, 0x0c, 0x55, 0xa6, 0xe8, 0xd6, 0x44, 0xa0, 0x17, 0x86, 0x7a,
        0x62, 0xe5, 0x42, 0xde, 0x0b, 0x1d, 0x8f, 0x3e, 0x25, 0x25, 0xeb, 0x60,
        0x68, 0x6f, 0x60, 0xca
    };

    ike_init(&init);
    ike_update(init, NULL, init_sa, sizeof(init_sa), 1);
    ike_update(init, NULL, init_auth, sizeof(init_auth), 1);
    ike_update(init, NULL, init_info, sizeof(init_info), 1);

    ike_init(&resp);
    ike_update(resp, NULL, resp_sa, sizeof(resp_sa), 1);
    ike_update(resp, NULL, resp_auth, sizeof(resp_auth), 1);
    ike_update(resp, NULL, resp_info, sizeof(resp_info), 1);

    ike_process(init, resp);

    if (resp->messages[0]->payloads[0]->body->sa->proposals[0]->transforms[0]->type != IKE_ENCRYPTION_ALGORITHM_V2) {
        joy_log_err("responder transform type");
        num_fails++;
    }

    if (resp->messages[0]->payloads[0]->body->sa->proposals[0]->transforms[0]->id != IKE_ENCR_AES_CTR_V2) {
        joy_log_err("responder transform id");
        num_fails++;
    }

    if (raw_to_uint16((char *)resp->messages[0]->payloads[0]->body->sa->proposals[0]->transforms[0]->attributes[0]->data->bytes) != 192) {
        joy_log_err("responder attribute value");
        num_fails++;
    }

    if (memcmp(init->messages[0]->payloads[1]->body->ke->data->bytes, init_ke_value, sizeof(init_ke_value)) != 0) {
        joy_log_err("initiator key exchange value");
        num_fails++;
    }

    if (memcmp(resp->messages[0]->payloads[1]->body->ke->data->bytes, resp_ke_value, sizeof(resp_ke_value)) != 0) {
        joy_log_err("responder key exchange value");
        num_fails++;
    }

    ike_delete(&init);
    ike_delete(&resp);
    return num_fails;
}

void ike_unit_test() {
    int num_fails = 0;

    fprintf(info, "\n******************************\n");
    fprintf(info, "IKE Unit Test starting...\n");

    num_fails += ike_test_v1_handshake();
    num_fails += ike_test_v2_handshake();

    if (num_fails) {
        fprintf(info, "Finished - # of failures: %u\n", num_fails);
    } else {
        fprintf(info, "Finished - success\n");
    }
    fprintf(info, "******************************\n\n");
}
