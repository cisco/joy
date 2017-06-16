"""
 *
 * Copyright (c) 2017 Cisco Systems, Inc.
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
"""
import os
import json

# A security_category object is one of { recommended, acceptable, legacy, avoid }
#

UNKNOWN = 0
INVALID = 1
VALID = 2


security_categories = {
    "unknown": 0,
    "avoid": 1,
    "legacy": 2,
    "acceptable": 3,
    "recommended": 4,
}


seclevel_names = {v: k for k, v in security_categories.iteritems()}


def seclevel(x):
    if x in seclevel_names:
        return seclevel_names[x]
    if x in security_categories:
        return security_categories[x]
    return 0

# A hash/enc/kex/sig/auth *_policy object maps a crypto mechanism to a
# security_category
#
hash_policy = {
    "SHA": 2,
    "NULL": 1,
    "SHA256": 4,
    "SHA384": 4,
    "MD5": 1
}

enc_policy = {
    "ARIA_128_GCM": 3,
    "DES_CBC": 1,
    "ARIA_128_CBC": 3,
    "CAMELLIA_256_GCM": 3,
    "AES_128_CCM": 4,
    "CAMELLIA_128_GCM": 3,
    "3DES_EDE_CBC": 2,
    "DES40_CBC": 1,
    "ARIA_256_GCM": 3,
    "SEED_CBC": 2,
    "RC4_128": 1,
    "NULL": 1,
    "CAMELLIA_256_CBC": 3,
    "ARIA_256_CBC": 3,
    "RC4_40": 1,
    "RC2_CBC_40": 1,
    "AES_256_GCM": 4,
    "IDEA_CBC": 1,
    "AES_128_CCM_8": 3,
    "AES_128_CBC": 3,
    "AES_256_CCM": 3,
    "CHACHA20_POLY1305": 3,
    "AES_256_CBC": 3,
    "AES_128_GCM": 3,
    "CAMELLIA_128_CBC": 3,
    "AES_256_CCM_8": 3
}

sig_policy = {
    "KRB5": 3,
    "PSK": 2,
    "SRP_SHA": 2,
    "RSA-KT": 3,
    "DSS": 2,
    "SRP_SHA_RSA": 2,
    "RSA": 3,
    "anon": 1,
    "NULL": 1,
    "ECDSA": 4
}

auth_policy = {
    "AES_256_GCM": 4,
    "NULL": 1,
    "AES_256_CCM": 3,
    "CHACHA20_POLY1305": 3,
    "AES_128_CCM_8": 3,
    "ARIA_128_GCM": 3,
    "AES_256_CCM_8": 3,
    "CAMELLIA_256_GCM": 3,
    "AES_128_CCM": 3,
    "CAMELLIA_128_GCM": 3,
    "AES_128_GCM": 4,
    "ARIA_256_GCM": 3,
    "HMAC": 3
}

kex_policy = {
    "KRB5": 3,
    "PSK": 2,
    "DH": 2,
    "SRP_SHA": 2,
    "ECDH_anon": 1,
    "DHE": 3,
    "ECDH": 3,
    "RSA": 3,
    "SRP_SHA_RSA": 2,
    "ECDHE": 4,
    "DHE_PSK": 3,
    "NULL": 1,
    "DH_anon": 1
}

sig_alg_policy = {
   "sha1WithRSAEncryption": 1,
   "sha256WithRSAEncryption": 3,
   "sha384WithRSAEncryption": 3,
   "sha512WithRSAEncryption": 4,
   "ecdsa-with-SHA256": 3
}


def tls_seclevel(scs, client_key_length, certs):
    if not scs:
        return 'unknown'

    cur_dir = os.path.dirname(__file__)
    data_file = "data_tls_params.json"
    data_path = os.path.join(cur_dir, data_file)

    with open(data_path) as f:
        data = json.load(f)
        params = data["tls_params"][scs]

        kex = params['kex']
        if kex == "RSA" or kex == "DH" or kex == "DHE_anon" or kex == "DHE_PSK" or kex == "SRP_SHA" or kex == "SRP_SHA_RSA":
            if client_key_length < 1024:
                kex_seclevel = 1 # avoid
            elif client_key_length < 2048:
                kex_seclevel = 2 # legacy
            elif client_key_length < 3072:
                kex_seclevel = 3 # acceptable
            else:
                kex_seclevel = 4 # recommended

        elif kex == "ECDHE" or kex == "ECDH" or kex == "ECDH_anon":
            if client_key_length < 224:
                kex_seclevel = 1 # avoid
            elif client_key_length < 256:
                kex_seclevel = 2 # legacy
            elif client_key_length < 512:
                kex_seclevel = 3 # acceptable
            else:
                kex_seclevel = 4 # recommended
        else:
            kex_seclevel = kex_policy[kex]

        if certs:
            certs_seclevel = 4
            for x in certs:
                sig_alg = x['signature_algorithm']
                sig_key_size = x['signature_key_size']
                if sig_alg == "sha1WithRSAEncryption":
                    if sig_key_size < 1024:
                        tmp_seclevel = 1
                    else:
                        tmp_seclevel = 2
                elif sig_alg == "sha256WithRSAEncryption":
                    if sig_key_size < 1024:
                        tmp_seclevel = 1
                    elif sig_key_size < 2048:
                        tmp_seclevel = 2
                    else:
                        tmp_seclevel = 3
                elif sig_alg == "ecdsa-with-SHA256":
                    if sig_key_size < 832:
                        tmp_seclevel = 1
                    else:
                        tmp_seclevel = 3
                elif sig_alg == "sha384WithRSAEncryption" or sig_alg == "sha512WithRSAEncryption":
                    if sig_key_size < 1024:
                        tmp_seclevel = 1
                    elif sig_key_size < 2048:
                        tmp_seclevel = 2
                    elif sig_key_size < 3072:
                        tmp_seclevel = 3
                    else:
                        tmp_seclevel = 4
                else:
                    tmp_seclevel = 0
                if tmp_seclevel < certs_seclevel:
                    certs_seclevel = tmp_seclevel
        else:
            certs_seclevel = 0

        return seclevel(min(kex_seclevel,
                            certs_seclevel,
                            sig_policy[params['sig']],
                            enc_policy[params['enc']],
                            auth_policy[params['auth']],
                            hash_policy[params['hash']]))


def enrich_tls(flow):
    if 'tls' not in flow:
        return None
    else:
        # Get security-relevant parameters from flow record
        tls = flow['tls']

        if 'tls_client_key_length' in tls:
            # Subtract 16 encoding bits
            client_key_length = tls['tls_client_key_length'] - 16
        else:
            client_key_length = None

        if 's_tls_ext' in tls:
            server_extensions = tls['s_tls_ext']
        else:
            server_extensions = None

        if 'scs' in tls:
            scs = tls['scs']
        else:
            scs = None

        if 'server_cert' in tls:
            certs = list()
            for x in tls['server_cert']:
                tmp = dict()
                tmp['signature_algorithm'] = x['signature_algorithm']
                tmp['signature_key_size'] = x['signature_key_size']
                certs.append(tmp)
        else:
            certs = None

        # Evaluate seclevel based on parameters
        return tls_seclevel(scs, client_key_length, certs)