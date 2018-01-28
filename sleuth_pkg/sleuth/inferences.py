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
import pickle


tls_fp_dict = None


def tls_fp_dict_init():
    global tls_fp_dict
    tls_fp_file = 'res_tls_fingerprints.json'

    cur_dir = os.path.dirname(__file__)
    tls_fp_path = os.path.join(cur_dir, tls_fp_file)
    
    tls_fp_dict = {}
    with open(tls_fp_path) as f:
        for counter, line in enumerate(f):
            tmp = json.loads(line)
            fpvalue = pickle.dumps(tmp['fingerprint']['tls'])
            if fpvalue in tls_fp_dict:
                print "warning: duplicate tls fingerprint in line " + str(counter + 1) + " of file " + tls_fp_file
            tls_fp_dict[fpvalue] = tmp['label']


def tls_inference(f, kwargs):
    global tls_fp_dict
    
    if not tls_fp_dict:
        tls_fp_dict_init()

    if 'fingerprint' in f:
        if 'tls' in f['fingerprint']:
            fpvalue = pickle.dumps(f['fingerprint']['tls'])
            if fpvalue in tls_fp_dict:
                return {'tls': tls_fp_dict[fpvalue]}

    return None

