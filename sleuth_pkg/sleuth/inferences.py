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
import string

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
            #print json.dumps(tmp)
            fpvalue = json.dumps(tmp['str_repr'])
            fpvalue = fpvalue.strip('"')
            if fpvalue in tls_fp_dict:
                print "warning: duplicate tls fingerprint in line " + str(counter + 1) + " of file " + tls_fp_file
            tls_fp_dict[fpvalue] = tmp


def grease_normalize(s):
    g = [ '0a0a', '1a1a', '2a2a', '3a3a', '4a4a', '5a5a', '6a6a', '7a7a',
          '8a8a', '9a9a', 'aaaa', 'baba', 'caca', 'dada', 'eaea', 'fafa' ]
    if s in g:
        return '0a0a'
    else:
        return s

def grease_normalize_array(s):
    output = ''
    for i in range(0, len(s), 4):
        output += grease_normalize(s[i:i+4])
    return output

            
def hex_fp_normalize(s):
    xtn_grease_list = [
        10,        # supported_groups
        11,        # ec_point_formats
        13,        # signature_algorithms
        43         # supported_versions  
    ]
    
    output = ''

    # parse protocol version 
    output += s[0:4]

    # parse ciphersuite offer vector
    cs_len = s[4:8]
    output += cs_len
    
    cs_data_len = int(cs_len, 16)*2    
    cs_vec = s[8:8+cs_data_len]
    output += grease_normalize_array(cs_vec)
        
    # parse client extensions, if present
    ext_index = 8+cs_data_len
    ext_len = s[ext_index:ext_index+4]
    if ext_len == '':
        return output
    output += ext_len
    
    ext_data_len = int(ext_len, 16)*2 
    ext_data = s[ext_index+4:ext_index+4+ext_data_len]

    x_index = 0    
    while x_index + 8 <= len(ext_data):
        x_type = ext_data[x_index+0:x_index+4]
        x_len  = ext_data[x_index+4:x_index+8]
        x_index_next = x_index + int(x_len, 16) * 2 + 8
        x_data = ext_data[x_index+8:x_index_next]
        x_index = x_index_next
        output += grease_normalize(x_type) + x_len
        output += grease_normalize_array(x_data)

    return output


def element_is_parent(s):
    if s:
        if s[0] is '(' and s[1] is '(':
            return True
        else:
            return False
    else:
        return False

def get_next_element(s):
    if s is '':
        return '', '', 0
    if s[0] is ')':
        level = 0
        for c in s:
            if c is not ')':
                break;
            level = level + 1
        return '', '', -level

    if True:
        level = 0
        while s[level] is '(':
            level = level + 1

        if level is 0:
            return '', '', 0

        tmp =  string.split(s[level:], ')', 1)
        tmp.append(level-1)
        return tmp

def print_out_structured_data(s):
    current_level = 0
    while s is not '':
        element, s, level = get_next_element(s)
        current_level += level
        print current_level, element, s 


def structured_fp_normalize(s):
    xtn_grease_list = [
        10,        # supported_groups
        11,        # ec_point_formats
        13,        # signature_algorithms
        43         # supported_versions  
    ]
    
    output = ''

    # parse protocol version 
    element, s, level = get_next_element(s)
    output += '(' + element + ')'

    # parse ciphersuite offer vector
    element, s, level = get_next_element(s)
    output += '(' + grease_normalize(element) + ')'
    
    # parse client extensions, if present
    output += '('
    while s is not '' and s is not ')':
        element, s, level = get_next_element(s)
        typecode = element[0:4]
        data = element[4:]
        output += '(' + grease_normalize(typecode) + grease_normalize_array(data) + ')'
    output += ')'
        
    return output


def tls_inference(f, kwargs):
    global tls_fp_dict
    
    if not tls_fp_dict:
        tls_fp_dict_init()
        # print json.dumps(tls_fp_dict)

    if 'fingerprints' in f:
        if 'tls' in f['fingerprints']:

            # get tls fingerprint value from object
            #            
            fpvalue = json.dumps(f['fingerprints']['tls'])
            fpvalue = fpvalue.strip('"')

            # normalize GREASE values, then look up inferences
            #
            fpvalue = structured_fp_normalize(fpvalue)
            if fpvalue in tls_fp_dict:
                return {'tls': tls_fp_dict[fpvalue]}
            else:
                return {'tls': 'unknown fingerprint' }

    return None

