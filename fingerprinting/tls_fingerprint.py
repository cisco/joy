"""
tls_fingerprint provides backend functionality for fingerprinter.py,
  gen_tls_fingerprint.py, and fingerprint_ui.py

 *
 * Copyright (c) 2019 Cisco Systems, Inc.
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
import re
import ast
import json
import gzip
import copy
import time
import math
import struct
import numpy as np
from collections import OrderedDict
from sys import path
from tls_constants import *

grease_ = set(['0a0a','1a1a','2a2a','3a3a','4a4a','5a5a','6a6a','7a7a',
               '8a8a','9a9a','aaaa','baba','caca','dada','eaea','fafa'])

ext_data_extract_ = set(['0001','0005','0007','0008','0009','000a','000b',
                         '000d','000f','0010','0011','0013','0014','0018',
                         '001b','001c','002b','002d','0032','5500'])
ext_data_extract_ = ext_data_extract_.union(grease_)

cs_mapping_file = os.path.dirname(__file__) + '/resources/cs_mapping.json.gz'
with gzip.open(cs_mapping_file,'r') as fp:
    cs_mapping = json.loads(fp.read())

imp_date_cs_file = os.path.dirname(__file__) + '/resources/implementation_date_cs.json.gz'
with gzip.open(imp_date_cs_file,'r') as fp:
    imp_date_cs_data = json.loads(fp.read())

imp_date_ext_file = os.path.dirname(__file__) + '/resources/implementation_date_ext.json.gz'
with gzip.open(imp_date_ext_file,'r') as fp:
    imp_date_ext_data = json.loads(fp.read())




class TLSFingerprint:
    def __init__(self, fp_database):
        self.aligner = SequenceAlignment(f_similarity, 0.0)

        # populate fingerprint database
        self.fp_db = {}
        self.tls_params_db = {}
        if fp_database != None:
            with gzip.open(os.path.dirname(__file__) + '/' + fp_database, 'r') as file_pointer:
                for line in file_pointer:
                    fp_ = json.loads(line)
                    fp_['str_repr'] = fp_['str_repr'].replace('()','')
                    fp_['tls_features']['cs_mapping'] = self.gen_cs_mapping(fp_['tls_features']['cipher_suites'])
                    self.fp_db[fp_['str_repr']] = fp_
                    lit_fp = self.eval_fp_str(fp_['str_repr'])
                    tls_params_ = get_tls_params(lit_fp)
                    self.tls_params_db[fp_['str_repr']] = tls_params_

        # TLS ClientHello pattern/RE
        self.pattern = '\x16\x03[\x00-\x03].{2}\x01.{3}\x03[\x00-\x03]'
        self.matcher = re.compile(self.pattern)


    def fingerprint(self, data, detailed=False):
        # check TLS version and record/handshake type
        if self.matcher.match(data[0:11]) == None:
            return None

        # bounds checking
        record_length = int(data[3:5].encode('hex'),16)
        if record_length != len(data[5:]):
            return None

        fp_str_ = self.extract_fingerprint(data[5:])

        fp_ = None
        if fp_str_ in self.fp_db:
            fp_ = self.fp_db[fp_str_]
        else:
            lit_fp = self.eval_fp_str(fp_str_)
            approx_ = self.find_approx_match(lit_fp)
            if approx_ == None:
                fp_ = self.gen_unknown_fingerprint(fp_str_)
                self.fp_db[fp_str_] = fp_
            else:
                self.fp_db[fp_str_] = copy.deepcopy(self.fp_db[approx_])
                self.fp_db[fp_str_]['origin_str_repr'] = fp_str_
                self.fp_db[fp_str_]['source'] = ['similarity_match']
                fp_ = self.fp_db[fp_str_]
        if detailed == False and 'cs_mapping' in fp_['tls_features']:
            del fp_['tls_features']['cs_mapping']
        return fp_


    def find_approximate_matches_set(self, tls_params):
        t_scores = []
        p0_ = tls_params[0]
        p1_ = tls_params[1]
        for k in self.fp_db:
            if k not in self.tls_params_db:
                continue
	    q0_ = self.tls_params_db[k][0]
	    q1_ = self.tls_params_db[k][1]
            s0_ = len(list(set(p0_).intersection(set(q0_))))/float(len(list(set(p0_).union(set(q0_)))))
            s1_ = len(list(set(p1_).intersection(set(q1_))))/max(1.0,float(len(list(set(p1_).union(set(q1_))))))
            s_ = s0_ + s1_
            t_scores.append((s_, k))
        t_scores.sort()
        t_scores.reverse()
        return t_scores[0:25]


    def find_approx_match(self, tls_features):
        target_ = get_sequence(tls_features)
        tls_params_ = get_tls_params(tls_features)

        t_sim_set = []
        approx_matches_set = self.find_approximate_matches_set(tls_params_)
        for _,k in approx_matches_set:
            tmp_lit_fp = self.eval_fp_str(self.fp_db[k]['str_repr'])
	    test_ = get_sequence(tmp_lit_fp)
	    score_ = self.aligner.align(target_, test_)
            t_sim_set.append((1.0-2*score_/float(len(target_)+len(test_)), k))

        t_sim_set.sort()
        if t_sim_set[0][0] < 0.1:
            return t_sim_set[0][1]
        else:
            return None


    def gen_unknown_fingerprint(self, fp_str_, ui=True):
        fp_ = OrderedDict({})
        fp_['str_repr'] = fp_str_
        lit_fp = self.eval_fp_str(fp_str_)
        if len(lit_fp) < 2 or len(lit_fp[1]) < 1:
            fp_['error'] = 'fingerprint string parsing error'
            return fp_
        max_imp, min_imp = self.get_implementation_date(lit_fp[1][0])
        fp_['max_implementation_date'] = max_imp
        fp_['min_implementation_date'] = min_imp
        fp_['tls_features'] = OrderedDict({})
        fp_['tls_features']['cipher_suites'] = self.get_cs_from_str(lit_fp[1][0])
        fp_['tls_features']['extensions'] = []
        if ui:
            fp_['tls_features']['cs_mapping'] = self.gen_cs_mapping(fp_['tls_features']['cipher_suites'])
        if len(lit_fp) > 2:
            fp_['tls_features']['extensions'] = self.get_ext_from_str(lit_fp[2])
        fp_['process_info'] = [{'process': 'Unknown', 'application_category':'Unknown', 'prevalence':'Unknown','sha256':'Unknown'}]

        return fp_


    def eval_fp_str(self, fp_str_):
        fp_str_ = '(' + fp_str_ + ')'
        fp_str_ = fp_str_.replace('(','["').replace(')','"]').replace('][','],[')
        new_str_ = fp_str_.replace('["[','[[').replace(']"]',']]')
        while new_str_ != fp_str_:
            fp_str_ = new_str_
            new_str_ = fp_str_.replace('["[','[[').replace(']"]',']]')
        return ast.literal_eval(fp_str_)


    def get_cs_from_str(self, cs_str_):
        cs_l_ = []
        for i in range(0,len(cs_str_),4):
            cs_ = cs_str_[i:i+4]
            if cs_ in imp_date_cs_data:
                cs_l_.append(imp_date_cs_data[cs_]['name'])
            else:
                cs_l_.append(cs_)
        return cs_l_


    def get_ext_from_str(self, exts_):
        ext_l_ = []
        for ext in exts_:
            ext_type_ = ext[0][0:4]
            ext_type_str_kind = str(int(ext_type_,16))
            if ext_type_str_kind in imp_date_ext_data:
                ext_type_ = imp_date_ext_data[ext_type_str_kind]['name']
            ext_data_ = ''
            if len(ext[0]) > 4:
                ext_data_ = self.parse_extension_data(ext_type_, ext[0][4:])

            ext_l_.append({ext_type_: ext_data_})

        return ext_l_


    def get_implementation_date(self, cs_str_): # @TODO: add extension
        dates_ = set([])
        for i in range(0,len(cs_str_),4):
            cs_ = cs_str_[i:i+4]
            if cs_ in imp_date_cs_data:
                dates_.add(imp_date_cs_data[cs_]['date'])
        dates_ = list(dates_)
        dates_.sort()
        return dates_[-1], dates_[0]


    def extract_fingerprint(self, data):
        # extract handshake version
        fp_ = data[4:6]

        # skip header/client_random
        offset = 38

        # parse/skip session_id
        session_id_length = int(data[offset:offset+1].encode('hex'),16)
        offset += 1 + session_id_length
        if len(data[offset:]) == 0:
            return None

        # parse/extract/skip cipher_suites length
        cipher_suites_length = int(data[offset:offset+2].encode('hex'),16)
        fp_ += data[offset:offset+2]
        offset += 2
        if len(data[offset:]) == 0:
            return None

        # parse/extract/skip cipher_suites
        cs_str_ = ''
        for i in range(0,cipher_suites_length,2):
            fp_ += self.degrease_type_code(data, offset+i)
            cs_str_ += self.degrease_type_code(data, offset+i)
        offset += cipher_suites_length
        if len(data[offset:]) == 0:
            return None

        # parse/skip compression method
        compression_methods_length = int(data[offset:offset+1].encode('hex'),16)
        offset += 1 + compression_methods_length
        if len(data[offset:]) == 0:
            return self.hex_fp_to_structured_representation(fp_.encode('hex'))

        # parse/skip extensions length
        ext_total_len = int(data[offset:offset+2].encode('hex'),16)
        offset += 2
        if len(data[offset:]) != ext_total_len:
            return None

        # parse/extract/skip extension type/length/values
        fp_ext_ = ''
        ext_fp_len_ = 0
        while ext_total_len > 0:
            if len(data[offset:]) == 0:
                return None

            tmp_fp_ext, offset, ext_len = self.parse_extension(data, offset)
            fp_ext_ += tmp_fp_ext
            ext_fp_len_ += len(tmp_fp_ext)

            ext_total_len -= 4 + ext_len

        fp_ += ('%04x' % ext_fp_len_).decode('hex')
        fp_ += fp_ext_

        return self.hex_fp_to_structured_representation(fp_.encode('hex'))


    # helper to parse/extract/skip single extension
    def parse_extension(self, data, offset):
        tmp_ext_type = self.degrease_type_code(data, offset)
        fp_ext_ = tmp_ext_type
        offset += 2
        ext_len = int(data[offset:offset+2].encode('hex'),16)
        tmp_ext_len = ('%04x' % (ext_len)).decode('hex')
        offset += 2
        tmp_ext_value = data[offset:offset+ext_len]
        if tmp_ext_type.encode('hex') in ext_data_extract_:
            tmp_ext_value = self.degrease_ext_data(data, offset, tmp_ext_type, ext_len, tmp_ext_value)
            fp_ext_ += tmp_ext_len
            fp_ext_ += tmp_ext_value
        else:
            fp_ext_ += ('%04x' % 0).decode('hex')
        offset += ext_len

        return fp_ext_, offset, ext_len

    # helper to normalize grease type codes
    def degrease_type_code(self, data, offset):
        if data[offset:offset+2].encode('hex') in grease_:
            return '0a0a'.decode('hex')
        else:
            return data[offset:offset+2]


    # helper to normalize grease within supported_groups and supported_versions
    def degrease_ext_data(self, data, offset, ext_type, ext_length, ext_value):
        if ext_type.encode('hex') == '000a': # supported_groups
            degreased_ext_value = data[offset:offset+2]
            for i in range(2,ext_length,2):
                if data[offset+i:offset+i+2].encode('hex') in grease_:
                    degreased_ext_value += '0a0a'.decode('hex')
                else:
                    degreased_ext_value += data[offset+i:offset+i+2]
            return degreased_ext_value
        elif ext_type.encode('hex') == '002b': # supported_versions
            degreased_ext_value = data[offset:offset+1]
            for i in range(1,ext_length,2):
                if data[offset+i:offset+i+2].encode('hex') in grease_:
                    degreased_ext_value += '0a0a'.decode('hex')
                else:
                    degreased_ext_value += data[offset+i:offset+i+2]
            return degreased_ext_value

        return ext_value


    def parse_extension_data(self, ext_type, ext_data_):
        ext_len = int(ext_data_[0:4],16)
        ext_data = ext_data_[4:]

        if ext_type == 'application_layer_protocol_negotiation':
            ext_data = self.parse_application_layer_protocol_negotiation(ext_data, ext_len)
	elif ext_type == 'signature_algorithms':
            ext_data = self.signature_algorithms(ext_data, ext_len)
        elif ext_type == 'status_request':
            ext_data = self.status_request(ext_data, ext_len)
        elif ext_type == 'ec_point_formats':
            ext_data = self.ec_point_formats(ext_data, ext_len)
        elif ext_type == 'key_share':
            ext_data = self.key_share_client(ext_data, ext_len)
        elif ext_type == 'psk_key_exchange_modes':
            ext_data = self.psk_key_exchange_modes(ext_data, ext_len)
        elif ext_type == 'supported_versions':
            ext_data = self.supported_versions(ext_data, ext_len)
	elif ext_type == 'supported_groups':
            ext_data = self.supported_groups(ext_data, ext_len)

        return ext_data

    def supported_groups(self, data, length):
        if len(data) < 2:
            return ''
        info = OrderedDict({})
        data = data.decode('hex')
        ext_len = int(data[0:2].encode('hex'),16)
        info['supported_groups_list_length'] = ext_len
        info['supported_groups'] = []
        offset = 2
        while offset < length:
            tmp_data = data[offset:offset+2].encode('hex')
            info['supported_groups'].append(TLS_SUPPORTED_GROUPS[int(tmp_data,16)])
            offset += 2

        return info


    def supported_versions(self, data, length):
        if len(data) < 2:
            return ''
        info = OrderedDict({})
        data = data.decode('hex')
        ext_len = int(data[0:1].encode('hex'),16)
        info['supported_versions_list_length'] = ext_len
        info['supported_versions'] = []
	offset = 1
        while offset < length:
            tmp_data = data[offset:offset+2].encode('hex')
            if tmp_data in TLS_VERSION:
                info['supported_versions'].append(TLS_VERSION[tmp_data])
            else:
                info['supported_versions'].append('Unknown Version (%s)' % tmp_data)
                print 'UNKNOWN %s: %s' % ('SUPPORTED_VERSION', tmp_data)
            offset += 2

        return info


    def psk_key_exchange_modes(self, data, length):
        if len(data) < 2:
            return ''
        info = OrderedDict({})
        data = data.decode('hex')
	ext_len = int(data[0:1].encode('hex'),16)
        info['psk_key_exchange_modes_length'] = ext_len
        mode = int(data[1:2].encode('hex'),16)
	info['psk_key_exchange_mode'] = TLS_PSK_KEY_EXCHANGE_MODES[mode]

	return info


    def key_share_client(self, data, length):
        if len(data) < 2:
            return ''
        info = OrderedDict({})
        data = data.decode('hex')
        ext_len = int(data[0:2].encode('hex'),16)
        info['key_share_length'] = ext_len
        info['key_share_entries'] = []
        offset = 2
        while offset < length:
            tmp_obj = OrderedDict({})
            tmp_data = data[offset:offset+2].encode('hex')
            tmp_obj['group'] = TLS_SUPPORTED_GROUPS[int(tmp_data,16)]
            tmp_obj['key_exchange_length'] = int(data[offset+2:offset+4].encode('hex'),16)
            tmp_obj['key_exchange'] = data[offset+4:offset+4+tmp_obj['key_exchange_length']].encode('hex')
            info['key_share_entries'].append(tmp_obj)
            offset += 4 + tmp_obj['key_exchange_length']

        return info


    def ec_point_formats(self, data, length):
        if len(data) < 2:
            return ''
        info = OrderedDict({})
        data = data.decode('hex')
        ext_len = int(data[0:1].encode('hex'),16)
        info['ec_point_formats_length'] = ext_len
        info['ec_point_formats'] = []
        for i in range(ext_len):
            if data[i+1:i+2].encode('hex') in TLS_EC_POINT_FORMATS:
                info['ec_point_formats'].append(TLS_EC_POINT_FORMATS[data[i+1:i+2].encode('hex')])
            else:
                info['ec_point_formats'].append(data[i+1:i+2].encode('hex'))
                print 'UNKNOWN %s: %s' % ('EC_POINT_FORMAT', data[i+1:i+2].encode('hex'))

        return info


    def status_request(self, data, length):
        if len(data) < 2:
            return ''
        info = OrderedDict({})
        data = data.decode('hex')
        info['certificate_status_type'] = TLS_CERTIFICATE_STATUS_TYPE[data[0:1].encode('hex')]
	offset = 1
        info['responder_id_list_length'] = int(data[offset:offset+2].encode('hex'),16)
	offset += info['responder_id_list_length'] + 2
        info['request_extensions_length'] = int(data[offset:offset+2].encode('hex'),16)
        offset += info['request_extensions_length'] + 2

        return info

    def signature_algorithms(self, data, length):
        if len(data) < 2:
            return ''
        info = OrderedDict({})
        data = data.decode('hex')
        ext_len = int(data[0:2].encode('hex'),16)
        info['signature_hash_algorithms_length'] = ext_len
        info['algorithms'] = []
        offset = 2
        while offset < length:
            tmp_data = data[offset:offset+2].encode('hex')
            if tmp_data in TLS_SIGNATURE_HASH_ALGORITHMS:
                info['algorithms'].append(TLS_SIGNATURE_HASH_ALGORITHMS[tmp_data])
            else:
                info['algorithms'].append('unknown(%s)' % tmp_data)
                print 'UNKNOWN %s: %s' % ('SIGNATURE_ALGORITHM', tmp_data)
            offset += 2

        return info


    def parse_application_layer_protocol_negotiation(self, data, length):
	data = data.decode('hex')
	alpn_len = int(data[0:2].encode('hex'),16)
        alpn_offset = 2
        alpn_data = []
        while alpn_offset < length:
            tmp_alpn_len = int(data[alpn_offset:alpn_offset+1].encode('hex'),16)
            alpn_offset += 1
            alpn_data.append(data[alpn_offset:alpn_offset+tmp_alpn_len])
            alpn_offset += tmp_alpn_len

        return alpn_data


    def gen_cs_mapping(self, cs):
        cs_map_ = []
        for cs_ in cs:
            if cs_ in cs_mapping:
                cs_map_.append(cs_mapping[cs_])
            else:
                try:
                    t_ = {}
                    t_['strength'] = 'unknown'
                    t_['color'] = 'black'
                    w_idx = cs_.split('_').index('WITH')
                    tok = cs_.split('_')
                    t_['hash'] = tok[-1]
                    tmp = tok[w_idx+1]
                    for i in range(w_idx+2,len(tok)-1):
                        tmp += '_' + tok[i]
                    t_['enc'] = tmp
                    t_['auth'] = tmp
                    t_['sig'] = tok[2]
                    t_['kex'] = tok[1]
                    cs_map_.append(t_)
                except:
                    cs_map_.append({'enc':'','hash':'','auth':'','strength':'','sig':'','kex':'','color':'black'})
        return cs_map_


    def hex_fp_to_structured_representation(self, s):
        xtn_grease_list = [
            10,        # supported_groups
            11,        # ec_point_formats
            13,        # signature_algorithms
            43         # supported_versions  
        ]
        output = ''

        # parse protocol version 
        output += '(' + s[0:4] + ')'

        # parse ciphersuite offer vector
        cs_len = s[4:8]
        output += '('
        cs_data_len = int(cs_len, 16)*2    
        cs_vec = s[8:8+cs_data_len]
        output += cs_vec + ')'

        if len(s) <= 8+cs_data_len:
            return output

        # parse client extensions
        ext_index = 8+cs_data_len
        ext_len = s[ext_index:ext_index+4]
        output += '('
        ext_data_len = int(ext_len, 16)*2 
        ext_data = s[ext_index+4:ext_index+4+ext_data_len]
        x_index = 0    
        while x_index + 8 <= len(ext_data):
            x_type = ext_data[x_index+0:x_index+4]
            x_len  = ext_data[x_index+4:x_index+8]
            x_index_next = x_index + int(x_len, 16) * 2 + 8
            x_data = ext_data[x_index+8:x_index_next]
            x_index = x_index_next
            output += '('
            output += x_type
            if x_len != '0000':
                output += x_len
                output += x_data
            output += ')'
        output += ')'

        return output


###
## Similarity Matching for Fingerprints
#

# ***** Sequence Alignment *****
class SequenceAlignment:
    def __init__(self, similarity, gap_penalty):
	self.map_ = {}
        self.similarity = similarity
        self.gap = float(gap_penalty)

    # Align two sequences, s1 and s2, using the
    #   Needleman-Wunsch Algorithm and return the
    #   score of the best possible alignment
    def align(self, s1, s2):
        F = np.zeros((len(s1)+1, len(s2)+1))
        for i in range(len(s1)+1):
            F[i,0] = self.gap*i
        for i in range(len(s2)+1):
            F[0,i] = self.gap*i
        for i in range(1,len(s1)+1):
            for j in range(1,len(s2)+1):
		match_ = F[i-1,j-1] + self.similarity(s1[i-1], s2[j-1])
                delete_ = F[i-1,j] + self.gap
		insert_ = F[i,j-1] + self.gap
                F[i,j] = max(match_, delete_, insert_)

        return F[len(s1),len(s2)]

# determine the similarity between two elements
#   in a TLS fingerprint
def f_similarity(a, b):
    # the two elements match
    if a == b:
        return 1.0
    return 0.0


def get_tls_params(fp_):
    cs_ = []
    for i in range(0,len(fp_[1][0]),4):
        cs_.append(fp_[1][0][i:i+4])
    cs_4_ = get_ngram(cs_, 4)

    ext_ = []
    if len(fp_) > 2:
        for t_ext_ in fp_[2]:
            ext_.append('ext_' + t_ext_[0][0:4] + '::' + t_ext_[0][4:])

    return [cs_4_, ext_]

def get_sequence(fp_):
    seq = []
    cs_ = fp_[1][0]
    for i in range(0,len(cs_),4):
        seq.append(cs_[i:i+4])
    ext_ = []
    if len(fp_) > 2:
        for t_ext_ in fp_[2]:
            seq.append('ext_' + t_ext_[0][0:4] + '::' + t_ext_[0][4:])
    return seq


def get_ngram(l, ngram):
    l_ = []
    for i in range(0,len(l)-ngram):
        s_ = ''
        for j in range(ngram):
            s_ += l[i+j]
	l_.append(s_)
    if len(l_) == 0:
        l_ = l
    return l_


