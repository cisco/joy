import os
import re
import ast
import json
import gzip
import time
import math
import struct
from collections import OrderedDict
from sys import path
path.append('/home/blake/Cisco/tmp_open_source/')


grease_ = set(['0a0a','1a1a','2a2a','3a3a','4a4a','5a5a','6a6a','7a7a',
               '8a8a','9a9a','aaaa','baba','caca','dada','eaea','fafa'])

ext_data_extract_ = set(['0005','000a','000b','000d','0010','002b','002d'])

cs_mapping_file = 'resources/cs_mapping.json.gz'
with gzip.open(cs_mapping_file,'r') as fp:
    cs_mapping = json.loads(fp.read())

imp_date_cs_file = 'resources/implementation_date_cs.json.gz'
with gzip.open(imp_date_cs_file,'r') as fp:
    imp_date_cs_data = json.loads(fp.read())

imp_date_ext_file = 'resources/implementation_date_ext.json.gz'
with gzip.open(imp_date_ext_file,'r') as fp:
    imp_date_ext_data = json.loads(fp.read())


class TLSFingerprint:
    def __init__(self, fp_database):
        # populate fingerprint database
        self.fp_db = {}
        if fp_database != None:
            with gzip.open(fp_database, 'r') as file_pointer:
                for line in file_pointer:
                    fp_ = json.loads(line)
                    fp_['tls_features']['cs_mapping'] = self.gen_cs_mapping(fp_['tls_features']['cipher_suites'])
                    self.fp_db[fp_['str_repr']] = fp_

        # TLS ClientHello pattern/RE
        self.pattern = '\x16\x03[\x01-\x03].{2}\x01.{3}\x03[\x01-\x03]'
        self.matcher = re.compile(self.pattern)


    def fingerprint(self, data):
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
            fp_ = self.gen_unknown_fingerprint(fp_str_)
            self.fp_db[fp_str_] = fp_
        return fp_


    def gen_unknown_fingerprint(self, fp_str_, ui=True):
        fp_ = OrderedDict({})
        fp_['str_repr'] = fp_str_
        lit_fp = self.eval_fp_str(fp_str_)
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


    def get_ext_from_str(self, exts_): # @TODO parse ext data
        ext_l_ = []
        for ext in exts_:
            ext_type_ = ext[0][0:4]
            ext_type_str_kind = str(int(ext_type_,16))
            if ext_type_str_kind in imp_date_ext_data:
                ext_l_.append({imp_date_ext_data[ext_type_str_kind]['name']: ''})
            else:
                ext_l_.append({ext_type_: ''})
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
            return None

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


