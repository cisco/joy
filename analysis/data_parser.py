'''
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
'''

import numpy as np
import math
import json
import gzip

# 176
cs = {u'c005': 0, u'c004': 1, u'c007': 2, u'0039': 3, u'0038': 4, u'c003': 5, u'c002': 6, u'0035': 7, u'0034': 8, u'0037': 9, u'0036': 10, u'c009': 11, u'c008': 12, u'0033': 13, u'0032': 14, u'c07a': 15, u'c07b': 16, u'c07c': 17, u'c07d': 18, u'0065': 19, u'c087': 21, u'c086': 22, u'c081': 23, u'c080': 24, u'c072': 25, u'c073': 26, u'c076': 27, u'c077': 28, u'0040': 29, u'0041': 30, u'0042': 31, u'feff': 32, u'0044': 33, u'0045': 34, u'0046': 35, u'0030': 36, u'c00e': 37, u'c00d': 38, u'c00f': 39, u'c00a': 40, u'c00c': 41, u'003e': 42, u'003d': 43, u'003f': 44, u'003a': 45, u'003c': 46, u'003b': 47, u'006a': 109, u'00ff': 49, u'00fd': 50, u'00fb': 51, u'00fc': 52, u'c08a': 53, u'c08b': 54, u'5600': 55, u'c05d': 56, u'c05c': 57, u'00af': 58, u'00ae': 59, u'0017': 113, u'00a7': 60, u'00a6': 61, u'00a5': 62, u'00a4': 63, u'00a3': 64, u'00a2': 65, u'00a1': 66, u'00a0': 67, u'cc13': 68, u'cc15': 69, u'cc14': 70, u'c049': 71, u'c048': 20, u'0016': 114, u'000d': 74, u'000f': 75, u'000a': 76, u'000c': 77, u'0064': 81, u'0066': 79, u'0067': 80, u'00b0': 78, u'00b1': 82, u'0062': 83, u'0063': 84, u'0060': 85, u'0061': 86, u'0068': 87, u'0069': 88, u'0004': 89, u'0005': 90, u'0006': 91, u'0007': 92, u'0001': 93, u'0002': 94, u'0003': 95, u'0008': 96, u'0009': 97, u'0031': 98, u'0019': 125, u'0018': 126, u'c030': 101, u'c031': 102, u'c032': 103, u'006d': 104, u'00ba': 105, u'006b': 106, u'006c': 107, u'00bd': 108, u'00be': 48, u'00c4': 110, u'00c0': 111, u'00c3': 112, u'cca9': 72, u'cca8': 73, u'0015': 115, u'0014': 116, u'0013': 117, u'0012': 118, u'0011': 119, u'0010': 120, u'c01b': 121, u'c01c': 122, u'c01a': 123, u'c01f': 124, u'c01d': 99, u'c01e': 100, u'002c': 127, u'002f': 128, u'c029': 129, u'c028': 130, u'c027': 131, u'c026': 132, u'c025': 133, u'c024': 134, u'c023': 135, u'c022': 136, u'c021': 137, u'c020': 138, u'009f': 139, u'009e': 140, u'009d': 141, u'009c': 142, u'009b': 143, u'009a': 144, u'0088': 145, u'0089': 146, u'0084': 147, u'0085': 148, u'0086': 149, u'0087': 150, u'0043': 151, u'c02f': 152, u'c02e': 153, u'c02d': 154, u'c02c': 155, u'c02b': 156, u'c02a': 157, u'c018': 158, u'c019': 159, u'001b': 160, u'001a': 161, u'c012': 162, u'c013': 163, u'c011': 164, u'c016': 165, u'c017': 166, u'c014': 167, u'008d': 168, u'008a': 169, u'008b': 170, u'008c': 171, u'0099': 172, u'0098': 173, u'0097': 174, u'0096': 175}

# 21
ext = {u'server_name': 0, u'extended_master_secret': 1, u'renegotiation_info': 2, u'supported_groups': 3, u'ec_point_formats': 4, u'session_ticket': 5, u'application_layer_protocol_negotiation': 6, u'status_request': 7, u'signature_algorithms': 8}


class DataParser:
    def __init__(self, json_file, compact=1):
        self.flows = []
        self.compact = compact

        with gzip.open(json_file,'r') as fp:
            try: 
                for line in fp:
                    try:
                        tmp = json.loads(line)
                        if 'version' not in tmp:
                            self.flows.append(tmp)
                    except:
                        continue
            except:
                return


    def getTLSInfo(self):
        if self.flows == []:
            return None

        data = []
        for flow in self.flows:
            if len(flow['packets']) == 0:
                continue
            tls_info = np.zeros(len(cs.keys())+len(ext.keys())+1)

            if 'tls' in flow and 'cs' in flow['tls']:
                for c in flow['tls']['cs']:
                    if c in cs:
                        tls_info[cs[c]] = 1
            else:
                data.append([])
                continue

            if 'tls' in flow and 'c_extensions' in flow['tls']:
                for c in flow['tls']['c_extensions']:
                    if c.keys()[0] in ext:
                        tls_info[len(cs.keys())+ext[c.keys()[0]]] = 1

            if 'tls' in flow and 'c_key_length' in flow['tls']:
                tls_info[len(cs.keys())+len(ext.keys())] = flow['tls']['c_key_length']

            data.append(list(tls_info))

        return data
        

    def getByteDistribution(self):
        if self.flows == []:
            return None

        data = []
        for flow in self.flows:
            if len(flow['packets']) == 0:
                continue
            if 'byte_dist' in flow and sum(flow['byte_dist']) > 0:
                tmp = map(lambda x: x/float(sum(flow['byte_dist'])),flow['byte_dist'])
                data.append(tmp)
            else:
                data.append(np.zeros(256))

        return data


    def getIndividualFlowPacketLengths(self):
        if self.flows == []:
            return None

        data = []
        if self.compact:
            numRows = 10
            binSize = 150.0
        else:
            numRows = 60
            binSize = 25.0
        for flow in self.flows:
            transMat = np.zeros((numRows,numRows))
            if len(flow['packets']) == 0:
                continue
            elif len(flow['packets']) == 1:
                curPacketSize = min(int(flow['packets'][0]['b']/binSize),numRows-1)
                transMat[curPacketSize,curPacketSize] = 1
                data.append(list(transMat.flatten()))
                continue

            # get raw transition counts
            for i in range(1,len(flow['packets'])):
                prevPacketSize = min(int(flow['packets'][i-1]['b']/binSize),numRows-1)
                if 'b' not in flow['packets'][i]:
                    break
                curPacketSize = min(int(flow['packets'][i]['b']/binSize),numRows-1)
                transMat[prevPacketSize,curPacketSize] += 1

            # get empirical transition probabilities
            for i in range(numRows):
                if float(np.sum(transMat[i:i+1])) != 0:
                    transMat[i:i+1] = transMat[i:i+1]/float(np.sum(transMat[i:i+1]))

            data.append(list(transMat.flatten()))

        return data


    def getIndividualFlowIPTs(self):
        if self.flows == []:
            return None

        data = []
        if self.compact:
            numRows = 10
            binSize = 50.0
        else:
            numRows = 30
            binSize = 50.0
        for flow in self.flows:
            transMat = np.zeros((numRows,numRows))
            if len(flow['packets']) == 0:
                continue
            elif len(flow['packets']) == 1:
                curIPT = min(int(flow['packets'][0]['ipt']/float(binSize)),numRows-1)
                transMat[curIPT,curIPT] = 1
                data.append(list(transMat.flatten()))
                continue

            # get raw transition counts
            for i in range(1,len(flow['packets'])):
                prevIPT = min(int(flow['packets'][i-1]['ipt']/float(binSize)),numRows-1)
                curIPT = min(int(flow['packets'][i]['ipt']/float(binSize)),numRows-1)
                transMat[prevIPT,curIPT] += 1
                
            # get empirical transition probabilities
            for i in range(numRows):
                if float(np.sum(transMat[i:i+1])) != 0:
                    transMat[i:i+1] = transMat[i:i+1]/float(np.sum(transMat[i:i+1]))

            data.append(list(transMat.flatten()))

        return data


    def getIndividualFlowMetadata(self):
        if self.flows == []:
            return None

        data = []
        for flow in self.flows:
            if len(flow['packets']) == 0:
                continue
            tmp = []

            key = flow['sa'].replace('.','')+flow['da'].replace('.','')+str(flow['sp'])+str(flow['dp'])+str(flow['pr'])

            if flow['dp'] != None:
                tmp.append(float(flow['dp'])) # destination port
            else:
                tmp.append(0) # ICMP/etc.
            if flow['sp'] != None:
                tmp.append(float(flow['sp'])) # source port
            else:
                tmp.append(0) # ICMP/etc.
            if 'num_pkts_in' in flow:
                tmp.append(flow['num_pkts_in']) # inbound packets
            else:
                tmp.append(0)
            if 'num_pkts_out' in flow:
                tmp.append(flow['num_pkts_out']) # outbound packets
            else:
                tmp.append(0)
            if 'bytes_in' in flow:
                tmp.append(flow['bytes_in']) # inbound bytes
            else:
                tmp.append(0)
            if 'bytes_out' in flow:
                tmp.append(flow['bytes_out']) # outbound bytes
            else:
                tmp.append(0)
            # elapsed time of flow
            if flow['packets'] == []:
                tmp.append(0)
            else:
                time = 0
                for packet in flow['packets']:
                    time += packet['ipt']
                tmp.append(time)

            data.append(tmp)

        if data == []:
            return None
        return data
