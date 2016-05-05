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

cs = {u'ec62': 317, u'9074': 319, u'f50f': 323, 'c07a': 263, 'c07b': 264, 'c07c': 265, 'c07d': 266, 'c07e': 267, 'c07f': 268, u'2cae': 324, u'a24c': 330, 'c070': 253, 'c071': 254, 'c072': 255, 'c073': 256, 'c074': 257, 'c075': 258, 'c076': 259, 'c077': 260, 'c078': 261, 'c079': 262, u'6843': 343, 'c031': 190, u'2312': 346, u'f694': 347, u'2ed1': 356, u'6382': 361, u'7632': 365, u'0200': 370, u'2d2a': 375, u'4195': 376, u'4a9c': 403, u'ba76': 380, u'005b': 383, u'cded': 387, u'51a1': 448, 'c084': 273, 'c086': 275, u'6570': 377, u'62ec': 422, u'1f5c': 423, '002d': 43, '002e': 44, '002b': 41, '002c': 42, '002a': 40, '002f': 45, u'c383': 441, 'c029': 182, 'c028': 181, 'c027': 180, 'c026': 179, 'c025': 178, 'c024': 177, 'c023': 176, 'c022': 175, 'c021': 174, 'c020': 173, u'0650': 329, '009f': 103, '009e': 102, '009d': 101, '009c': 100, '009b': 99, '009a': 98, 'c09b': 296, 'c09c': 297, 'c09a': 295, 'c09f': 300, 'c09d': 298, 'c09e': 299, u'b16c': 402, '0022': 32, '0023': 33, '0020': 30, '0021': 31, '0026': 36, '0027': 37, '0024': 34, '0025': 35, 'c02f': 188, 'c02e': 187, 'c02d': 186, 'c02c': 185, 'c02b': 184, 'c02a': 183, u'ff00': 350, u'ff01': 461, u'ff02': 462, u'ff03': 463, u'c2f4': 464, 'c092': 287, 'c093': 288, 'c090': 285, 'c091': 286, 'c096': 291, 'c097': 292, 'c094': 289, 'c095': 290, u'f370': 470, 'c098': 293, 'c099': 294, '0099': 97, '0098': 96, '0097': 95, '0096': 94, '0095': 93, '0094': 92, '0093': 91, '0092': 90, '0091': 89, '0090': 88, u'53de': 318, u'7f62': 322, u'5e4d': 446, u'0065': 409, u'd0f0': 326, 'c03d': 202, u'ebe0': 369, 'c03e': 203, 'c03f': 204, u'fefe': 337, u'3934': 338, u'feff': 339, 'c044': 209, 'c03b': 200, 'c046': 211, u'6812': 439, 'c063': 240, 'c062': 239, 'c061': 238, 'c060': 237, 'c067': 244, 'c066': 243, 'c065': 242, 'c064': 241, 'c069': 246, 'c068': 245, '00af': 119, '00ae': 118, '00ad': 117, '00ac': 116, '00ab': 115, '00aa': 114, u'24cb': 366, u'db5e': 372, '0028': 38, '0029': 39, u'7c3b': 374, u'd5b2': 378, 'c06c': 249, 'c06b': 248, 'c06a': 247, 'c06f': 252, 'c06e': 251, 'c06d': 250, u'1c48': 385, '00a7': 111, '00a6': 110, '00a5': 109, '00a4': 108, '00a3': 107, '00a2': 106, '00a1': 105, '00a0': 104, u'cc13': 392, u'1ef3': 393, u'cc15': 394, u'cc14': 395, '00a9': 113, '00a8': 112, u'a04c': 396, u'2592': 397, u'b23c': 398, u'da33': 399, u'5acc': 405, u'ff52': 406, u'0066': 407, '0067': 69, u'0064': 408, u'31cf': 353, u'0062': 410, u'0063': 411, u'0060': 412, u'0061': 413, '0068': 70, '0069': 71, u'9404': 418, u'd717': 420, u'8476': 424, '006d': 75, '006b': 73, '006c': 74, '006a': 72, u'3abf': 427, u'2757': 430, u'c876': 415, u'f815': 433, u'f143': 434, 'c01b': 168, 'c01c': 169, 'c01a': 167, 'c01f': 172, 'c01d': 170, 'c01e': 171, u'a4d1': 442, u'bad6': 416, u'deb4': 363, u'7b7c': 454, u'fca9': 459, 'c018': 165, 'c019': 166, u'74ba': 465, 'c012': 159, 'c013': 160, 'c010': 157, 'c011': 158, 'c016': 163, 'c017': 164, 'c014': 161, 'c015': 162, '0039': 55, '0038': 54, '0035': 51, '0034': 50, '0037': 53, '0036': 52, '0031': 47, '0030': 46, '0033': 49, '0032': 48, 'c034': 193, 'c036': 195, u'6e8b': 325, 'c04b': 216, 'c089': 278, 'c088': 277, u'1540': 328, 'c085': 274, 'c030': 189, 'c087': 276, u'1d40': 321, 'c081': 270, 'c080': 269, 'c083': 272, 'c082': 271, u'76df': 331, u'182d': 333, 'c033': 192, u'd887': 334, u'6bf0': 336, u'bd06': 340, u'a647': 341, '003e': 60, '003d': 59, '003f': 61, '003a': 56, '003c': 58, '003b': 57, 'c08e': 283, 'c08d': 282, 'c08f': 284, 'c08a': 279, 'c08c': 281, 'c08b': 280, u'682d': 359, 'c05f': 236, u'6700': 362, 'c05d': 234, 'c05e': 235, 'c05b': 232, 'c05c': 233, 'c05a': 231, u'a9c3': 367, 'c058': 229, 'c059': 230, 'c056': 227, 'c057': 228, 'c054': 225, 'c055': 226, 'c052': 223, 'c053': 224, 'c050': 221, 'c051': 222, u'6179': 381, u'978c': 386, u'45ae': 388, u'0596': 389, u'9960': 391, '000d': 13, '000e': 14, '000f': 15, u'63a1': 435, '000a': 10, '000b': 11, '000c': 12, u'6f71': 436, '00b2': 122, '00b3': 123, '00b0': 120, '00b1': 121, '00b6': 126, '00b7': 127, '00b4': 124, '00b5': 125, '00b8': 128, '00b9': 129, '0004': 4, '0005': 5, '0006': 6, '0007': 7, '0000': 0, '0001': 1, '0002': 2, '0003': 3, '0008': 8, '0009': 9, u'4444': 421, u'8077': 440, '00bb': 131, '00bc': 132, '00ba': 130, '00bf': 135, '00bd': 133, '00be': 134, u'2892': 429, u'b068': 425, u'eedb': 437, u'5297': 438, u'f40b': 355, u'8eec': 444, u'38c5': 447, u'13c3': 352, u'8c29': 455, u'74a7': 456, u'aaa1': 453, u'02a6': 469, 'c005': 146, 'c004': 145, 'c007': 148, 'c006': 147, 'c001': 142, u'c000': 320, 'c003': 144, 'c002': 143, 'c009': 150, 'c008': 149, u'3d5f': 327, u'f19c': 332, u'0300': 432, u'612f': 335, '0040': 62, '0041': 63, '0042': 64, '0043': 65, '0044': 66, '0045': 67, '0046': 68, 'c00e': 155, 'c00d': 154, 'c00f': 156, 'c00a': 151, 'c00c': 153, 'c00b': 152, u'adb9': 342, u'd296': 344, u'c48c': 345, u'7eb0': 400, u'00ff': 348, u'00fd': 349, u'00fb': 472, u'00fc': 351, u'4b3e': 354, u'193d': 357, u'7a24': 358, u'5600': 360, 'c0ab': 312, 'c0ac': 313, 'c0aa': 311, 'c0af': 316, 'c0ad': 314, 'c0ae': 315, u'be1d': 458, u'5b21': 371, 'c0a8': 309, 'c0a9': 310, u'ab4d': 364, 'c0a2': 303, 'c0a3': 304, 'c0a0': 301, 'c0a1': 302, 'c0a6': 307, 'c0a7': 308, 'c0a4': 305, 'c0a5': 306, u'8358': 379, u'b6ec': 382, u'a180': 384, u'217c': 417, u'a7f9': 390, 'c049': 214, 'c048': 213, 'c041': 206, 'c040': 205, 'c043': 208, 'c042': 207, 'c045': 210, 'c03a': 199, 'c047': 212, 'c03c': 201, u'c13a': 401, u'e3a1': 404, u'5788': 414, u'8776': 419, 'c038': 197, 'c039': 198, 'c04a': 215, 'c035': 194, 'c04c': 217, 'c037': 196, 'c04e': 219, 'c04d': 218, 'c032': 191, 'c04f': 220, u'f6aa': 426, u'1180': 428, u'a209': 431, '00c5': 141, '00c4': 140, '00c1': 137, '00c0': 136, '00c3': 139, '00c2': 138, '0017': 23, '0016': 22, '0015': 21, '0014': 20, '0013': 19, '0012': 18, '0011': 17, '0010': 16, '0019': 25, '0018': 24, u'86b1': 443, u'200c': 457, u'5f74': 445, '0088': 80, '0089': 81, '0084': 76, '0085': 77, '0086': 78, '0087': 79, u'0080': 449, u'0081': 450, u'0082': 451, u'0083': 452, u'5281': 368, u'f2dc': 373, u'e60e': 460, '001f': 29, '001e': 28, '001b': 27, '001a': 26, u'20fa': 466, u'1ad6': 467, u'0fe4': 468, '008d': 85, '008e': 86, '008f': 87, '008a': 82, '008b': 83, '008c': 84, u'f7d8': 471}

bd_merges = [[0, 65, 69, 48, 109, 77, 47, 112, 52, 117, 57], [10, 99, 13], [130, 7, 9, 139, 20, 25, 28, 31, 42, 54, 55, 187, 64, 68, 73, 74, 80, 209, 210, 213, 86, 215, 228, 229, 102, 238, 246, 252, 253, 126], [32, 97, 45], [67, 114, 111, 49, 50, 116], [100, 84], [101], [194, 162, 104, 105, 75, 44, 98, 108, 115, 53, 118, 56, 184, 61], [201, 203, 233], [193, 226, 171, 197, 198, 231, 234, 235, 174, 175, 208, 146, 147, 181, 217, 199, 159], [131, 137, 150, 151, 221, 185, 186, 190, 63, 206, 211, 85, 89, 93, 95, 224, 227, 236, 237, 240, 113, 242, 244, 245], [2, 3, 8, 21, 34, 168, 41, 43, 46, 178, 51, 182, 58, 71, 72, 76, 202, 204, 78, 207, 248, 82, 83, 214, 79, 103, 106, 110, 239, 40, 119, 120, 121, 122], [128, 1, 225, 132, 133, 6, 129, 136, 138, 11, 140, 141, 15, 144, 152, 18, 19, 148, 22, 23, 24, 4, 154, 155, 156, 26, 30, 5, 160, 33, 27, 164, 165, 166, 39, 169, 135, 172, 173, 29, 176, 177, 91, 180, 59, 188, 189, 134, 35, 192, 66, 70, 161, 12, 143, 92, 81, 163, 87, 88, 36, 90, 219, 220, 94, 96, 16, 38, 107, 157, 243, 62, 249, 250, 124, 125, 127], [142, 17, 149, 153, 158, 37, 167, 170, 179, 183, 60, 191, 195, 196, 200, 205, 212, 14, 216, 218, 222, 223, 123, 230, 145, 232, 241, 247, 251], [254], [255]]


def getTLSVersionVector(cs_list, ext):
    tls_info = np.zeros(len(cs.keys())+36)

    for c in cs_list:
        tls_info[cs[c]] = 1

    for c in ext:
        if int(c['type'],16) < 36:
            tls_info[int(c['type'],16)+len(cs.keys())] = 1

    return tls_info



bd_comp = {}
for i in range(len(bd_merges)):
    for x in bd_merges[i]:
        bd_comp[x] = i

class DataParser:
    def __init__(self, json_file, compact=1):
        self.compact = compact
        self.skipped = 0
        self.legacy_format = False
        self.flows = []
        self.advancedInfo = {}
        self.all_flows = {}

        with gzip.open(json_file,'r') as fp:
            try: # for incomplete gzip files
                for line in fp:
#                    if line.strip == '{' or 'metadata' in line:
#                    if 'metadata' in line:
#                        self.legacy_format = True
#                        break

                    try:
                        tmp = json.loads(line)
                        if 'version' not in tmp:
                            self.flows.append(tmp)
                    except:
                        continue
            except:
                return


        if self.legacy_format:
            data = ""
            with open(json_file,'r') as fp:
                for line in fp:
                    if "\"hd\"" in line:
                        continue
                    data += line.strip().replace('"x": i','"x": "i"').replace('"x": a','"x": "a"')
            try:
                self.flows = json.loads(data)
            except:
                if not data.endswith("] }"):
                    data += "] }"
                self.flows = json.loads(data)


    def getTLSInfo(self):
        if self.legacy_format == False:
            if self.flows == []:
                return None

            data = []
            for flow in self.flows:
                if len(flow['packets']) == 0:
                    continue
                tls_info = np.zeros(len(cs.keys())+36+1)

                if 'tls' in flow and 'cs' in flow['tls']:
                    for c in flow['tls']['cs']:
                        tls_info[cs[c]] = 1

                # need to look more into this
                if 'tls' in flow and 'tls_ext' in flow['tls']:
                    for c in flow['tls']['tls_ext']:
                        if int(c['type'],16) < 36:
                            tls_info[int(c['type'],16)+len(cs.keys())] = 1
                if 'tls' in flow and 'tls_client_key_length' in flow['tls']:
                    tls_info[len(cs.keys())+36] = flow['tls']['tls_client_key_length']

                data.append(list(tls_info))

            return data


        if self.flows['appflows'] == []:
            return None

        data = []
        for flow in self.flows['appflows']:
            if len(flow['flow']['non_norm_stats']) == 0:
                continue
            tls_info = np.zeros(len(cs.keys())+36+1)

            if 'tls' in flow['flow'] and 'cs' in flow['flow']['tls']:
                for c in flow['flow']['tls']['cs']:
                    tls_info[cs[c]] = 1

            # need to look more into this
            if 'tls' in flow['flow'] and 'tls_ext' in flow['flow']['tls']:
                for c in flow['flow']['tls']['tls_ext']:
                    if int(c['type'],16) < 36:
                        tls_info[int(c['type'],16)+len(cs.keys())] = 1
            if 'tls' in flow['flow'] and 'tls_client_key_length' in flow['flow']['tls']:
                tls_info[len(cs.keys())+36] = flow['flow']['tls']['tls_client_key_length']

            data.append(list(tls_info))

        return data
        

    def getByteDistribution(self):
        if self.legacy_format == False:
            if self.flows == []:
                return None

            data = []
            for flow in self.flows:
                if len(flow['packets']) == 0:
                    continue
                if 'bd' in flow and sum(flow['bd']) > 0:
                    tmp = map(lambda x: x/float(sum(flow['bd'])),flow['bd'])
                    data.append(tmp)
                else:
                    data.append(np.zeros(256))

            return data


        if self.flows['appflows'] == []:
            return None

        data = []
        for flow in self.flows['appflows']:
            if len(flow['flow']['non_norm_stats']) == 0:
                continue
            if 'bd' in flow['flow'] and sum(flow['flow']['bd']) > 0:
                tmp = map(lambda x: x/float(sum(flow['flow']['bd'])),flow['flow']['bd'])
                data.append(tmp)
            else:
                data.append(np.zeros(256))

        return data

    def getByteDistribution_compact(self):
        if self.legacy_format == False:
            if self.flows == []:
                return None

            data = []


            return data


        if self.flows['appflows'] == []:
            return None

        data = []
        for flow in self.flows['appflows']:
            if len(flow['flow']['non_norm_stats']) == 0:
                continue
            if 'bd' in flow['flow'] and sum(flow['flow']['bd']) > 0:
                tmp = np.zeros(16)
                for i in range(len(flow['flow']['bd'])):
                    tmp[bd_comp[i]] += flow['flow']['bd'][i]
                tmp = map(lambda x: x/float(sum(tmp)),list(tmp))
                data.append(tmp)
            else:
                data.append(np.zeros(16))

        return data

    def getByteDistribution_mean_std(self):
        if self.legacy_format == False:
            if self.flows == []:
                return None

            data = []


            return data


        if self.flows['appflows'] == []:
            return None

        data = []
        for flow in self.flows['appflows']:
            if len(flow['flow']['non_norm_stats']) == 0:
                continue
            if 'bd_mean' in flow['flow'] and 'bd_std' in flow['flow']:
                tmp = np.zeros(9)
                x = flow['flow']['bd_mean']
                y = flow['flow']['bd_std']
                tmp[0] = x
                tmp[1] = y
                tmp[2] = x*y
                tmp[3] = x**2
                tmp[4] = y**2
                tmp[5] = x*y**2
                tmp[6] = y*x**2
                tmp[7] = x**3
                tmp[8] = y**3
                data.append(tmp)
            else:
                if 'bd' in flow['flow'] and sum(flow['flow']['bd']) > 0:
                    tmp = np.zeros(9)
                    bd_ = np.array(flow['flow']['bd'])
                    bd = []
                    for i in range(256):
                        for j in range(bd_[i]):
                            bd.append(i)
                    x = np.mean(bd)
                    y = np.std(bd)
                    tmp[0] = x
                    tmp[1] = y
                    tmp[2] = x*y
                    tmp[3] = x**2
                    tmp[4] = y**2
                    tmp[5] = x*y**2
                    tmp[6] = y*x**2
                    tmp[7] = x**3
                    tmp[8] = y**3
                    data.append(tmp)
                else:
                    data.append(np.zeros(9))

        return data

    def getIndividualFlowPacketLengths(self):
        if self.legacy_format == False:
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


        if self.flows['appflows'] == []:
            return None

        data = []
        if self.compact:
            numRows = 10
            binSize = 150.0
        else:
            numRows = 60
            binSize = 25.0
        for flow in self.flows['appflows']:
            transMat = np.zeros((numRows,numRows))
            if len(flow['flow']['non_norm_stats']) == 0:
                continue
            elif len(flow['flow']['non_norm_stats']) == 1:
                curPacketSize = min(int(flow['flow']['non_norm_stats'][0]['b']/binSize),numRows-1)
                transMat[curPacketSize,curPacketSize] = 1
                data.append(list(transMat.flatten()))
                continue

            # get raw transition counts
            for i in range(1,len(flow['flow']['non_norm_stats'])):
                prevPacketSize = min(int(flow['flow']['non_norm_stats'][i-1]['b']/binSize),numRows-1)
                if 'b' not in flow['flow']['non_norm_stats'][i]:
                    break
                curPacketSize = min(int(flow['flow']['non_norm_stats'][i]['b']/binSize),numRows-1)
                transMat[prevPacketSize,curPacketSize] += 1

            # get empirical transition probabilities
            for i in range(numRows):
                if float(np.sum(transMat[i:i+1])) != 0:
                    transMat[i:i+1] = transMat[i:i+1]/float(np.sum(transMat[i:i+1]))

            data.append(list(transMat.flatten()))

        return data

    def getIndividualFlowIPTs(self):
        if self.legacy_format == False:
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


        if self.flows['appflows'] == []:
            return None

        data = []
        if self.compact:
            numRows = 10
            binSize = 50.0
        else:
            numRows = 30
            binSize = 50.0
        for flow in self.flows['appflows']:
            transMat = np.zeros((numRows,numRows))
            if len(flow['flow']['non_norm_stats']) == 0:
                continue
            elif len(flow['flow']['non_norm_stats']) == 1:
                curIPT = min(int(flow['flow']['non_norm_stats'][0]['ipt']/float(binSize)),numRows-1)
                transMat[curIPT,curIPT] = 1
                data.append(list(transMat.flatten()))
                continue

            # get raw transition counts
            for i in range(1,len(flow['flow']['non_norm_stats'])):
                prevIPT = min(int(flow['flow']['non_norm_stats'][i-1]['ipt']/float(binSize)),numRows-1)
                curIPT = min(int(flow['flow']['non_norm_stats'][i]['ipt']/float(binSize)),numRows-1)
                transMat[prevIPT,curIPT] += 1

            # get empirical transition probabilities
            for i in range(numRows):
                if float(np.sum(transMat[i:i+1])) != 0:
                    transMat[i:i+1] = transMat[i:i+1]/float(np.sum(transMat[i:i+1]))

            data.append(list(transMat.flatten()))

        return data

    def getIndividualFlowMetadata(self):
        if self.legacy_format == False:
            if self.flows == []:
                return None, None

            data = []
            metadata = []
            for flow in self.flows:
                if len(flow['packets']) == 0:
                    continue
                tmp = []
                tmp_m = []
                tmp_b = 0
                if 'ib' in flow:
                    tmp_b += flow['ib']
                if 'ob' in flow:
                    tmp_b += flow['ob']
            

                key = flow['sa'].replace('.','')+flow['da'].replace('.','')+str(int(flow['sp']))+str(int(flow['dp']))+str(tmp_b)
                key = str(key)
                bd = None
                if 'bd' in flow:
                    bd = flow['bd']
                self.advancedInfo[key] = (flow['sa'],flow['da'],flow['sp'],flow['dp'],flow['packets'],bd)
                self.all_flows[key] = flow
                tmp_m.append(flow['sa']) # source port
                tmp_m.append(flow['da']) # destination port
                tmp_m.append(flow['sp']) # source port
                tmp_m.append(flow['dp']) # destination port
                tmp.append(float(flow['dp'])) # destination port
                tmp.append(float(flow['sp'])) # source port
                if 'ip' in flow:
                    tmp.append(flow['ip']) # inbound packets
                    tmp_m.append(flow['ip'])
                else:
                    tmp.append(0)
                    tmp_m.append(0)
                if 'op' in flow:
                    tmp.append(flow['op']) # outbound packets
                    tmp_m.append(flow['op'])
                else:
                    tmp.append(0)
                    tmp_m.append(0)
                if 'ib' in flow:
                    tmp.append(flow['ib']) # inbound bytes
                    tmp_m.append(flow['ib'])
                else:
                    tmp.append(0)
                    tmp_m.append(0)
                if 'ob' in flow:
                    tmp.append(flow['ob']) # outbound bytes
                    tmp_m.append(flow['ob'])
                else:
                    tmp_m.append(0)
                    tmp.append(0)
                # elapsed time of flow
                if flow['packets'] == []:
                    tmp.append(0)
                else:
                    time = 0
                    for packet in flow['packets']:
                        time += packet['ipt']
                    tmp.append(time)
                if 'pr' in flow:
                    tmp_m.append(flow['pr'])
                else:
                    tmp_m.append(0)

                # add tls specific items
                if 'tls' in flow and 'scs' in flow['tls']:
                    tmp_m.append(flow['tls']['scs'])
                else:
                    tmp_m.append(-1)
                if 'tls' in flow and 'tls_client_key_length' in flow['tls']:
                    tmp_m.append(flow['tls']['tls_client_key_length'])
                else:
                    tmp_m.append(-1)
                if 'tls' in flow and 'tls_ov' in flow['tls'] and 'tls_iv' in flow['tls']:
                    tmp_v = max(flow['tls']['tls_iv'],flow['tls']['tls_ov'])
                elif 'tls' in flow and 'tls_ov' in flow['tls']:
                    tmp_v = flow['tls']['tls_ov']
                elif 'tls' in flow and 'tls_iv' in flow['tls']:
                    tmp_v = flow['tls']['tls_iv']
                else:
                    tmp_v = -1
                if tmp_v == 5:
                    tmp_m.append('TLS 1.2')
                elif tmp_v == 4:
                    tmp_m.append('TLS 1.1')
                elif tmp_v == 3:
                    tmp_m.append('TLS 1.0')
                elif tmp_v == 2:
                    tmp_m.append('SSL 3.0')
                elif tmp_v == 1:
                    tmp_m.append('SSL 2.0')
                else:
                    tmp_m.append(-1)                
                tmp_m.append(tmp_v) # for convenience

                data.append(tmp)
                metadata.append(tmp_m)

            if data == []:
                return None,None
            return data, metadata

        if 'appflows' not in self.flows:
            return None, None
        if self.flows['appflows'] == None:
            return None, None
        if self.flows['appflows'] == []:
            return None, None

        data = []
        metadata = []
        for flow in self.flows['appflows']:
            if len(flow['flow']['non_norm_stats']) == 0:
                continue
            tmp = []
            tmp_m = []
            tmp_b = 0
            if 'ib' in flow['flow']:
                tmp_b += flow['flow']['ib']
            if 'ob' in flow['flow']:
                tmp_b += flow['flow']['ob']
            

            key = flow['flow']['sa'].replace('.','')+flow['flow']['da'].replace('.','')+str(int(flow['flow']['sp']))+str(int(flow['flow']['dp']))+str(tmp_b)
            key = str(key)
            bd = None
            if 'bd' in flow['flow']:
                bd = flow['flow']['bd']
            self.advancedInfo[key] = (flow['flow']['sa'],flow['flow']['da'],flow['flow']['sp'],flow['flow']['dp'],flow['flow']['non_norm_stats'],bd)
            tmp_m.append(flow['flow']['sa']) # source port
            tmp_m.append(flow['flow']['da']) # destination port
            tmp_m.append(flow['flow']['sp']) # source port
            tmp_m.append(flow['flow']['dp']) # destination port
            tmp.append(float(flow['flow']['dp'])) # destination port
            tmp.append(float(flow['flow']['sp'])) # source port
            if 'ip' in flow['flow']:
                tmp.append(flow['flow']['ip']) # inbound packets
                tmp_m.append(flow['flow']['ip'])
            else:
                tmp.append(0)
                tmp_m.append(0)
            if 'op' in flow['flow']:
                tmp.append(flow['flow']['op']) # outbound packets
                tmp_m.append(flow['flow']['op'])
            else:
                tmp.append(0)
                tmp_m.append(0)
            if 'ib' in flow['flow']:
                tmp.append(flow['flow']['ib']) # inbound bytes
                tmp_m.append(flow['flow']['ib'])
            else:
                tmp.append(0)
                tmp_m.append(0)
            if 'ob' in flow['flow']:
                tmp.append(flow['flow']['ob']) # outbound bytes
                tmp_m.append(flow['flow']['ob'])
            else:
                tmp_m.append(0)
                tmp.append(0)
            # elapsed time of flow
            if flow['flow']['non_norm_stats'] == []:
                tmp.append(0)
            else:
                time = 0
                for packet in flow['flow']['non_norm_stats']:
                    time += packet['ipt']
                tmp.append(time)
            if 'pr' in flow['flow']:
                tmp_m.append(flow['flow']['pr'])
            else:
                tmp_m.append(0)

            # add tls specific items
            if 'tls' in flow['flow'] and 'scs' in flow['flow']['tls']:
                tmp_m.append(flow['flow']['tls']['scs'])
            else:
                tmp_m.append(-1)
            if 'tls' in flow['flow'] and 'tls_client_key_length' in flow['flow']['tls']:
                tmp_m.append(flow['flow']['tls']['tls_client_key_length'])
            else:
                tmp_m.append(-1)
            if 'tls' in flow['flow'] and 'tls_ov' in flow['flow']['tls'] and 'tls_iv' in flow['flow']['tls']:
                tmp_v = max(flow['flow']['tls']['tls_iv'],flow['flow']['tls']['tls_ov'])
            elif 'tls' in flow['flow'] and 'tls_ov' in flow['flow']['tls']:
                tmp_v = flow['flow']['tls']['tls_ov']
            elif 'tls' in flow['flow'] and 'tls_iv' in flow['flow']['tls']:
                tmp_v = flow['flow']['tls']['tls_iv']
            else:
                tmp_v = -1
            if tmp_v == 5:
                tmp_m.append('TLS 1.2')
            elif tmp_v == 4:
                tmp_m.append('TLS 1.1')
            elif tmp_v == 3:
                tmp_m.append('TLS 1.0')
            elif tmp_v == 2:
                tmp_m.append('SSL 3.0')
            elif tmp_v == 1:
                tmp_m.append('SSL 2.0')
            else:
                tmp_m.append(-1)                
            tmp_m.append(tmp_v) # for convenience

            data.append(tmp)
            metadata.append(tmp_m)

        if data == []:
            return None,None
        return data, metadata


