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

from data_parser import DataParser
import os

class Pull:
    def __init__(self, pos_dir, neg_dir, types=[0], compact=1, max_files=[None,None]):
        self.num_params = 0
        self.types = types
        self.compact = compact

        for t in self.types:
            if t == 0:
                self.num_params += 7
            elif t == 1 and self.compact == 0:
                self.num_params += 3600
            elif t == 1 and self.compact == 1:
                self.num_params += 100
            elif t == 2 and self.compact == 0:
                self.num_params += 900
            elif t == 2 and self.compact == 1:
                self.num_params += 100
            elif t == 3:
                self.num_params += 256
            elif t == 4:
                self.num_params += 186


        self.data = []
        self.labels = []

        if neg_dir != None:
            self.load_data(neg_dir,0.0, max_files[1])
        if pos_dir != None:
            self.load_data(pos_dir,1.0, max_files[0])

    def load_data(self, idir, label, max_files):
        files = os.listdir(idir)
        num_files = 0
        for f in files:
            try:
                dParse = DataParser(idir + f,self.compact)
            except:
                print 'Error: failued to parse file %s' % (idir + f)
                continue

            num_files += 1

            tmpTLS = dParse.getTLSInfo()
            tmpBD = dParse.getByteDistribution()
            tmpIPT = dParse.getIndividualFlowIPTs()
            tmpPL = dParse.getIndividualFlowPacketLengths()
            tmp = dParse.getIndividualFlowMetadata()

            if tmp != None and tmpPL != None and tmpIPT != None:
                for i in range(len(tmp)):
                    tmp_data = []
                    if 0 in self.types:
                        tmp_data.extend(tmp[i])
                    if 1 in self.types:
                        tmp_data.extend(tmpPL[i])
                    if 2 in self.types:
                        tmp_data.extend(tmpIPT[i])
                    if 3 in self.types:
                        tmp_data.extend(tmpBD[i])
                    if 4 in self.types:
                        tmp_data.extend(tmpTLS[i])

                    if len(tmp_data) != self.num_params:
                        continue

                    self.data.append(tmp_data)
                    self.labels.append(label)

            if max_files != None and num_files >= max_files:
                break
