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

from classifier import LogRegClassifier
import numpy as np
import json
import math
import time
import os
import random
import argparse
from pull_data import Pull

def learn_param(data, labels, param_file):
    logreg = LogRegClassifier(standardize=False)
    logreg.train(data, labels)

    print 'non-zero parameters:\t' + str(logreg.get_num_nonzero_params())
    w,b = logreg.get_parameters()
    A = list(b)
    w = list(w[0])
    A.extend(w)
    np.savetxt(param_file,A)

def main():
    parser = argparse.ArgumentParser(description="Generate Model Parameters for LAUI", add_help=True)
    
    parser.add_argument('-p', '--pos_dir', action="store", help="Directory of Positive Examples (JSON Format)")
    parser.add_argument('-n', '--neg_dir', action="store", help="Directory of Negative Examples (JSON Format)")
    parser.add_argument('-m', '--meta', action="store_true", default=False, help="Parse Metadata Information")
    parser.add_argument('-l', '--lengths', action="store_true", default=False, help="Parse Packet Size Information")
    parser.add_argument('-t', '--times', action="store_true", default=False, help="Parse Inter-packet Time Information")
    parser.add_argument('-d', '--dist', action="store_true", default=False, help="Parse Byte Distribution Information")
    parser.add_argument('-o', '--output', action="store", default="params.txt", help="Output file for parameters")

    args = parser.parse_args()

    max_files = [None,None]
    compact = 1
    bd_compact = 0

    types = []
    if args.meta:
        types.append(0)
    if args.lengths:
        types.append(1)
    if args.times:
        types.append(2)
    if args.dist:
        types.append(3)

    if args.pos_dir == None or not os.path.isdir(args.pos_dir):
        print 'No valid positive directory'
        return

    if args.neg_dir == None or not os.path.isdir(args.neg_dir):
        print 'No valid negative directory'
        return

    if types == []:
        print 'Enter some data types to learn on (-m, -l, -t, -d)'
        return

    param_file = args.output
    if not args.pos_dir.endswith('/'):
        args.pos_dir += '/'
    if not args.neg_dir.endswith('/'):
        args.neg_dir += '/'
    d = Pull(args.pos_dir, args.neg_dir, types, compact, max_files, bd_compact)
    data = d.data
    labels = d.labels

    num_positive = 0
    num_negative = 0
    for l in labels:
        if l == 1:
            num_positive += 1
        else:
            num_negative += 1

    print 'Num Positive:\t%i' % (num_positive)
    print 'Num Negative:\t%i' % (num_negative)
    print
    print 'Features Used:'
    num_params = 0
    for t in types:
        if t == 0:
            print '\tMetadata\t\t(7)'
            num_params += 7
        elif t == 1 and compact == 0:
            print '\tPacket Lengths\t\t(3600)'
            num_params += 3600
        elif t == 1 and compact == 1:
            print '\tPacket Lengths\t\t(100)'
            num_params += 100
        elif t == 2 and compact == 0:
            print '\tPacket Times\t\t(900)'
            num_params += 900
        elif t == 2 and compact == 1:
            print '\tPacket Times\t\t(100)'
            num_params += 100
        elif t == 3 and bd_compact == 0:
            print '\tByte Distribution\t(256)'
            num_params += 256
        elif t == 3 and bd_compact == 1:
            print '\tByte Distribution\t(16)'
            num_params += 16
        elif t == 3 and bd_compact == 2:
            print '\tByte Distribution Mean/std\t(9)'
            num_params += 9
        elif t == 4:
            print '\tTLS Information\t\t(198)'
            num_params += 198
    print 'Total Features:\t%i' % (num_params)
    print

    learn_param(data, labels, args.output)


if __name__ == "__main__":
    main()
