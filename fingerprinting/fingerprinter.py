#!/usr/bin/python

"""
fingerprinter correlates TLS client_hello's in a packet capture with TLS fingerprints
  contained within a fingerprint database; see fingerprinter.py --help for more details.

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
import sys
import dpkt
import pcap
import json
import time
import socket
import optparse
import datetime
from collections import OrderedDict

from tls_fingerprint import TLSFingerprint

class Fingerprinter:

    def __init__(self, database, port=None, output=None):
        self.database = database
        self.port = port
        self.tls = TLSFingerprint(database)

        if output == None:
            self.out_file_pointer = None
        elif output == sys.stdout:
            self.out_file_pointer = sys.stdout
        else:
            self.out_file_pointer = open(output, 'w')


    def get_client_info(self, client_ip, data):
        unique_fps = []
        seen_str = set([])
        proc_weight = {}
        procs_ = []
        total_weight = 0.0
        for flow_repr in data:
            ip_ = flow_repr['source_addr']
            fp_ = flow_repr['fingerprint']
            if ip_ == client_ip and fp_['str_repr'] not in seen_str:
                for p_ in fp_['process_info']:
                    if p_['sha256'] not in proc_weight:
                        proc_weight[p_['sha256']] = [0.0,p_['process'],p_['application_category'], p_['sha256']]
                    if p_['prevalence'] == 'Unknown':
                        proc_weight[p_['sha256']][0] += 0.1
                        total_weight += 0.1
                    else:
                        proc_weight[p_['sha256']][0] += float(p_['prevalence'])
                        total_weight += float(p_['prevalence'])
                seen_str.add(fp_['str_repr'])

        for k in proc_weight:
            proc_weight[k][0] /= total_weight
            procs_.append(proc_weight[k])
        procs_.sort()
        procs_.reverse()

        return procs_


    def extract_fingerprints(self, input_files, detailed=False):
        for input_file in input_files:
            if os.path.isfile(input_file):
                f = open(input_file,'rb')
                packets = dpkt.pcap.Reader(f)
                capture_type = 'offline'
            else:
                packets = pcap.pcap(input_file, timeout_ms=1000)
                capture_type = 'online'

            data_ = []
            while True:
                if capture_type == 'offline':
                    pkts = []
                    while True:
                        try:
                            pkts.append(packets.__next__())
                        except Exception as e:
                            break
                else:
                    pkts = packets.readpkts()

                for ts, buf in pkts:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                    except:
                        break # no data error?
                    ip = eth.data

                    if (type(ip) != dpkt.ip.IP and type(ip) != dpkt.ip6.IP6) or type(ip.data) != dpkt.tcp.TCP:
                        continue

                    tcp = ip.data
                    data = tcp.data

                    if self.port != None:
                        if not tcp.dport == int(self.port):
                            continue

                    if type(ip) == dpkt.ip.IP:
                        add_fam = socket.AF_INET
                    else:
                        add_fam = socket.AF_INET6
                    flow_key = (socket.inet_ntop(add_fam,ip.src), tcp.sport, socket.inet_ntop(add_fam,ip.dst), tcp.dport)


                    # TODO: TCP retransmissions
                    fp_ = self.tls.fingerprint(data, detailed)

                    if fp_ != None:
                        flow_repr = OrderedDict({})
                        flow_repr['source_addr'] = socket.inet_ntop(add_fam,ip.src)
                        flow_repr['dest_addr'] = socket.inet_ntop(add_fam,ip.dst)
                        flow_repr['source_port'] = tcp.sport
                        flow_repr['dest_port'] = tcp.dport
                        flow_repr['protocol'] = 'TCP'
                        flow_repr['timestamp'] = str(datetime.datetime.utcfromtimestamp(ts))
                        flow_repr['fingerprint'] = fp_
                        data_.append(flow_repr)

                    if fp_ != None and self.out_file_pointer != None:
                        self.write_record(flow_repr)

                if capture_type == 'offline':
                    break

        if self.out_file_pointer != None and self.out_file_pointer != sys.stdout:
            self.out_file_pointer.close()

        return data_

    def write_record(self, flow_repr):
        self.out_file_pointer.write('%s\n' % json.dumps(flow_repr))
        self.out_file_pointer.flush()



def main():
    parser = optparse.OptionParser()

    parser.add_option('-i','--input',action='store',dest='input',help='pcap file or interface name',default=None)
    parser.add_option('-f','--fp_db',action='store',dest='fp_db',help='location of fingerprint database (e.g., resources/fingerprint_db.json.gz)',default='resources/fingerprint_db.json.gz')
    parser.add_option('-p','--port',action='store',dest='port',help='filter on port <x>',default=None)
    parser.add_option('-o','--output',action='store',dest='output',help='name for output file',default=sys.stdout)

    options, args = parser.parse_args()

    input_files = []
    if options.input != None:
        input_files.append(options.input)
    for x in args:
        if x.endswith('.pcap'):
            input_files.append(x)

    if len(input_files) == 0:
        print 'error: need a pcap/interface'
        return 1

    fingerprinter = Fingerprinter(options.fp_db, options.port, options.output)
    fingerprinter.extract_fingerprints(input_files)


if __name__ == '__main__':
    sys.exit(main())
