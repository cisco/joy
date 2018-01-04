"""
 *
 * Copyright (c) 2018 Cisco Systems, Inc.
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
import subprocess
import collections
import copy
import gzip
import bz2
from .sleuth import DictStreamIteratorFromFile
from .sleuth import DictStreamIterator
from .sleuth import SleuthFileType


class FlowIteratorFromFile(DictStreamIteratorFromFile):
    """
    Create a new DictIterator instance from the given input file.
    This allows iteration over all JSON objects within the file.
    """

    def __init__(self, file_name):
        self.pcap_loader = PcapLoader(file=file_name)
        super(FlowIteratorFromFile, self).__init__(file_name=file_name,
                                                   skip_lines=['version'])

    def _cleanup(self):
        """
        Overrides parent.
        Close any resources that are still open.
        :return:
        """
        try:
            self.f.close()
        except IOError:
            pass

        self.pcap_loader.cleanup()

    def _load_file(self):
        """
        Overrides parent.
        If the file given is a PCAP, it will first be run through Joy
        in order to generate the necessary JSON output for use here.
        :return:
        """
        if self.file_name is sys.stdin:
            self.f = self.file_name
        else:
            if self.pcap_loader.is_pcap():
                # Run Joy to generate some JSON for use in this script.
                self.pcap_loader.run()
                # Open the json file that was just made.
                ft = SleuthFileType(self.pcap_loader.temp_json['file'])
                if ft.is_gz():
                    self.f = gzip.open(self.pcap_loader.temp_json['file'], 'r')
                elif ft.is_bz2():
                    self.f = bz2.BZ2File(self.pcap_loader.temp_json['file'], 'r')
                else:
                    self.f = open(self.pcap_loader.temp_json['file'], 'r')
            else:
                ft = SleuthFileType(self.file_name)
                if ft.is_gz():
                    self.f = gzip.open(self.file_name, 'r')
                elif ft.is_bz2():
                    self.f = bz2.BZ2File(self.file_name, 'r')
                else:
                    self.f = open(self.file_name, 'r')


class FlowStitchIterator(DictStreamIterator):
    def __init__(self, source):
        self.source = source
        self.active_flows = collections.OrderedDict()

        for f in source:
            key = (f['sa'], f['da'], f['sp'], f['dp'], f['pr'])
            revkey = (f['da'], f['sa'], f['dp'], f['sp'], f['pr'])
            if key in self.active_flows:
                self.active_flows[key] = self.merge(self.active_flows[key], f)
            elif revkey in self.active_flows:
                self.active_flows[revkey] = self.merge_reverse(self.active_flows[revkey], f)
            else:
                self.active_flows[key] = f

        self.flows = iter(self.active_flows.values())

    def next(self):
        return self.flows.next()

    # merge f2 into f1, where both flows are in the same direction, and
    # f1 precedes f2 (f1.ts < f2.ts)
    #
    def merge(self, f1, f2):
        for k, v in f2.items():
            if k not in f1:
                f1[k] = f2[k]
            else:
                if k == 'time_end':
                    f1[k] = max(f1[k], f2[k])
                elif k == 'num_pkts_in' or k == 'bytes_in':
                    f1[k] += f2[k]
                elif k == 'num_pkts_out' or k == 'bytes_out':
                    f1[k] += f2[k]
                elif k == 'byte_dist':
                    for i, e in enumerate(f2[k]):
                        f1[k][i] += e
                else:
                    pass
            return f1

    # merge f2 into f1, where f2 is in the reverse direction to f1, and
    # f1 precedes f2 (f1.ts < f2.ts)
    #
    def merge_reverse(self, f1, f2):
        for k, v in f2.items():
            if k not in f1:
                if k == 'num_pkts_out':
                    f1['num_pkt_in'] += f2[k]
                elif k == 'bytes_out':
                    f1['bytes_in'] += f2[k]
                else:
                    f1[k] = f2[k]
            else:
                if k == 'time_end':
                    f1[k] = max(f1[k], f2[k])
                elif k == 'num_pkts_in':
                    f1[k] += f2['bytes_out']
                elif k == 'num_pkts_out':
                    f1[k] += f2['bytes_in']
                elif k == 'byte_dist':
                    for i, e in enumerate(f2[k]):
                        f1[k][i] += e
                else:
                    pass
            return f1


class PcapLoader:
    """
    Helper to operate on PCAP files directly
    """

    def __init__(self, file):
        self.file = file
        self.temp_json = {'file': None, 'created': False}

    def cleanup(self):
        """
        Delete the temporary JSON file that was created.
        :return:
        """
        if self.temp_json['created'] is True:
            try:
                os.remove(self.temp_json['file'])
            except OSError:
                pass

    def is_pcap(self):
        """
        Determine whether a file is pcap.
        :return: True if pcap file, False otherwise
        """
        if self.file.endswith('.pcap'):
            return True
        else:
            # Look inside the file and check for pcap magic number
            if sys.byteorder == 'little':
                magic_number = bytearray.fromhex('d4 c3 b2 a1')
            else:
                magic_number = bytearray.fromhex('a1 b2 c3 d4')

            with open(self.file, 'rb') as f:
                ba = bytearray(f.readline())

                if ba[:4] == magic_number:
                    return True
                else:
                    return False

    def run(self):
        """
        Run Joy with the pcap file as input.
        The json output will then be operated upon in this program (sleuth).
        A temporary json file (temp-sleuth.json.gz) will be written to the user's "home" directory.
        Use the function cleanup() within this class to delete the file before program exit.
        :return:
        """
        cur_dir = os.path.dirname(__file__)
        temp_json_dir = os.path.expanduser('~')
        temp_json_filename = 'temp-sleuth.json.gz'
        self.temp_json['file'] = os.path.join(temp_json_dir, temp_json_filename)

        enabled_features = ['bidir=1', 'http=1', 'tls=1', 'dns=1',
                            'ssh=1', 'ppi=1', 'entropy=1']

        # Construct the commands
        command = ['joy', 'outdir=' + temp_json_dir, 'output=' + temp_json_filename]
        command += enabled_features
        command.append(os.path.join(cur_dir, self.file))

        command_local = copy.deepcopy(command)
        command_local[0] = './joy'

        command_source = copy.deepcopy(command)
        command_source[0] = './bin/joy'

        try:
            subprocess.call(command)
        except OSError as e:
            if e.errno == os.errno.ENOENT:
                # Look within the same directory where sleuth lives.
                try:
                    subprocess.call(command_local)
                except OSError as ee:
                    if ee.errno == os.errno.ENOENT:
                        # Look in typical source location
                        try:
                            subprocess.call(command_source)
                        except OSError as eee:
                            if eee.errno == os.errno.ENOENT:
                                print('\033[91m' + 'error: could not locate "joy" executable. exiting.' + '\033[0m')
                                sys.exit(1)
                    else:
                        raise
            else:
                raise

        # Set flag indicating the temporary JSON file was made.
        self.temp_json['created'] = True