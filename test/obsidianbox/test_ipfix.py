#!/usr/bin/env python
"""
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
"""

import os
import sys
import subprocess
import time
import logging
import json
import gzip
from .utils import end_process


class ValidateExporter(object):
    """
    Class suite to validate the data produced by Joy's Ipfix exporter and consumption
    by the collector. The exporter and collector each use their own system process.
    """
    def __init__(self, paths, compare_keys=['sa','da','sp','dp','pr']):
        self.paths = paths
        self.compare_keys = compare_keys
        self.ipfix_flows = list()
        self.sniff_flows = list()
        self.corrupt_flows = list()
        self.tmp_outputs = {'sniff': 'tmp-ipfix-sniff.json.gz',
                            'export': 'tmp-ipfix-export.json.gz',
                            'collect': 'tmp-ipfix-collect.json.gz',
                            }

    def _cleanup_tmp_files(self):
        """
        Delete any existing temporary files.
        :return:
        """
        for key, f in self.tmp_outputs.iteritems():
            if os.path.isfile(f):
                os.remove(f)

    def _intraop_export_to_collect(self):
        """
        Perform intraoperation test between the Joy Ipfix exporter and collector.
        The flow data gathered by the collector is recorded in the self.exported_flows list.
        :return: 0 for success
        """
        # Start the ipfix collector
        proc_collect = subprocess.Popen([self.paths['exec'],
                                         'output=' + self.tmp_outputs['collect'],
                                         'ipfix_collect_online=1',
                                         'ipfix_collect_port=4739'])
        time.sleep(0.5)

        # Start the ipfix exporter
        proc_export = subprocess.Popen([self.paths['exec'],
                                        'output=' + self.tmp_outputs['export'],
                                        'ipfix_export_port=2000',
                                        self.paths['pcap']])
        proc_export.wait()
        time.sleep(0.5)

        """
        Cleanup
        """
        # End the ipfix exporting
        rc_export = end_process(proc_export)
        # End the ipfix collecting
        rc_collect = end_process(proc_collect)

        if rc_export != 0 or rc_collect != 0:
            self._cleanup_tmp_files()
            logger.error("Subprocess Joy IPFIX failure")
            raise RuntimeError("Subprocess Joy IPFIX failure")

        with gzip.open(self.tmp_outputs['collect'], 'r') as f:
            for line in f:
                try:
                    flow = json.loads(line)
                    self.ipfix_flows.append(flow)
                except:
                    continue

    def _sniff_pcap(self):
        """
        Perform a direct sniff on a sample pcap file using Joy.
        The flow data gathered by the sniffer is recorded in the self.sniff_flows list.
        :return:
        """
        # Start the ipfix collector
        proc_collect = subprocess.Popen([self.paths['exec'],
                                         'output=' + self.tmp_outputs['sniff'],
                                         self.paths['pcap']])
        time.sleep(0.5)

        # End the ipfix collecting process
        rc = end_process(proc_collect)
        if rc != 0:
            self._cleanup_tmp_files()
            logger.error("Subprocess Joy sniffer failure")
            raise RuntimeError("Subprocess Joy sniffer failure")

        with gzip.open(self.tmp_outputs['sniff'], 'r') as f:
            for line in f:
                try:
                    flow = json.loads(line)
                    self.sniff_flows.append(flow)
                except:
                    continue

    def validate_export_against_sniff(self):
        """
        Gather the IPFIX and sniffer outputs and then compare to see if
        any considerable deltas occur. If no match is found for an IPFIX flow,
        then log the flow's JSON and fail.
        :return:
        """
        # Exporter -> collector
        self._intraop_export_to_collect()

        # Pcap -> collector
        self._sniff_pcap()

        # Compare the two results
        for ipfix_flow in self.ipfix_flows:
            corrupt = True
            if not 'sa' in ipfix_flow:
                # Optimize prelim check to see if a flow object
                continue
            elif ipfix_flow['dp'] == 4739:
                # Ignore the exporter -> collector initial packet
                continue

            for sniff_flow in self.sniff_flows:
                if not 'sa' in sniff_flow:
                    # Optimize prelim check to see if a flow object
                    continue

                match = True
                for key in self.compare_keys:
                    try:
                        if not ipfix_flow[key] == sniff_flow[key]:
                            # One of the key/value pairs did not match
                            match = False
                            break
                    except KeyError:
                        # This json object is not a flow, skip
                        break

                if match is True:
                    # All of the key/value pairs matched
                    corrupt = False
                    break

            if corrupt is True:
                self.corrupt_flows.append(ipfix_flow)

        if self.corrupt_flows:
            # Log the corrupt flows
            for flow in self.corrupt_flows:
                logger.warning('Corrupt flow --> ' + str(flow))

            self._cleanup_tmp_files()
            logger.error("Failure, corruption detected")
            raise AssertionError

        # Delete temporary files
        self._cleanup_tmp_files()


def test_unix_os():
    """
    Prepare the module for testing within a UNIX-like enviroment,
    and then run the appropriate test functions.
    :return:
    """
    cur_dir = os.path.dirname(__file__)

    paths = dict()
    paths['exec'] = os.path.join(cur_dir, '../../bin/joy')
    paths['pcap'] = os.path.join(cur_dir, '../../sample.pcap')

    validate_exporter = ValidateExporter(paths=paths)
    validate_exporter.validate_export_against_sniff()


def main_ipfix():
    """
    Main IPFIX testing entry point.
    :return:
    """
    global logger
    logger = logging.getLogger(__name__)

    os_platform = sys.platform
    unix_platforms = ['linux', 'linux2', 'darwin']

    if os_platform in unix_platforms:
        test_unix_os()

    logger.warning('SUCCESS')
