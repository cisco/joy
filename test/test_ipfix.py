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
import argparse
import json
import gzip


def end_process(process):
    """
    Takes care of the end-of-life stage of a process.
    If the process is still running, end it.
    The process EOL return code is collected and passed back.
    :param process: A python subprocess object, i.e. subprocess.Popen()
    :return: 0 for process success
    """
    if process.poll() is None:
        # Gracefully terminate the process
        process.terminate()
        time.sleep(1)
        if process.poll() is None:
            # Hard kill the process
            process.kill()
            time.sleep(1)
            if process.poll() is None:
                # Runaway zombie process
                logger.error('subprocess ' + str(process) + 'turned zombie')
                return 1
    elif process.poll() != 0:
        # Export process ended with bad exit code
        return process.poll()

    return 0


class ValidateExporter(object):
    """
    Class suite to validate the data produced by Joy's Ipfix exporter and consumption
    by the collector. The exporter and collector each use their own system process.
    """
    def __init__(self, cli_paths, compare_keys=['sa','da','sp','dp','pr']):
        self.cli_paths = cli_paths
        self.compare_keys = compare_keys
        self.exported_flows = list()
        self.sniffed_flows = list()
        self.corrupt_flows = list()
        self.export_output = 'tmp-ipfix-export.json.gz'
        self.collect_output = 'tmp-ipfix-collect.json.gz'

    def __cleanup_tmp_files(self):
        """
        Delete any existing temporary files.
        :return:
        """
        # Delete temporary files
        if os.path.isfile(self.collect_output):
            os.remove(self.collect_output)
        if os.path.isfile(self.export_output):
            os.remove(self.export_output)

    def __intraop_export_to_collect(self):
        """
        Perform intraoperation test between the Joy Ipfix exporter and collector.
        The flow data gathered by the collector is recorded in the self.exported_flows list.
        :return: 0 for success
        """
        exec_path = self.cli_paths['exec_path']
        pcap_path = self.cli_paths['pcap_path']
        rc_overall = 0

        # Start the ipfix collector
        proc_collect = subprocess.Popen([exec_path,
                                         'output=' + self.collect_output,
                                         'ipfix_collect_online=1',
                                         'ipfix_collect_port=4739'])
        time.sleep(0.5)

        # Start the ipfix exporter
        proc_export = subprocess.Popen([exec_path,
                                        'output=' + self.export_output,
                                        'ipfix_export_port=2000',
                                        pcap_path])
        proc_export.wait()
        time.sleep(0.5)

        """
        Cleanup
        """
        # End the ipfix exporting
        rc_proc = end_process(proc_export)
        if rc_proc != 0:
            rc_overall = rc_proc

        # End the ipfix collecting
        rc_proc = end_process(proc_collect)
        if rc_proc != 0:
            rc_overall = rc_proc

        with gzip.open(self.collect_output, 'r') as f:
            for line in f:
                try:
                    flow = json.loads(line)
                    self.exported_flows.append(flow)
                except:
                    continue

        return rc_overall

    def __sniff_pcap(self):
        """
        Perform a direct sniff on a sample pcap file using the Joy Ipfix collector.
        The flow data gathered by the collector is recorded in the self.sniffed_flows list.
        :return: 0 for success
        """
        exec_path = self.cli_paths['exec_path']
        pcap_path = self.cli_paths['pcap_path']
        rc_overall = 0

        # Start the ipfix collector
        proc_collect = subprocess.Popen([exec_path,
                                         'output=' + self.collect_output,
                                         'ipfix_collect_port=4739',
                                         pcap_path])
        time.sleep(0.5)

        """
        Cleanup
        """
        # End the ipfix collecting process
        rc_proc = end_process(proc_collect)
        if rc_proc != 0:
            rc_overall = rc_proc

        with gzip.open(self.collect_output, 'r') as f:
            for line in f:
                try:
                    flow = json.loads(line)
                    self.sniffed_flows.append(flow)
                except:
                    continue

        return rc_overall

    def validate_export_against_sniff(self):
        """
        Use a set
        :return: 0 for success
        """
        # Exporter -> collector
        rc_overall = self.__intraop_export_to_collect()
        if rc_overall != 0:
            logger.warning(str(self.__intraop_export_to_collect) + 'failed')
            return rc_overall

        # Pcap -> collector
        rc_overall = self.__sniff_pcap()
        if rc_overall != 0:
            logger.warning(str(self.__sniff_pcap) + 'failed')
            return rc_overall

        # Compare the two results
        for flow in self.exported_flows:
            corrupt = True
            if not 'sa' in flow:
                # Optimize prelim check to see if a flow object
                continue
            elif flow['dp'] == 4739:
                # Ignore the exporter -> collector initial packet
                continue

            for sniff_flow in self.sniffed_flows:
                if not 'sa' in sniff_flow:
                    # Optimize prelim check to see if a flow object
                    continue

                match = True
                for key in self.compare_keys:
                    try:
                        if not flow[key] == sniff_flow[key]:
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
                self.corrupt_flows.append(flow)
                rc_overall = 1

        if self.corrupt_flows:
            # Info log the corrupt flows
            for flow in self.corrupt_flows:
                logger.info('CORRUPT FLOW: ' + str(flow))

        # Delete temporary files
        self.__cleanup_tmp_files()

        return rc_overall


def test_unix_os():
    """
    Prepare the module for testing within a UNIX-like enviroment,
    and then run the appropriate test functions.
    :return: 0 for success
    """
    rc_unix_overall = 0
    cur_dir = os.path.dirname(__file__)

    cli_paths = dict()
    cli_paths['exec_path'] = os.path.join(cur_dir, '../bin/pcap2flow')
    cli_paths['pcap_path'] = os.path.join(cur_dir, '../sample.pcap')

    validate_exporter = ValidateExporter(cli_paths=cli_paths)

    rc_unix_test = validate_exporter.validate_export_against_sniff()
    if rc_unix_test != 0:
        rc_unix_overall = rc_unix_test
        logger.warning(str(validate_exporter.validate_export_against_sniff) +
                       ' failed with return code ' + str(rc_unix_test))

    return rc_unix_overall


def main():
    """
    Main function to run any test within module.
    :return: 0 for success
    """
    global logger
    logger = logging.getLogger(__name__)

    os_platform = sys.platform
    unix_platforms = ['linux', 'linux2', 'darwin']

    if os_platform in unix_platforms:
        status = test_unix_os()
        if status is not 0:
            logger.warning('FAILED')
            return status

    logger.warning('SUCCESS')
    return 0


if __name__ == "__main__":
    """
    test_ipfix.py executing through shell
    """
    parser = argparse.ArgumentParser(
        description='Joy IPFix program execution tests'
    )
    parser.add_argument('-l', '--log',
                        dest='log_level',
                        choices=['debug', 'info', 'warning', 'error', 'critical'],
                        help='Set the logging level')
    args = parser.parse_args()

    # Configure root logging
    if args.log_level:
        logging.basicConfig(level=args.log_level.upper())
    else:
        logging.basicConfig()

    rc_main = main()
    exit(rc_main)
