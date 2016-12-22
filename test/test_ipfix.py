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


def end_process(process):
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
                logging.error('subprocess ' + str(process) + 'turned zombie')
                return 1
    elif process.poll() != 0:
        # Export process ended with bad exit code
        return process.poll()

    return 0


def intraop_export_to_collect(exec_path, pcap_path):
    collect_output = 'tmp-ipfix-collect.gz'
    export_output = 'tmp-ipfix-export.gz'
    rc_overall = 0

    # Start the ipfix collector
    proc_collect = subprocess.Popen([exec_path,
                                     'output=' + collect_output,
                                     'ipfix_collect_online=1',
                                     'ipfix_collect_port=4739'])
    time.sleep(1)

    # Start the ipfix exporter
    proc_export = subprocess.Popen([exec_path,
                                    'output=' + export_output,
                                    'ipfix_export_port=2000',
                                    pcap_path])
    proc_export.wait()
    time.sleep(1)

    """
    Cleanup
    """
    # End the ipfix exporting
    rc_test = end_process(proc_export)
    if rc_test != 0:
        rc_overall = rc_test

    # End the ipfix collecting
    rc_test = end_process(proc_collect)
    if rc_test != 0:
        rc_overall = rc_test

    # Delete temporary files
    if os.path.isfile(collect_output):
        os.remove(collect_output)
    if os.path.isfile(export_output):
        os.remove(export_output)

    return rc_overall


def test_unix_os():
    rc_unix_overall = 0
    cur_dir = os.path.dirname(__file__)
    exec_path = os.path.join(cur_dir, '../bin/pcap2flow')
    pcap_path = os.path.join(cur_dir, '../sample.pcap')

    rc_unix_test = intraop_export_to_collect(exec_path=exec_path,
                                             pcap_path=pcap_path)
    if rc_unix_test != 0:
        rc_unix_overall = rc_unix_test
        logging.warning(str(intraop_export_to_collect) +
                        ' failed with return code ' + str(rc_unix_test))

    return rc_unix_overall


def main(child_log=False):
    # There is a parent logger, get a local module logger
    if child_log is True:
        logging.getLogger(__name__)

    os_platform = sys.platform
    unix_platforms = ['linux', 'linux2', 'darwin']

    if os_platform in unix_platforms:
        status = test_unix_os()
        if status is not 0:
            logging.warning('FAILED')
            return status

    logging.warning('SUCCESS')
    return 0


if __name__ == "__main__":
    # This argparse will only work when file is being run through command
    parser = argparse.ArgumentParser(
        description='Joy IPFix program execution tests'
    )
    parser.add_argument('-l', '--log',
                        dest='log_level',
                        choices=['debug', 'info', 'warning', 'error', 'critical'],
                        help='Set the logging level')
    args = parser.parse_args()
    if args.log_level:
        logging.basicConfig(level=args.log_level.upper())

    rc_main = main()
    exit(rc_main)
