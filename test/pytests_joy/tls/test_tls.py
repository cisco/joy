"""
 *
 * Copyright (c) 2017 Cisco Systems, Inc.
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
import logging
import subprocess
import time
import uuid
from pytests_joy.utilities import end_process
from pytests_joy.utilities import ensure_path_exists


# Default globals
baseline_path = 'baseline'
pcap_path = 'pcaps'
flag_generate_base = False
flag_base_file_uuid = True


def generate_baseline(cli_paths):
    rc_overall = 0

    ensure_path_exists(cli_paths['baseline_path'])

    # Get the paths to the tls pcap files
    path_tls10_pcap = os.path.join(pcap_path, 'tls10.pcap')
    path_tls11_pcap = os.path.join(pcap_path, 'tls11.pcap')
    path_tls12_pcap = os.path.join(pcap_path, 'tls12.pcap')
    path_tls13_pcap = os.path.join(pcap_path, 'tls13.pcap')

    # Make the names for the baseline files
    if flag_base_file_uuid:
        base_file_tls10 = str(uuid.uuid4()) + '_base-tls-10.gz'
        base_file_tls11 = str(uuid.uuid4()) + '_base-tls-11.gz'
        base_file_tls12 = str(uuid.uuid4()) + '_base-tls-12.gz'
        base_file_tls13 = str(uuid.uuid4()) + '_base-tls-13.gz'
    else:
        base_file_tls10 = 'base-tls-10.gz'
        base_file_tls11 = 'base-tls-11.gz'
        base_file_tls12 = 'base-tls-12.gz'
        base_file_tls13 = 'base-tls-13.gz'

    # Append the files to the baseline destination dir
    path_tls10_base = os.path.join(cli_paths['baseline_path'],
                                   base_file_tls10)
    path_tls11_base = os.path.join(cli_paths['baseline_path'],
                                   base_file_tls11)
    path_tls12_base = os.path.join(cli_paths['baseline_path'],
                                   base_file_tls12)
    path_tls13_base = os.path.join(cli_paths['baseline_path'],
                                   base_file_tls13)

    # Group variables in dict-list to keep track of related files
    base_and_pcap = [{'base': path_tls10_base, 'pcap': path_tls10_pcap},
                     {'base': path_tls11_base, 'pcap': path_tls11_pcap},
                     {'base': path_tls12_base, 'pcap': path_tls12_pcap},
                     {'base': path_tls13_base, 'pcap': path_tls13_pcap}]

    # Generate the baselines
    processes = list()
    logger.warning("Generating TLS baselines...\n")
    for files in base_and_pcap:
        processes.append(subprocess.Popen([cli_paths['exec_path'],
                                           'output=' + files['base'],
                                           'tls=1',
                                           files['pcap']]))
    time.sleep(1)

    # End running subprocesses
    for proc in processes:
        rc_proc = end_process(proc)
        if rc_proc != 0:
            rc_overall = rc_proc

    return rc_overall


def compare():
    pass


def test_unix_os():
    """
    Prepare the module for testing within a UNIX-like enviroment,
    and then run the appropriate test functions.
    :return: 0 for success
    """
    rc_unix_overall = 0
    cur_dir = os.path.dirname(__file__)

    cli_paths = dict()
    cli_paths['exec_path'] = os.path.join(cur_dir, '../../../bin/joy')
    cli_paths['pcap_path'] = os.path.join(cur_dir, pcap_path)
    cli_paths['baseline_path'] = os.path.join(cur_dir, baseline_path)

    if flag_generate_base is True:
        generate_baseline(cli_paths)
    else:
        compare()

    return rc_unix_overall


def main_tls(baseline_dir=None,
             pcap_dir=None,
             create_base=False):
    """
    Main function to run any test within module.
    :return: 0 for success
    """
    global logger
    logger = logging.getLogger(__name__)

    if baseline_dir:
        global baseline_path
        baseline_path = baseline_dir
    if pcap_dir:
        global pcap_path
        pcap_path = pcap_dir
    if create_base:
        global flag_generate_base
        flag_generate_base = True

    os_platform = sys.platform
    unix_platforms = ['linux', 'linux2', 'darwin']

    if os_platform in unix_platforms:
        status = test_unix_os()
        if status is not 0:
            logger.warning('FAILED')
            return status

    logger.warning('SUCCESS')
    return 0
