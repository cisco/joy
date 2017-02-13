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
import gzip
import json
import uuid
import glob
from pytests_joy.utilities import end_process
from pytests_joy.utilities import ensure_path_exists


# Default globals
baseline_path = 'baseline'
pcap_path = 'pcaps'
flag_generate_base = False
flag_base_generic = False


def generate_baseline(cli_paths):
    rc_overall = 0

    ensure_path_exists(cli_paths['baseline_path'])

    # Get the paths to the tls pcap files
    path_tls10_pcap = os.path.join(pcap_path, 'tls10.pcap')
    path_tls11_pcap = os.path.join(pcap_path, 'tls11.pcap')
    path_tls12_pcap = os.path.join(pcap_path, 'tls12.pcap')
    path_tls13_pcap = os.path.join(pcap_path, 'tls13.pcap')

    # Make the names for the baseline files
    if not flag_base_generic:
        base_file_tls10 = str(uuid.uuid4()) + '_base-tls10.json.gz'
        base_file_tls11 = str(uuid.uuid4()) + '_base-tls11.json.gz'
        base_file_tls12 = str(uuid.uuid4()) + '_base-tls12.json.gz'
        base_file_tls13 = str(uuid.uuid4()) + '_base-tls13.json.gz'
    else:
        base_file_tls10 = 'base-tls10.json.gz'
        base_file_tls11 = 'base-tls11.json.gz'
        base_file_tls12 = 'base-tls12.json.gz'
        base_file_tls13 = 'base-tls13.json.gz'

    # Group variables in dict-list to keep track of related files
    base_and_pcap = [{'base': base_file_tls10, 'pcap': path_tls10_pcap},
                     {'base': base_file_tls11, 'pcap': path_tls11_pcap},
                     {'base': base_file_tls12, 'pcap': path_tls12_pcap},
                     {'base': base_file_tls13, 'pcap': path_tls13_pcap}]

    # Generate the baselines
    processes = list()
    logger.info("Generating TLS baselines...")
    for files in base_and_pcap:
        processes.append(subprocess.Popen([cli_paths['exec_path'],
                                           'output=' + files['base'],
                                           'outdir=' + cli_paths['baseline_path'],
                                           'tls=1',
                                           files['pcap']]))
    time.sleep(1)

    # End running subprocesses
    for proc in processes:
        rc_proc = end_process(proc)
        if rc_proc != 0:
            rc_overall = rc_proc

    return rc_overall


class ValidateTLS(object):
    def __init__(self, cli_paths):
        self.cli_paths = cli_paths
        self.compare_keys = ['sa','da','sp','dp','pr']
        self.new_flows = {'tls10': list(), 'tls11': list(),
                          'tls12': list(), 'tls13': list()}
        self.base_flows = {'tls10': list(), 'tls11': list(),
                           'tls12': list(), 'tls13': list()}
        self.corrupt_new_flows = {'tls10': list(), 'tls11': list(),
                              'tls12': list(), 'tls13': list()}
        self.tmp_outputs = {'tls10': 'tmp-tls10.json.gz',
                            'tls11': 'tmp-tls11.json.gz',
                            'tls12': 'tmp-tls12.json.gz',
                            'tls13': 'tmp-tls13.json.gz'}

    def __cleanup_tmp_files(self):
        """
        Delete any existing temporary files.
        :return:
        """
        # Delete temporary files
        for key, f in self.tmp_outputs.iteritems():
            if os.path.isfile(f):
                os.remove(f)

    def __load_baseline(self):
        for version, flows in self.base_flows.iteritems():
            pattern = self.cli_paths['baseline_path'] + '/*base-' + version + '.json.gz'
            base_files = glob.glob(pattern)

            if not base_files:
                logger.error('could not find baseline files.' +
                             'please use --tls-base-dir option to specify a location where valid files exist.')
                return 1

            latest_file = max(base_files, key=os.path.getmtime)
            logger.debug('latest ' + str(version) + ' base file selected ' + str(latest_file))

            with gzip.open(latest_file, 'r') as f:
                for line in f:
                    try:
                        flow = json.loads(line)
                        flows.append(flow)
                    except:
                        continue

        return 0

    def __run_tls(self):
        for version, flows in self.new_flows.iteritems():
            pcap = os.path.join(pcap_path, version +'.pcap')
            proc = subprocess.Popen([self.cli_paths['exec_path'],
                                    'output=' + self.tmp_outputs[version], 'tls=1', pcap])

            time.sleep(0.5)

            rc_proc = end_process(proc)
            if rc_proc != 0:
                return rc_proc

            with gzip.open(self.tmp_outputs[version], 'r') as f:
                for line in f:
                    try:
                        flow = json.loads(line)
                        flows.append(flow)
                    except:
                        continue

        return 0

    def compare_new_against_base(self):
        rc_overall = 0

        # Load the baseline json into memory
        rc = self.__load_baseline()
        if rc:
            logger.warning(str(self.__load_baseline) + ' failed with return code ' + str(rc))
            return rc

        # Run joy with tls, and load the json into memory
        rc = self.__run_tls()
        if rc:
            logger.warning(str(self.__run_tls) + ' failed with return code ' + str(rc))
            self.__cleanup_tmp_files()
            return rc

        # Compare the 2 datasets
        for version, tls_flows in self.new_flows.iteritems():
            # Operate on 1 TLS version at a time...
            for flow in tls_flows:
                corrupt = True
                if 'sa' not in flow:
                    # Skip if not a flow object
                    continue

                for base_flow in self.base_flows[version]:
                    if 'sa' not in base_flow:
                        # Skip if not a flow object
                        continue

                    if flow == base_flow:
                        # All of the key/value pairs matched
                        corrupt = False
                        break

                if corrupt is True:
                    self.corrupt_new_flows[version].append(flow)
                    rc_overall = 1

            if self.corrupt_new_flows[version]:
                # Log the corrupt flows
                for flow in self.corrupt_new_flows[version]:
                    logger.warning('New corrupt flow ' + str(version) + ' --> ' + str(flow))
                logger.warning('Please manually compare these corrupt flows against corresponding baseline file!')

        # Cleanup
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
    cli_paths['exec_path'] = os.path.join(cur_dir, '../../../bin/joy')
    cli_paths['pcap_path'] = os.path.join(cur_dir, pcap_path)
    cli_paths['baseline_path'] = os.path.join(cur_dir, baseline_path)
    logger.debug("script cli paths... " + str(cli_paths))

    if flag_generate_base is True:
        # The user wants to make a set of baseline files
        rc_unix_test = generate_baseline(cli_paths)
        # Check the value of function exit code
        if rc_unix_test:
            logger.warning(str(generate_baseline) + ' failed with return code ' + str(rc_unix_test))
            return rc_unix_test
    else:
        # Default to comparing new against baseline
        validate_tls = ValidateTLS(cli_paths)
        rc_unix_test = validate_tls.compare_new_against_base()
        # Check the value of function exit code
        if rc_unix_test:
            logger.warning(str(validate_tls.compare_new_against_base) +
                           ' failed with return code ' + str(rc_unix_test))
            return rc_unix_test

    return 0


def main_tls(baseline_dir=None,
             pcap_dir=None,
             create_base=False,
             base_generic=False):
    """
    Main function.
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
    if base_generic:
        global flag_base_generic
        flag_base_generic = True

    os_platform = sys.platform
    unix_platforms = ['linux', 'linux2', 'darwin']

    if os_platform in unix_platforms:
        status = test_unix_os()
        if status is not 0:
            logger.warning('FAILED')
            return status

    logger.warning('SUCCESS')
    return 0
