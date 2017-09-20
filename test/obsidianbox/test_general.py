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
import platform
import time
import logging
import subprocess
import gzip
import json
from .utils import end_process
from .utils import FileType

test_params = [[''],
               ['bidir=1'],
               ['bidir=1', 'zeros=1'],
               ['bidir=1', 'dist=1'],
               ['bidir=1', 'entropy=1'],
               ['bidir=1', 'tls=1'],
               ['bidir=1', 'idp=1400'],
               ['bidir=1', 'num_pkts=0'],
               ['bidir=1', 'num_pkts=101'],
               ['bidir=1', 'anon=internal.net'],
               ['bidir=1', 'label=internal:internal.net'],
               ['bidir=1', 'classify=1'],
               ['bidir=1', 'wht=1'],
               ['bidir=1', 'dns=1'],
               ['bidir=1', 'bpf=tcp'],
               ['bidir=1', 'hd=1'],
               ['bidir=1', 'type=1'], ]


class ValidateGeneral(object):
    def __init__(self, paths):
        self.paths = paths
        self.tmp_output = "tmp-general.json.gz"

    def _cleanup_tmp_files(self):
        """
        Delete any existing temporary files.
        :return:
        """
        if os.path.isfile(self.tmp_output):
            os.remove(self.tmp_output)

    def run(self):
        for params in test_params:
            proc = subprocess.Popen([self.paths['exec'], 'output=' + self.tmp_output] + params + [self.paths['pcap']])
            time.sleep(0.5)

            # End the Joy process
            rc = end_process(proc)
            if rc != 0:
                self._cleanup_tmp_files()
                logger.error("Subprocess Joy failure")
                raise RuntimeError("Subprocess Joy failure")

            # Make sure everything is valid JSON
            ft = FileType(self.tmp_output)
            if ft.is_gz():
                with gzip.open(self.tmp_output, 'r') as f:
                    for line in f:
                        try:
                            json.loads(line)
                        except ValueError as e:
                            logger.error("Invalid JSON object, see file %s", self.tmp_output)
                            raise e
            else:
                with open(self.tmp_output, 'r') as f:
                    for line in f:
                        try:
                            json.loads(line)
                        except ValueError as e:
                            logger.error("Invalid JSON object, see file %s", self.tmp_output)
                            raise e

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
    paths['pcap'] = os.path.join(cur_dir, '../pcaps/sample.pcap')

    validate_general = ValidateGeneral(paths)
    validate_general.run()


def test_windows_os():
    """
    Prepare the module for testing within a UNIX-like enviroment,
    and then run the appropriate test functions.
    :return:
    """
    cur_dir = os.path.dirname(__file__)

    paths = dict()
    paths['exec'] = os.path.join(cur_dir, '../../bin/win-joy.exe')
    paths['pcap'] = os.path.join(cur_dir, '../pcaps/sample.pcap')

    validate_general = ValidateGeneral(paths)
    validate_general.run()


def main_general():
    """
    Main IPFIX testing entry point.
    :return:
    """
    global logger
    logger = logging.getLogger(__name__)

    os_platform = platform.system()
    unix_platforms = ['Linux', 'Darwin']

    if os_platform in unix_platforms:
        test_unix_os()
    elif os_platform == "Windows":
        test_windows_os()

    logger.warning('SUCCESS')
