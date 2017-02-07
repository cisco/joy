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

import logging
import argparse
from pytests_joy.ipfix import main_ipfix
from pytests_joy.tls import main_tls


def modify_test_suite(suite, module_flag, module_func, single_module):
    """
    Change the list of test modules that will be run.
    :param suite: List of test modules
    :param module_flag: A flag corresponding to a single module, given through CLI
    :param module_func: The entry point function of the selected test module
    :param single_module: If it exists, the current selection for SINGLE (1 only) module to run.
    :return:
    """
    if module_flag == 'no':
        # Exclude the specified module
        suite.remove(module_func)
        return None
    elif module_flag == 'yes':
        # Only test the specified module
        if single_module:
            logger.error('error: ' + single_module + ' has been selected to run by itself.\n' +
                         '\tonly 1 module can be run individually.')
            exit(1)
        for test in suite:
            if test is not module_func:
                suite.remove(test)
        return module_func


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Defaults to run all of pytests_joy modules. ' +
                    'Please use the listed module options to select a subset.'
    )
    parser.add_argument('-l', '--log',
                        dest='log_level',
                        choices=['debug', 'info', 'warning', 'error', 'critical'],
                        help='Set the logging level')
    parser.add_argument('--ipfix',
                        dest='flag_ipfix',
                        choices=['yes', 'no'],
                        help='yes to run ONLY ipfix module; no to exclude from test suite')
    parser.add_argument('--tls',
                        dest='flag_tls',
                        choices=['yes', 'no'],
                        help='yes to run ONLY tls module; no to exclude from test suite')
    parser.add_argument('--tls-base-dir',
                        dest='tls_base_dir',
                        help='Specify the absolute path to directory where tls baseline files will reside.')
    parser.add_argument('--tls-pcap-dir',
                        dest='tls_pcap_dir',
                        help='Specify the absolute path to directory where tls pcap files currently exist.')
    parser.add_argument('--tls-make-base',
                        action='store_true',
                        dest='tls_make_base',
                        help='Use to create a new set of tls baseline files. ')
    args = parser.parse_args()

    """
    Configure root logging
    """
    if args.log_level:
        logging.basicConfig(level=args.log_level.upper())
    else:
        logging.basicConfig()

    logger = logging.getLogger(__name__)

    """
    Local namespace variables for the option values
    """
    tls_base_dir = None
    if args.tls_base_dir:
        tls_base_dir = args.tls_base_dir

    tls_pcap_dir = None
    if args.tls_pcap_dir:
        tls_pcap_dir = args.tls_pcap_dir

    tls_make_base = False
    if args.tls_make_base:
        tls_make_base = args.tls_make_base

    """
    Add a new test:
    1: Import the module that contains test
    2: Add the test function reference to the 'test_suite' list below
    """
    test_suite = [main_ipfix, main_tls, ]

    single_mod = None
    if args.flag_ipfix:
        single_mod = modify_test_suite(test_suite, args.flag_ipfix, main_ipfix, single_mod)
    if args.flag_tls:
        single_mod = modify_test_suite(test_suite, args.flag_tls, main_tls, single_mod)

    for test in test_suite:
        if test is main_tls:
            # Invoke with proper parameter values for TLS
            rc_main = main_tls(tls_base_dir, tls_pcap_dir, tls_make_base)
        else:
            rc_main = test()
        if rc_main != 0:
            logger.warning('FAILED')
            exit(rc_main)

    logger.warning('SUCCESS')
    exit(0)
