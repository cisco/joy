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
from obsidianbox import main_general
from obsidianbox import main_ipfix
from obsidianbox import main_tls


def modify_test_suite(suite, module_flag, module_func, wiped):
    """
    Change the list of test modules that will be run.
    :param suite: List of test modules
    :param module_flag: A flag corresponding to a single module, given through CLI
    :param module_func: The entry point function of the selected test module
    :param wiped: Flag indicating whether the suite list has been previously wiped.
    :return:
    """
    if module_flag == 'off':
        # Exclude the specified module
        suite.remove(module_func)
    elif module_flag == 'on':
        # Only test the specified module
        if wiped is True:
            # The list is already a subset, append to it
            suite.append(module_func)
        else:
            # Create new subset list from scratch
            del suite[:]
            suite.append(module_func)
            wiped = True

    return wiped


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Defaults to run all of pytests_joy modules. ' +
                    'Please use the listed module options to select a subset.'
    )
    parser.add_argument('-l', '--log',
                        dest='log_level',
                        choices=['debug', 'info', 'warning', 'error', 'critical'],
                        help='Set the logging level')
    parser.add_argument('--log-file',
                        action='store_true',
                        dest='log_file',
                        help='Log messages to a file instead of the console (terminal).')
    parser.add_argument('--general',
                        dest='flag_general',
                        choices=['on', 'off'],
                        help='on to run ONLY general module (includes others turned "on"); off to exclude')
    parser.add_argument('--ipfix',
                        dest='flag_ipfix',
                        choices=['on', 'off'],
                        help='on to run ONLY ipfix module (includes others turned "on"); off to exclude')
    parser.add_argument('--tls',
                        dest='flag_tls',
                        choices=['on', 'off'],
                        help='on to run only tls module (includes others turned "on"); off to exclude')
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
    parser.add_argument('--tls-base-file-generic',
                        action='store_true',
                        dest='tls_base_generic',
                        help='Use a generic default name when making baseline files. ' +
                             'Caution: overwrite of previous files with same name is probable!')
    args = parser.parse_args()

    """
    Configure logging
    """
    LEVELS = {'debug': logging.DEBUG,
              'info': logging.INFO,
              'warning': logging.WARNING,
              'error': logging.ERROR,
              'critical': logging.CRITICAL}

    log_level = None
    if args.log_level:
        log_level = LEVELS[args.log_level.lower()]

    log_file = None
    if args.log_file:
        logging.basicConfig(
            filename='obsidianbox.log',
            level=log_level,
            format='%(levelname)s - %(asctime)s - {%(name)s:%(lineno)d} - %(message)s',
        )
    else:
        logging.basicConfig(
            level=log_level,
            format='%(levelname)s - {%(name)s:%(lineno)d} - %(message)s',
        )

    logger = logging.getLogger(__name__)

    """
    Add a new test:
    1: Import the module that contains test
    2: Add the test function reference to the 'test_suite' list below
    """
    test_suite = [main_general, main_ipfix, main_tls, ]

    wiped_flag = False
    if args.flag_general:
        wiped_flag = modify_test_suite(test_suite, args.flag_general, main_general, wiped_flag)
    if args.flag_ipfix:
        wiped_flag = modify_test_suite(test_suite, args.flag_ipfix, main_ipfix, wiped_flag)
    if args.flag_tls:
        wiped_flag = modify_test_suite(test_suite, args.flag_tls, main_tls, wiped_flag)

    logger.warning('Joy Obsidianbox tests start...')
    logger.warning('------------------------------')

    for test in test_suite:
        if test is main_tls:
            # Invoke with proper parameter values for TLS
            main_tls(args.tls_base_dir, args.tls_pcap_dir,
                     args.tls_make_base, args.tls_base_generic)
        else:
            test()

    logger.warning('SUCCESS')
    exit(0)
