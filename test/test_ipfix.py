#!/usr/bin/env python
import os
import sys
import subprocess
import time


def test_unix_os():
    rc = 0

    cur_dir = os.path.dirname(__file__)
    exec_path = os.path.join(cur_dir, '../bin/pcap2flow')
    sample_input = os.path.join(cur_dir, '../sample.pcap')

    # Start the ipfix collector
    proc_collect = subprocess.Popen([exec_path,
                                     'output=test-ipfix-collect.gz',
                                     'ipfix_collect_online=1',
                                     'ipfix_collect_port=4739'])
    time.sleep(1)

    # Start the ipfix exporter
    proc_export = subprocess.Popen([exec_path,
                                    'output=test-ipfix-export.gz',
                                    'ipfix_export_port=2000',
                                    sample_input])
    proc_export.wait()
    time.sleep(1)

    """
    Cleanup
    """
    # End the ipfix exporting process
    if proc_export.poll() is None:
        # Gracefully terminate the process
        proc_export.terminate()
        time.sleep(1)
        if proc_export.poll() is None:
            # Hard kill the subprocess
            proc_export.kill()
            time.sleep(1)
            if proc_export.poll() is None:
                # Runaway zombie process
                print(str(__file__) + ' - error: export subprocess turned zombie')
                rc = 1
    elif proc_export.poll() != 0:
        # Export process ended with bad exit code
        print(str(__file__) + ' - error: export subprocess failed rc: ' +
              str(proc_export.poll()))
        rc = 1

    # End the ipfix collecting process
    if proc_collect.poll() is None:
        # Gracefully terminate the process
        proc_collect.terminate()
        time.sleep(1)
        if proc_collect.poll() is None:
            # Hard kill the subprocess
            proc_collect.kill()
            time.sleep(1)
            if proc_collect.poll() is None:
                # Runaway zombie process
                print(str(__file__) + ' - error: collect subprocess turned zombie')
                rc = 1
    elif proc_collect.poll() != 0:
        # Collect process ended with bad exit code
        print(str(__file__) + ' - error: collect subprocess failed rc: ' +
              str(proc_collect.poll()))
        rc = 1

    # End of test
    return rc


if __name__ == "__main__":
    os_platform = sys.platform
    unix_platforms = ['linux', 'linux2', 'darwin']

    if os_platform in unix_platforms:
        status = test_unix_os()
        if status is not 0:
            print(str(__file__) + ' - FAILURE')
            exit(status)

    print(str(__file__) + ' - SUCCESS')
    exit(0)
