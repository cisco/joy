#!/bin/python
import os
import sys
import gzip
import json
import time
import optparse
import datetime
from collections import OrderedDict

from tls_fingerprint import TLSFingerprint

class GenFingerprint:

    def __init__(self, contrib_info):
        self.tls = TLSFingerprint(None)
        self.fp_db = {}
        self.contrib_info = contrib_info

    def generate(self, ifile):
        file_ = None
        if ifile.endswith('.gz'):
            file_ = gzip.open(ifile, 'r')
        else:
            file_ = open(ifile, 'r')

        for line in file_:
            try:
                flow = json.loads(line)
            except Exception as e:
                print e

            if 'fingerprints' in flow and 'tls' in flow['fingerprints']:
                fp_str_ = flow['fingerprints']['tls']

                tmp_fp_ = self.tls.gen_unknown_fingerprint(fp_str_, ui=False)
                tmp_fp_['source'] = [self.contrib_info]
                tmp_fp_['process_info'][0]['prevalence'] = 1.0
                tmp_fp_['process_info'][0]['count'] = 1
                if 'exe' in flow and 'hash' in flow['exe']:
                    del tmp_fp_['process_info']
                    tmp_fp_['process_info'] = [OrderedDict({})]
                    tmp_fp_['process_info'][0]['process'] = flow['exe']['name']
                    tmp_fp_['process_info'][0]['application_category'] = 'Unknown'
                    tmp_fp_['process_info'][0]['prevalence'] = 1.0
                    tmp_fp_['process_info'][0]['count'] = 1
                    tmp_fp_['process_info'][0]['sha256'] = flow['exe']['hash']

                self.update_database(fp_str_, tmp_fp_)

        file_.close()

        self.clean_process_counts()


    def export(self, ofile):
        with open(ofile, 'w') as op:
            for k in self.fp_db:
                op.write(json.dumps(self.fp_db[k]) + '\n')


    # sort process list and adjust prevalence field
    def clean_process_counts(self):
        for k in self.fp_db:
            total_count = 0
            tmp_procs = []
            for p_ in self.fp_db[k]['process_info']:
                total_count += p_['count']
                tmp_procs.append((p_['count'], p_))
            tmp_procs.sort()
            tmp_procs.reverse()
            procs = []
            for _, p_ in tmp_procs:
                p_['prevalence'] = float('%0.2f' % (p_['count']/float(total_count)))
                procs.append(p_)
            self.fp_db[k]['process_info'] = procs


    # update the fingerprint database with a single fingerprint observation
    def update_database(self, fp_str_, fp_):
        if fp_str_ not in self.fp_db:
            self.fp_db[fp_str_] = fp_
        else:
            seen = False
            for p_ in self.fp_db[fp_str_]['process_info']:
                if p_['sha256'] == fp_['process_info'][0]['sha256']:
                    p_['count'] += 1
                    seen = True
                    break
            if seen == False:
                self.fp_db[fp_str_]['process_info'].append(fp_['process_info'][0])


def main():
    parser = optparse.OptionParser()

    parser.add_option('-i','--input',action='store',dest='input',help='Joy JSON output, with fpx=1',default=None)
    parser.add_option('-o','--output',action='store',dest='output',help='name for generated fingerprint database',default='anon.json')
    parser.add_option('-c','--contrib_info',action='store',dest='contrib_info',help='brief contributor information',default='anon')

    options, args = parser.parse_args()

    if options.input == None:
        print 'error: need Joy JSON'
        return 1

    gen_fp_db = GenFingerprint(options.contrib_info)
    gen_fp_db.generate(options.input)
    gen_fp_db.export(options.output)


if __name__ == '__main__':
    sys.exit(main())
