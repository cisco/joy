#!/usr/bin/python2.7

#
# joy_test.py - test driver for the joy program
#
# see the "usage" function for instructions
#
import platform
import time
import subprocess
import glob

#
# Setup variables
#
PLATFORM_OS = platform.system()
BINDIR = "bin"
DATA = "sample.pcap"
if any(glob.iglob('resources/*.pcap')):
    DATA += " resources/*.pcap"
OUTPUT = ("joyTest-%s" % (time.time()))

#
# Setup test scenarios
#
test_parms = ['',
              'bidir=1',
              'bidir=1 zeros=1',
              'bidir=1 retrans=1',
              'bidir=1 dist=1',
              'bidir=1 entropy=1',
              'bidir=1 tls=1',
              'bidir=1 idp=1400',
              'bidir=1 num_pkts=0',
              'bidir=1 num_pkts=101',
              'bidir=1 anon=internal.net',
              'bidir=1 label=intenral:internal.net',
              'bidir=1 classify=1',
              'bidir=1 wht=1',
              'bidir=1 ssh=1',
              'bidir=1 dns=1',
              'bidir=1 bpf=tcp',
              'bidir=1 hd=1',
              'bidir=1 type=1']

#
# main function
#
if __name__=='__main__':

   print("Platform: %s - Begin Testing" % (PLATFORM_OS))
   for i in test_parms:
     if PLATFORM_OS == "Windows":
         exe_cmd = ("%s\win-joy.exe %s output=%s %s" % (BINDIR,i,OUTPUT,DATA))
     else:
         exe_cmd = ("%s/joy %s output=%s %s" % (BINDIR,i,OUTPUT,DATA))
     print("testing joy with arguments %s output=%s ..." % (i, OUTPUT))
     rc = subprocess.call(exe_cmd, shell=True)
     if rc == 0:
         next_exe_cmd = ("python query.py %s > %s-2" % (OUTPUT, OUTPUT))
         rc = subprocess.call(next_exe_cmd, shell=True)
         if rc == 0:
             print("passed")
         else:
             print("failed: output was not valid JSON (see file %s)" % (OUTPUT))
             exit()
     else:
         print("failed: joy internal failure (see file %s)" % (OUTPUT))
         exit()

   print("Platform: %s - All Tests Passed!" % (PLATFORM_OS))
   clean_up_cmd = ("rm %s %s-2" % (OUTPUT,OUTPUT))
   subprocess.call(clean_up_cmd, shell=True)
