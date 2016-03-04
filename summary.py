#!/usr/bin/python2.7


import sys, json
from optparse import OptionParser
from pprint import pprint
from math import sqrt

# network address and netmask routines

import socket, struct

def ip2num(ip):
   return struct.unpack('I', socket.inet_aton(ip))[0]

def netmask(ip, numbits):
   return ip2num(ip) & ((2<<(numbits-1))-1)

def addressInSubnet(ip, subnet):
   return (ip2num(ip) & subnet) == subnet

localTable = [ netmask("10.0.0.0", 24), netmask("172.16.0.0", 20), netmask("192.168.0.0", 16) ]

def addrIsLocal(ip):
   if ip.startswith("10."): return True
   if ip.startswith("172.16."): return True
   if ip.startswith("192.168."): return True
   return False

# flowstats class 

class flowstats:
   def __init__(self):
      self.numbytes = 0
      self.num_msg = 0
      self.numflows = 0
      self.inbytes = 0
      self.outbytes = 0
      self.inmsg = 0
      self.outmsg = 0
      self.inbytesSq = 0
      self.outbytesSq = 0
      self.numbytesSq = 0

   def observe(self, numbytes, direction):
      self.numbytes += numbytes
      self.numbytesSq += numbytes * numbytes
      self.num_msg += 1
      if direction == ">":
         self.outbytes += numbytes
         self.outbytesSq += numbytes * numbytes
         self.outmsg += 1
      else:
         self.inbytes += numbytes
         self.inbytesSq += numbytes * numbytes
         self.inmsg += 1

   def printflowstats(self):
      print "flows:      " + '%5s' % str(self.numflows)
      print "messages:   " + '%5s' % str(self.num_msg)
      print "bytes:      " + '%5s' % str(self.numbytes)
      print "> messages: " + '%5s' % str(self.outmsg)
      print "> bytes:    " + '%5s' % str(self.outbytes)
      print "< messages: " + '%5s' % str(self.inmsg)
      print "< bytes:    " + '%5s' % str(self.inbytes)
      if self.numflows > 0:
         amf = float(self.num_msg)/float(self.numflows)
         print "messages per flow:    " + '%5s' % str(amf)
         afs = float(self.numbytes)/float(self.numflows)
         print "bytes per flow:       " + '%5s' % str(afs) 
         amf = float(self.outmsg)/float(self.numflows)
         print "outbound messages per flow: " + '%5s' % str(amf)
         amf = float(self.inmsg)/float(self.numflows)
         print "inbound messages per flow:  " + '%5s' % str(amf)
      if self.num_msg > 1:
         ads = float(self.numbytes)/float(self.num_msg)
         print "average message size: " + '%5s' % str(ads)
         vms = (float(self.numbytesSq) - float(self.numbytes * self.numbytes)/float(self.num_msg))/float(self.num_msg - 1)
         print "std dev message size: " + '%5s' % str(sqrt(vms))
      if self.inmsg > 1:
         ads = float(self.inbytes)/float(self.inmsg)
         print "average inbound message size: " + '%5s' % str(ads)
         vms = (float(self.inbytesSq) - float(self.inbytes * self.inbytes)/float(self.inmsg))/float(self.inmsg - 1)
         print "std dev inbound message size: " + '%5s' % str(sqrt(vms))
      if self.outmsg > 1:
         ads = float(self.outbytes)/float(self.outmsg)
         print "average outbound message size: " + '%5s' % str(ads)
         vms = (float(self.outbytesSq) - float(self.outbytes * self.outbytes)/float(self.outmsg))/float(self.outmsg - 1)
         print "std dev outbound message size: " + '%5s' % str(sqrt(vms))
      

flowdict = {}
flowtotal = flowstats()

def process_file(f, destPort, bidir, addrType):
   global flowdict, flowtotal
   json_data=open(f)
   data = json.load(json_data)
   for flow in data["appflows"]:
      
      dp = flow["flow"]["dp"]

      # filter on destPort, if provided
      if (destPort != None):
         if (str(destPort) != str(dp)):
            break 

      # filter on bidirectional traffic, if flagged
      if (bidir != None):
         if (flow["flow"]["ib"] == 0 or flow["flow"]["ob"] == 0):
            break 

      # filter on internal destination, if flagged
      da = flow["flow"]["da"]
      if (addrType == 'local'):
         if not addrIsLocal(da):
            break
         print "address is local: " + str(da)
      if (addrType == 'remote'):
         if addrIsLocal(da):
            break
         print "address is remote: " + str(da)      

      # keep separate statistics for each destination port
      if dp not in flowdict:
         fs = flowstats()
         flowdict[dp] = fs
      else:
         fs = flowdict[dp]

      # gather stats for each flow record
      fs.numflows += 1
      flowtotal.numflows += 1
      for x in flow["flow"]['non_norm_stats']:
         fs.observe(x["b"], x["dir"])
         flowtotal.observe(x["b"], x["dir"])
         print x["b"]


   json_data.close()

if __name__=='__main__':

   # check args
   if len(sys.argv) < 2:
      print "usage: " + sys.argv[0] + " <filename>"
      sys.exit()

   parser = OptionParser()
   parser.set_description("summarize JSON flow data")
   parser.add_option("--dp", dest="dp", help="select destination port")
   parser.add_option("--bidir", dest="bidir", action='store_true', 
                     help="bidirectional only")
   parser.add_option("--addr", dest="addrType", help="local or remote")

   (opts, args) = parser.parse_args()

   # process files
   for x in args:
      process_file(x, opts.dp, opts.bidir, opts.addrType)

   for fs in flowdict:
      print "flow stats for dp=" + str(fs)
      flowdict[fs].printflowstats()
      print 

   if (opts.dp == None):
      print "total flow stats"
      flowtotal.printflowstats()

   sys.exit()

