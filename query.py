#!/usr/bin/python2.7

# query.py implements flow filtering and data selection functions
#
# see the "usage" function for instructions
#

import sys, json, operator
from optparse import OptionParser
from pprint import pprint
from math import sqrt, log
                    
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
      self.lengths = {}
      self.times = {}
      self.rle_lengths = {}

   def observe(self, numbytes, direction, time):
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
      if numbytes not in self.lengths:
         self.lengths[numbytes] = 1
      else:
         self.lengths[numbytes] = self.lengths[numbytes] + 1
      if time not in self.times:
         self.times[time] = 1
      else:
         self.times[time] = self.times[time] + 1

   def print_lengths(self):
      for x in self.lengths:
        print str(self.lengths[x]) + "\t" + str(x)
      # for x in self.rle_lengths:
      #   print str(self.rle_lengths[x]) + "\t" + str(x)

   def print_times(self):
      for x in self.times:
        print str(self.times[x]) + "\t" + str(x)
      # for x in self.rle_lengths:
      #   print str(self.rle_lengths[x]) + "\t" + str(x)

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
      


class filter:
   def __init__(self):
      self.filters = [ ]
  
   def match(self, flow):
      # by default, match everything
      if not self.filters:     
         return True
      # match any filter
      for f in self.filters:
         if f.match(flow):
            return True

   def addFilter(self, f):
      self.filters.append(f)

class conjunctionFilter(filter):

   def match(self, flow):
      # by default, match nothing
      if not self.filters:     
         return False
      # match all filter
      tval = True
      for f in self.filters:
         tval = tval and f.match(flow)
      return tval



# START TLS FUNCTIONS

class seclevel:
   unknown = 255
   recommended = 1
   acceptable = 2
   legacy = 3
   avoid = 4

def seclevel2string(s):
   switch = {
      seclevel.recommended: "recommended",
      seclevel.acceptable: "accpetable",
      seclevel.legacy: "legacy",
      seclevel.avoid: "avoid"
      }
   return switch.get(s, "unknown")

def keylen_seclevel(keylen):
    switch = {
       520: seclevel.recommended,
       528: seclevel.recommended,
       2048: seclevel.acceptable,
       1024: seclevel.avoid, 
       4096: seclevel.recommended,
       776:  seclevel.avoid,
       512:  seclevel.avoid,
    }
    return switch.get(keylen, seclevel.unknown)

def signature_keylen_seclevel(keylen):
    switch = {
       1024: seclevel.avoid, 
       2048: seclevel.acceptable,
       3072: seclevel.recommended,
       4096: seclevel.recommended,
    }
    return switch.get(keylen, seclevel.unknown)

def ciphersuite_seclevel(cs):
   switch = {
      "0000": seclevel.avoid,
      "0001": seclevel.avoid,
      "0002": seclevel.avoid,
      "0003": seclevel.avoid,
      "0004": seclevel.avoid,
      "0005": seclevel.avoid,
      "0006": seclevel.avoid,
      "0007": seclevel.legacy,
      "0008": seclevel.avoid,
      "0009": seclevel.avoid,
      "000a": seclevel.legacy,
      "000b": seclevel.avoid,
      "000c": seclevel.avoid,
      "000d": seclevel.legacy,
      "000e": seclevel.avoid,
      "000f": seclevel.avoid,
      "0010": seclevel.legacy,
      "0011": seclevel.avoid,
      "0012": seclevel.avoid,
      "0013": seclevel.legacy,
      "0014": seclevel.avoid,
      "0015": seclevel.avoid,
      "0016": seclevel.legacy,
      "0017": seclevel.avoid,
      "0018": seclevel.avoid,
      "0019": seclevel.avoid,
      "001a": seclevel.avoid,
      "001b": seclevel.avoid,
      "001e": seclevel.avoid,
      "001f": seclevel.legacy,
      "0020": seclevel.avoid,
      "0021": seclevel.legacy,
      "0022": seclevel.avoid,
      "0023": seclevel.avoid,
      "0024": seclevel.avoid,
      "0025": seclevel.avoid,
      "0026": seclevel.avoid,
      "0027": seclevel.avoid,
      "0028": seclevel.avoid,
      "0029": seclevel.avoid,
      "002a": seclevel.avoid,
      "002b": seclevel.avoid,
      "002c": seclevel.avoid,
      "002d": seclevel.avoid,
      "002e": seclevel.avoid,
      "002f": seclevel.recommended,
      "0030": seclevel.legacy,
      "0031": seclevel.legacy,
      "0032": seclevel.recommended,
      "0033": seclevel.recommended,
      "0034": seclevel.avoid,
      "0035": seclevel.recommended,
      "0036": seclevel.legacy,
      "0037": seclevel.legacy,
      "0038": seclevel.recommended,
      "0039": seclevel.recommended,
      "003a": seclevel.avoid,
      "003b": seclevel.avoid,
      "003c": seclevel.recommended,
      "003d": seclevel.recommended,
      "003e": seclevel.legacy,
      "003f": seclevel.legacy,
      "0040": seclevel.recommended,
      "0041": seclevel.recommended,
      "0042": seclevel.legacy,
      "0043": seclevel.legacy,
      "0044": seclevel.recommended,
      "0045": seclevel.recommended,
      "0046": seclevel.avoid,
      "0067": seclevel.recommended,
      "0068": seclevel.legacy,
      "0069": seclevel.legacy,
      "006a": seclevel.recommended,
      "006b": seclevel.recommended,
      "006c": seclevel.avoid,
      "006d": seclevel.avoid,
      "0084": seclevel.recommended,
      "0085": seclevel.legacy,
      "0086": seclevel.legacy,
      "0087": seclevel.recommended,
      "0088": seclevel.recommended,
      "0089": seclevel.avoid,
      "008a": seclevel.avoid,
      "008b": seclevel.legacy,
      "008c": seclevel.recommended,
      "008d": seclevel.recommended,
      "008e": seclevel.avoid,
      "008f": seclevel.legacy,
      "0090": seclevel.recommended,
      "0091": seclevel.recommended,
      "0092": seclevel.avoid,
      "0093": seclevel.legacy,
      "0094": seclevel.recommended,
      "0095": seclevel.recommended,
      "0096": seclevel.recommended,
      "0097": seclevel.legacy,
      "0098": seclevel.legacy,
      "0099": seclevel.recommended,
      "009a": seclevel.recommended,
      "009b": seclevel.avoid,
      "009c": seclevel.recommended,
      "009d": seclevel.recommended,
      "009e": seclevel.recommended,
      "009f": seclevel.recommended,
      "00a0": seclevel.legacy,
      "00a1": seclevel.legacy,
      "00a2": seclevel.recommended,
      "00a3": seclevel.recommended,
      "00a4": seclevel.legacy,
      "00a5": seclevel.legacy,
      "00a6": seclevel.avoid,
      "00a7": seclevel.avoid,
      "00a8": seclevel.recommended,
      "00a9": seclevel.recommended,
      "00aa": seclevel.recommended,
      "00ab": seclevel.recommended,
      "00ac": seclevel.recommended,
      "00ad": seclevel.recommended,
      "00ae": seclevel.recommended,
      "00af": seclevel.recommended,
      "00b0": seclevel.avoid,
      "00b1": seclevel.avoid,
      "00b2": seclevel.recommended,
      "00b3": seclevel.recommended,
      "00b4": seclevel.avoid,
      "00b5": seclevel.avoid,
      "00b6": seclevel.recommended,
      "00b7": seclevel.recommended,
      "00b8": seclevel.avoid,
      "00b9": seclevel.avoid,
      "00ba": seclevel.recommended,
      "00bb": seclevel.legacy,
      "00bc": seclevel.legacy,
      "00bd": seclevel.recommended,
      "00be": seclevel.recommended,
      "00bf": seclevel.avoid,
      "00c0": seclevel.recommended,
      "00c1": seclevel.legacy,
      "00c2": seclevel.legacy,
      "00c3": seclevel.recommended,
      "00c4": seclevel.recommended,
      "00c5": seclevel.avoid,
      "c001": seclevel.avoid,
      "c002": seclevel.avoid,
      "c003": seclevel.legacy,
      "c004": seclevel.recommended,
      "c005": seclevel.recommended,
      "c006": seclevel.avoid,
      "c007": seclevel.avoid,
      "c008": seclevel.legacy,
      "c009": seclevel.recommended,
      "c00a": seclevel.recommended,
      "c00b": seclevel.avoid,
      "c00c": seclevel.avoid,
      "c00d": seclevel.legacy,
      "c00e": seclevel.recommended,
      "c00f": seclevel.recommended,
      "c010": seclevel.avoid,
      "c011": seclevel.avoid,
      "c012": seclevel.legacy,
      "c013": seclevel.recommended,
      "c014": seclevel.recommended,
      "c015": seclevel.avoid,
      "c016": seclevel.avoid,
      "c017": seclevel.avoid,
      "c018": seclevel.avoid,
      "c019": seclevel.avoid,
      "c01a": seclevel.legacy,
      "c01b": seclevel.legacy,
      "c01c": seclevel.legacy,
      "c01d": seclevel.recommended,
      "c01e": seclevel.recommended,
      "c01f": seclevel.recommended,
      "c020": seclevel.recommended,
      "c021": seclevel.recommended,
      "c022": seclevel.recommended,
      "c023": seclevel.recommended,
      "c024": seclevel.recommended,
      "c025": seclevel.recommended,
      "c026": seclevel.recommended,
      "c027": seclevel.recommended,
      "c028": seclevel.recommended,
      "c029": seclevel.recommended,
      "c02a": seclevel.recommended,
      "c02b": seclevel.recommended,
      "c02c": seclevel.recommended,
      "c02d": seclevel.recommended,
      "c02e": seclevel.recommended,
      "c02f": seclevel.recommended,
      "c030": seclevel.recommended,
      "c031": seclevel.recommended,
      "c032": seclevel.recommended,
      "c033": seclevel.avoid,
      "c034": seclevel.legacy,
      "c035": seclevel.recommended,
      "c036": seclevel.recommended,
      "c037": seclevel.recommended,
      "c038": seclevel.recommended,
      "c039": seclevel.avoid,
      "c03a": seclevel.avoid,
      "c03b": seclevel.avoid,
      "c03c": seclevel.recommended,
      "c03d": seclevel.recommended,
      "c03e": seclevel.legacy,
      "c03f": seclevel.legacy,
      "c040": seclevel.legacy,
      "c041": seclevel.legacy,
      "c042": seclevel.recommended,
      "c043": seclevel.recommended,
      "c044": seclevel.recommended,
      "c045": seclevel.recommended,
      "c046": seclevel.avoid,
      "c047": seclevel.avoid,
      "c048": seclevel.recommended,
      "c049": seclevel.recommended,
      "c04a": seclevel.recommended,
      "c04b": seclevel.recommended,
      "c04c": seclevel.recommended,
      "c04d": seclevel.recommended,
      "c04e": seclevel.recommended,
      "c04f": seclevel.recommended,
      "c050": seclevel.recommended,
      "c051": seclevel.recommended,
      "c052": seclevel.recommended,
      "c053": seclevel.recommended,
      "c054": seclevel.legacy,
      "c055": seclevel.legacy,
      "c056": seclevel.recommended,
      "c057": seclevel.recommended,
      "c058": seclevel.legacy,
      "c059": seclevel.legacy,
      "c05a": seclevel.avoid,
      "c05b": seclevel.avoid,
      "c05c": seclevel.recommended,
      "c05d": seclevel.recommended,
      "c05e": seclevel.recommended,
      "c05f": seclevel.recommended,
      "c060": seclevel.recommended,
      "c061": seclevel.recommended,
      "c062": seclevel.recommended,
      "c063": seclevel.recommended,
      "c064": seclevel.recommended,
      "c065": seclevel.recommended,
      "c066": seclevel.recommended,
      "c067": seclevel.recommended,
      "c068": seclevel.recommended,
      "c069": seclevel.recommended,
      "c06a": seclevel.recommended,
      "c06b": seclevel.recommended,
      "c06c": seclevel.recommended,
      "c06d": seclevel.recommended,
      "c06e": seclevel.recommended,
      "c06f": seclevel.recommended,
      "c070": seclevel.recommended,
      "c071": seclevel.recommended,
      "c072": seclevel.recommended,
      "c073": seclevel.recommended,
      "c074": seclevel.recommended,
      "c075": seclevel.recommended,
      "c076": seclevel.recommended,
      "c077": seclevel.recommended,
      "c078": seclevel.recommended,
      "c079": seclevel.recommended,
      "c07a": seclevel.recommended,
      "c07b": seclevel.recommended,
      "c07c": seclevel.recommended,
      "c07d": seclevel.recommended,
      "c07e": seclevel.legacy,
      "c07f": seclevel.legacy,
      "c080": seclevel.recommended,
      "c081": seclevel.recommended,
      "c082": seclevel.legacy,
      "c083": seclevel.legacy,
      "c084": seclevel.avoid,
      "c085": seclevel.avoid,
      "c086": seclevel.recommended,
      "c087": seclevel.recommended,
      "c088": seclevel.recommended,
      "c089": seclevel.recommended,
      "c08a": seclevel.recommended,
      "c08b": seclevel.recommended,
      "c08c": seclevel.recommended,
      "c08d": seclevel.recommended,
      "c08e": seclevel.recommended,
      "c08f": seclevel.recommended,
      "c090": seclevel.recommended,
      "c091": seclevel.recommended,
      "c092": seclevel.recommended,
      "c093": seclevel.recommended,
      "c094": seclevel.recommended,
      "c095": seclevel.recommended,
      "c096": seclevel.recommended,
      "c097": seclevel.recommended,
      "c098": seclevel.recommended,
      "c099": seclevel.recommended,
      "c09a": seclevel.recommended,
      "c09b": seclevel.recommended,
      "c09c": seclevel.recommended,
      "c09d": seclevel.recommended,
      "c09e": seclevel.recommended,
      "c09f": seclevel.recommended,
      "c0a0": seclevel.recommended,
      "c0a1": seclevel.recommended,
      "c0a2": seclevel.recommended,
      "c0a3": seclevel.recommended,
      "c0a4": seclevel.recommended,
      "c0a5": seclevel.recommended,
      "c0a6": seclevel.recommended,
      "c0a7": seclevel.recommended,
      "c0a8": seclevel.recommended,
      "c0a9": seclevel.recommended,
      "c0aa": seclevel.recommended,
      "c0ab": seclevel.recommended,
      "c0ac": seclevel.recommended,
      "c0ad": seclevel.recommended,
      "c0ae": seclevel.recommended,
      "c0af": seclevel.recommended,
   }
   return switch.get(str(cs), seclevel.unknown)

def securityLevel(tls):
   # print str(tls)
   # print str(type(tls))
   if type(tls) is not dict:
      print "error: wrong type argument to seclevel function"
      sys.exit()
   seclevels = []
   if "tls_client_key_length" in tls:
      seclevels.append(keylen_seclevel(tls["tls_client_key_length"]))
   if "scs" in tls:
      seclevels.append(ciphersuite_seclevel(tls["scs"]))
   if "server_cert" in tls:
      if "signature_key_size" in tls["server_cert"]:
         seclevels.append(signature_keylen_seclevel(tls["server_cert"]["signature_key_size"]))

   if not seclevels:
      return "\"unknown\""
   return "\"" + seclevel2string(max(seclevels)) + "\""

# END TLS FUNCTIONS

def entropy(bd):
   if type(bd) is not list:
      print "error: wrong type argument to entropy function"
      sys.exit()
   sum = 0.0
   e = 0.0
   for x in bd:
      sum = sum + x
   if sum == 0.0:
      return 0.0
   for x in bd:
      p = x / sum
      if p > 0:
         e = e - p * log(p)
   return e / log(2.0)

def collision(bd):
   if type(bd) is not list:
      print "error: wrong type argument to collision entropy function"
      sys.exit()
   total = 0.0
   e = 0.0
   for x in bd:
      total = total + x
   if total == 0.0:
      return 0.0
   for x in bd:
      p = x / total
      e = e + (p * p)
   if e == 0.0:
      e = 0.0
   else:
      e = - log(e) / log(2.0)
   return e

def minentropy(bd):
   if type(bd) is not list:
      print "error: wrong type argument to collision entropy function"
      sys.exit()
   total = 0.0
   e = 0.0
   for x in bd:
      total = total + x
   if total == 0.0:
      return 0.0
   for x in bd:
      if x > e:
         e = x
   if e == 0.0:
      e = 0.0
   else:
      e = - log(e / total) / log(2.0)
   return e

def gini(bd):
   if type(bd) is not list:
      print "error: wrong type argument to gini function"
      sys.exit()
   total = 0.0
   for x in bd:
      total = total + x
   if total == 0.0:
      return 0.0

   bd.sort()   
   n = len(bd)
   for i in range(n):
      bd[i] = bd[i] / total
   print "bd: " + str(bd)
   e = 0.0
   for i in range(n):
      e = (n - i) * bd[i]
   e = 1 + (- 2 * e)/float(n)
   print "gini: " + str(e)
   return e

def identity(x):
   return x

def alwaysTrue(x,y):
   return True

class matchType:
   base = 0
   list_any = 1
   list_all = 2

class flowFilter:

   def selectField(self, a):
      if self.field2 is None:
         return a
      else:
         if self.field2 in a:
            return a[self.field2]
         return None

   def __init__(self, string):
      self.func = identity
      
      if string is None:
         self.matchAll = True
         return
      else:
         self.matchAll = False

      # remove whitespace
      string = string.replace(" ", "")         

      # print "string: " + string

      for op in [ '=', '>', '<' ]: 
         if op in string:
            (self.field, self.value) = string.split(op, 2)

            # look for functions
            if '(' in self.field:
               funcname, argument = self.field.split('(')
               if ')' in argument:
                  self.field = argument.split(')')[0]
                  if funcname == "entropy":
                     self.func = entropy
                  elif funcname == "collision":
                     self.func = collision
                  elif funcname == "minentropy":
                     self.func = minentropy
                  elif funcname == "gini":
                     self.func = gini
                  elif funcname == "seclevel":
                     self.func == securityLevel
                  else:
                     print "error: unrecognized function " + funcname
                     sys.exit()
               else:
                  print "error: could not parse command " + str(string)
                  sys.exit()
      
            # arrays are notated array[all] or array[any]
            if "[all]" in self.field:
               self.field = self.field.replace("[all]", "")
               self.type = matchType.list_all
            elif "[any]" in self.field:
               self.field = self.field.replace("[any]", "")
               self.type = matchType.list_any
            else:
               self.type = matchType.base
            # print self.field

            # subfields are notated "flow.subfield"
            if '.' in self.field:
               (self.field, self.field2) = self.field.split(".", 2)
            else:
               self.field2 = None
            
            # convert to int or float as needed
            try:
               self.value = int(self.value)
            except ValueError:
               try:
                  self.value = float(self.value)
               except:
                  pass

            if op == '=':
               if self.value is '*':
                  self.operator = alwaysTrue
               else:
                  self.operator = operator.eq 
            if op == '<':
               self.operator = operator.lt 
            if op == '>':
               self.operator = operator.gt 
            # print "filter: " + self.field + " " + str(self.operator) + " " + str(self.value)



   def matchElement(self, filter):
      # print "this is my filter: " + str(filter) + " and value: " + str(self.value) 
      # print "type: " + str(self.type) + " : " + str(matchType.list_all)
      if self.type is matchType.base:
         # print "func(): " + self.func(self.selectField(filter))
         # print self.operator,
         # print self.value,
         # print type(self.value),
         # print " = ",
         # print self.operator(self.func(self.selectField(filter)), float(self.value))
         # print "------"
         if self.operator(self.func(self.selectField(filter)), self.value):   
            return True
         else:
            return False
      elif self.type is matchType.list_all:
         tval = True
         if not filter:
            return False
         for x in filter:
            tval = tval and self.operator(self.selectField(x), self.value)
         return tval
      elif self.type is matchType.list_any:
         if not filter:
            return False
         for x in filter:
            if self.operator(self.selectField(x), self.value):
               return True
         return False

   def match(self, flow):
      if self.matchAll is True:
         return True         
      if self.field in flow:
         return self.matchElement(flow[self.field])

import string

class noTranslation():
   def __init__(self):
      pass

   def translate(self, s, val):
      return val

class translator():
   def __init__(self):
      try:
         self.initialize()
      except:
         print "error: could not initialize translator (check for missing data files)"
         sys.exit()

   def initialize(self):
      self.d = {}
      with open("/usr/share/joy/data/ciphersuites.txt") as f:
         for line in f:
            (key, val, sec) = line.split()
            self.d[key] = val + " (" + sec + ")"
      
      self.pr = {
         6: "TCP",
         17: "UDP"
         }
      with open("/usr/share/joy/data/ip.txt") as f:
         for line in f:
            (key, val) = line.split()
            self.pr[key] = val

      self.ports = {}
      with open("/usr/share/joy/data/ports.txt") as f:
         for line in f:
            try:
               (val, key) = line.split()
               if '-' in str(key):
                  start, stop = str(key).split('-')
                  for a in range(int(start), int(stop)):
                     self.ports[a] = string.upper(val)
               else:
                  key = int(key)
                  self.ports[key] = string.upper(val)
            except:
               pass
               # print "could not parse line " + line


   def translate(self, s, val):
      print "translating " + str(s) + " " + str(type(s))
      print "compare to " + str(u"dp") + " " + str(type(u"dp"))

      print "\"" + s + "\""
      print "\"" + str(val) + "\""

      if s is u"scs" or s is u"cs":
         return self.d.setdefault(val, "unknown")
      elif s is u"pr":
         return self.pr.setdefault(val, "unknown")
      elif s is u"dp" or s is u"sp":
         print "GOT HERE"
         z = self.ports.setdefault(val, None)
         if z is None:
            return val
         else:
            return z
      else:
         return val

def elementPrint(f, *elements):
   printComma = True
   for s in elements:
      if s is "START":
         printComma = False
      if (s) in f:
         if printComma:
            print ","
         else:
            printComma = True
         val = t.translate(s, f[s])
         print "         \"" + s + "\": ",
         if type(val) is int or type(val) is float:
            print str(val),
         else:
            print "\"" + str(val) + "\"",

def listPrint(f, listname, itemsPerLine=16):
   first = True
   count = 0
   if listname in f:
      print ","
      print "         \"" + listname + "\": [",
      for x in f[listname]:
         if not first:
            print ",",
         else:
            first = False
         if count % itemsPerLine == 0:
            print
            print "         ",
         val = t.translate(listname, x)
         print '%4s' % str(val),
         count = count + 1
      print
      print "          ]",

def listPrintObject(f, listname, *elements):
   first = True
   if listname in f:
      print ","
      print "         \"" + listname + "\": ["
      for x in f[listname]:
         if not first:
            print ","
         else:
            first = False
         print "            {",
         objFirst = True
         for s in elements:
            if (s) in x:
               if not objFirst:
                  print ",",
               else:
                  objFirst = False
               print " \"" + s + "\": ",
               if type(x[s]) is int or type(x[s]) is float:
                  print str(x[s]),
               else:
                  print "\"" + str(x[s]) + "\"",
         print "}",
      if f[listname]:
         print
      print "          ]",

def objectPrint(f, objname):
   first = True
   if objname in f:
      print ","
      print "         \"" + objname + "\": {"
      for x in f[objname]:
         if not first:
            print ","
         else:
            first = False
         print "            \"" + str(x) + "\": \"" + str(f[objname][x]) + "\"",
      print
      print "          }",

def flowPrint(f):
      print "   {"
      # print json.dumps(f, indent=3),
      # OLD: print "      \"flow\": {"
      elementPrint(f, "START", "sa", "da", "pr", "sp", "dp", "ob", "op", "ib", "ip", "ts", "te", "ottl", "ittl")
      listPrintObject(f, "packets", "b", "dir", "ipt")
      listPrint(f, "bd")
      listPrint(f, "compact_bd")
      elementPrint(f, "bd_mean", "bd_std", "be", "tbe", "i_probable_os", "o_probable_os")
      listPrintObject(f, "dns", "qn", "rn", "a", "soa", "ttl", "rc", "type", "class")
      elementPrint(f,  )
      listPrint(f, "cs", 1)
      elementPrint(f, "scs")
      objectPrint(f, "tls") # , "tls_iv", "tls_ov", "tls_orandom", "tls_irandom", "tls_osid", "tls_isid", "srlt")
      objectPrint(f, "ihttp")
      objectPrint(f, "ohttp")
      # OLD: print "\n      }"
      print "\n   }"

def printItem(x, indentation):
   if type(x) is unicode:
      print indentation + "\"" + str(x) + "\"",
   else:
      print indentation + str(x),

def stringifyItem(x):
   if type(x) is unicode:
      return "\"" + str(x) + "\""
   else:
      return str(x)

def printObject(obj, indentation):
   firstLine = True
   for x, y in obj.iteritems():
      if not firstLine:
         print ",",
      else:
         firstLine = False
      if type(y) is dict:
         print indentation + "\"" + str(x) + "\": {",
         printObject(y, indentation + "   ")
         print indentation + "}", 
      elif type(y) is list:
         print indentation + "\"" + str(x) + "\": " + "[", 
         firstInList = True
         for z in y:
            if not firstInList:
               print ",",
            firstInList = False
            if type(z) is dict:
               print indentation + "{",
               printObject(z, indentation + "   ")
               print indentation + "}", 
            else:
               print stringifyItem(z),
               # print indentation + "   " + str(z),
         print indentation + "]", 
      else:
         value = t.translate(x, y)
         print indentation + "\"" + str(x) + "\": " + stringifyItem(value), 

def flowPrintAlt(f):
   print "{",
   printObject(f, "\n   ")
   print "\n}"
   # print json.dumps(f, indent=3)   

class flowProcessor:
   def __init__(self):
      self.firstFlow = 1

   def processFlow(self, flow):
      # OLD: if not self.firstFlow:
      # OLD:    print ","
      # OLD: else:
      # OLD:    self.firstFlow = 0
         # OLD: print "\"appflows\": ["
      flowPrintAlt(flow)

   def processMetadata(self, metadata):
      # OLD: print "\"metadata\": ", 
      print json.dumps(metadata, indent=3),
      # OLD: print ","

   def preProcess(self):    
      pass
      # OLD: print "{"

   def postProcess(self):    
      if self.firstFlow:
         self.firstFlow = 0
         # OLD: print "\"appflows\": ["
      # OLD: print "]"
      # OLD: print "}"

import time

def flowSummaryPrint(f):
      print "%32s" % str(f["sa"]), 
      print "%32s" % str(f["da"]),
      print "%4s" % str(f["pr"]),
      print "%6s" % str(f["sp"]),
      print "%6s" % str(f["dp"]),
      print "%6s" % str(f["ob"]),
      print "%6s" % str(f["op"]),
      if "ib" in f:
         print "%6s" % str(f["ib"]),
         print "%6s" % str(f["ip"]),
      else:
         print "             ",
      print time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(f["ts"])) + " ",
      print round(f["te"] - f["ts"], 3)
      # print time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(f["te"]))
      # print "%14s" % str(f["ts"]) + " ",
      # print "%14s" % str(f["te"])

class flowSummaryProcessor(flowProcessor):
     def processFlow(self, flow):
        flowSummaryPrint(flow)

     def processMetadata(self, metadata):
        pass
     
     def preProcess(self):    
        print "%32s" % "source address", 
        print "%32s" % "destination address",
        print "%4s" %  "prot",
        print "%6s" % "sport",
        print "%6s" % "dport",
        print "%6s" % "obytes",
        print "%6s" % "opkts",
        print "%6s" % "ibytes",
        print "%6s" % "ipkts",
        print "%19s" % "date     time",
        print "%8s" % "seconds"
     
     def postProcess(self):    
        pass


def printable(s):
   if not s.isdigit():
      return "\"" + s + "\""
   else:
      return str(s)

def raw2output(raw):
   # print "raw: " + str(raw) + " type: " + str(type(raw))
   if type(raw) is float:
      return "{:.3f}".format(raw) 
   if type(raw) is int:
      return str(raw)
   if type(raw) is unicode:
      return "\"" + raw + "\""
   if type(raw) is dict:
      return json.dumps(raw)  # indent=3 makes this legible
   else:
      return raw

class printSelectedElements:
   def __init__(self, field):
      self.func = identity
      self.funcname = None
      self.firstFlow = True
      self.field = field.replace(" ", "") # no whitespace
      if '.' in self.field:
         (self.field, self.field2) = self.field.split(".", 2)
         self.depth = 2
      else:
         self.depth = 1

      # look for functions
      if '(' in self.field:
         self.funcname, argument = self.field.split('(')
         if ')' in argument:
            self.field = argument.split(')')[0]
            if self.funcname == "entropy":
               self.func = entropy
            elif self.funcname == "collision":
               self.func = collision
            elif self.funcname == "minentropy":
               self.func = minentropy
            elif self.funcname == "gini":
               self.func = gini
            elif self.funcname == "seclevel":
               self.func = securityLevel
            else:
               print "error: unrecognized function " + funcname
               sys.exit()
         else:
            print "error: could not parse command " + str(string)
            sys.exit()


   def processFlow(self, flow, first):
      # print "   {"
      # print "      \"flow\": ",
      # print json.dumps(flow, indent=3),

      if self.field in flow:
         filter = flow[self.field]
         if self.depth is 1:
            if self.funcname is not None:
               name = self.funcname + "(" + self.field + ")"
            else:
               name = self.field
            if first:
               first = False
               if not self.firstFlow:
                  print ",",
               else:
                  self.firstFlow = False
               print  "\n\t{ ",
            else:
               print ", ",
            if self.funcname is not None: 
               print "\"" + name + "\": ", 
               print raw2output(self.func(filter)), 
            else:
               print "\"" + name + "\": ",
               print raw2output(filter), 
         else:
            if type(filter) is list:
               for a in filter:
                  if self.field2 in a:
                     filter2 = a[self.field2]
                     print "\"" + str(self.field2) + "\": " + printable(filter2),
                     if first:
                        first = False
                        if not self.firstFlow:
                           print ",",
                        else:
                           self.firstFlow = False
                        print  "\n\t{ ",
                     else:
                        print ", ",
                     print "\"" + str(self.field2) + "\": " + printable(filter2),
            else:
               if self.field2 in filter:
                  filter2 = filter[self.field2]
                  if first:
                     first = False
                     if not self.firstFlow:
                        print ",",
                     else:
                        self.firstFlow = False
                     print  "\n\t{ ",
                  else:
                     print ", ",
                  print "\"" + str(self.field2) + "\": " + raw2output(filter2),
      # print "   }",
      return first

   def processMetadata(self, metadata):
      pass

   def preProcess(self):    
      print "{"
      print "\"" + str(self.field) + "\": ["

   def postProcess(self):    
      print
      print "   ]"
      print "}"


class printMultipleElements():
   def __init__(self, name):
      self.array = []
      self.field = name
      self.firstFlow = True

   def addElement(self, x):
      self.array.append(x)

   def processFlow(self, flow):
      first = True
      for x in self.array:
         first = x.processFlow(flow, first)
      if not first:
         print "}",

   def preProcess(self):    
      print "{"
      print "\"" + str(self.field) + "\": [",

   def postProcess(self):    
      print
      print "   ]"
      print "}"

   def processMetadata(self, metadata):    
      pass


class flowStatsPrinter:
   def __init__(self):
      self.flowdict = {}
      self.flowtotal = flowstats()      

   def processFlow(self, flow):
      #
      # keep separate statistics for each destination port
      dp = flow["dp"]
      if dp not in self.flowdict:
         fs = flowstats()
         self.flowdict[dp] = fs
      else:
         fs = self.flowdict[dp]

      fs.numflows += 1
      self.flowtotal.numflows += 1
      for x in flow['packets']:
         fs.observe(x["b"], x["dir"], x["ipt"])
         self.flowtotal.observe(x["b"], x["dir"], x["ipt"])      

   def processMetadata(self, metadata):
      pass

   def preProcess(self):    
      print

   def postProcess(self):      
      # for fs in self.flowdict:
      #   print "flow stats for dp=" + str(fs)
      #   self.flowdict[fs].printflowstats()
      #   print 
      print "total flow stats"
      self.flowtotal.printflowstats()
      # self.flowtotal.print_lengths()
      # self.flowtotal.print_times()


def description(t):
   if t is str:
      return "string"
   if t is int:
      return "int"
   if t is list:
      return "list"
   if t is object:
      return "object"
   if t is float:
      return "float"
   return "unknown"

class printSchema:
   def __init__(self):
      self.firstFlow = 1
      self.indentation = ""
      self.schema = {}

   def processDatum(self, x, y):
      t = type(y)
      if t is dict:
         print "processing object: " + str(y)
         tmp = self.indentation
         self.indentation = self.indentation + "\t"
         self.processFlow(y)
         self.indentation = tmp
         self.schema[x] = "flow.object" + str(x) + '\t' 
      elif t is list:
         print "processing list: " + str(y)
         tmp = self.indentation
         self.indentation = self.indentation + "\t"
         # self.processFlow((y)[1])
         self.indentation = tmp
      else:
         print self.indentation + "flow." + str(x) + '\t' + description(t)
         self.schema[x] = self.indentation + "flow." + str(x) + '\t' + description(t)
      

   def processFlow(self, flow):
      print "got flow"
      for x in flow:
         self.processDatum(x, flow[x])

   def printSchema(self, schema):
      for x in schema:
         print schema[x] + " " + str(type(schema[x]))
         if type(schema[x]) is dict:
            print "printing dictionary"
            self.printSchema(x)

   def preProcess(self):    
      pass

   def postProcess(self):    
      print "schema: "
      # print self.schema
      self.printSchema(self.schema)
      
   def processMetadata(self, x):
      pass

def processFileOld(f, ff, fp):
   global flowdict, flowtotal
   json_data=open(f)
   data = json.load(json_data)

   if "metadata" in data:
      fp.processMetadata(data["metadata"])

   for flow in data["appflows"]:
      if ff.match(flow["flow"]):
         fp.processFlow(flow["flow"])
   json_data.close()

def processLine(line):
   if line.strip == '{' or 'metadata' in line:
      print "warning: legacy JSON format"
      return
   try:
      tmp = json.loads(line)
      if 'version' not in tmp:
         if ff.match(tmp):
            fp.processFlow(tmp)
   except:
      pass

import gzip

def processFile(f, ff, fp):
   if f is '-':
      for line in sys.stdin:
         processLine(line)
   else:
      if ".gz" in f:
         with gzip.open(f,'r') as jsonobjects:
            for line in jsonobjects:
               processLine(line)
      else:
         with open(f,'r') as jsonobjects:
            for line in jsonobjects:
               processLine(line)



def usage():
   print
   print "EXAMPLE"
   print "./query.py sample.json --where \" packets[any].b = 478 & pr = 6\" --select dp"
   print
   print "FILTER examples:"
   print "  dp=443"
   print "  \"dp > 1024\""
   print "  \"sa = 10.0.0.1\""
   print "  \"pr = 17\""
   print "  \"bd[all] > 10\""
   print "  \"bd[any] > 10\""
   print "  \"packets[any].b = 41 & ip = 2\""
   print "  \"packets[all].ipt < 5 & dp = 80\""
   print "  \"entropy(bd) > 7.0\""
   print "  \"collision(bd) > 7.0\""
   print "  \"minentropy(bd) > 7.0\""
   print
   print "SELECTION examples:"
   print "  dp"
   print "  sa"
   print "  ohttp.uri"
   print "  packets"
   print "  packets.ipt"
   print "  \"entropy(bd)\""
   print "  \"collision(bd)\""
   print "  \"minentropy(bd)\""

#
# main function 
#
if __name__=='__main__':

   parser = OptionParser()
   parser.set_description("filter JSON flow data and print out matching flows, selected fields, or stats")
   parser.add_option("--where", dest="filter", help="filter flows")
   parser.add_option("--select", dest="selection", help="select field to output")
   parser.add_option("--stats", action="store_true", help="print out statistics")
   parser.add_option("--summary", action='store_true', dest="summary", help="print single line per flow ")
   parser.add_option("--translate", action='store_true', dest="translate", help="translate numbers to acronyms ")
   parser.add_option("--schema", action='store_true', dest="schema", help="print out schema")

   # parse command line, and check arguments
   (opts, args) = parser.parse_args()
   if not args:
      args.append('-')   # no input files, so assume stdin 

   if opts.translate is True:
      t = translator()
   else:
      t = noTranslation()

   if opts.selection is not None:
      # fp = printSelectedElements(opts.selection)
      fp = printMultipleElements("name")
      for z in opts.selection.split(','):
         fp.addElement(printSelectedElements(z))
   else:
      if opts.schema is True:
         fp = printSchema()
      elif opts.stats is True:
         fp = flowStatsPrinter()
      elif opts.summary is True:
         fp = flowSummaryProcessor()
      else:
         fp = flowProcessor()      

   ff = filter()
   if opts.filter:
      for z in opts.filter.split('|'):
         # print "disjunction: " + str(z)
         if '&' in z:
            conjf = conjunctionFilter()
            for conj in z.split('&'):
               # print "conjunction: " + str(conj)
               conjf.addFilter(flowFilter(conj))
            ff.addFilter(conjf)
         else:
            ff.addFilter(flowFilter(z))

   if not args:
      parser.print_help()
      usage()
      sys.exit()

   # process all files, with preamble and postable
   #
   fp.preProcess()
   for x in args:
      try:
         processFile(x, ff, fp)
      except KeyboardInterrupt:
         sys.exit()      
   fp.postProcess()




