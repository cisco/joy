#!/usr/bin/python

# query2.py is a rewrite of query.py - the goal is to implement
# reusable classes for flow filtering and data selection functions

import sys, json, operator, gzip, string, time, pprint, copy, re, pickle, collections
from optparse import OptionParser
from math import sqrt, log

badLineCount = 0
mergeCount = 0
lineCount = 0

class flowIterator:
   def __init__(self):
      pass

   def __iter__(self):
      return self

   def next(self):
      flow = dict()
      return flow

class flowIteratorFromFile(flowIterator):
   def __iter__(self):
      return self

   def next(self):
      global lineCount
      while True:
         try:
            line = self.f.readline()
            if line == '':
               raise StopIteration
            tmp = json.loads(line)
            if 'version' not in tmp:
               lineCount += 1
               return tmp
         except StopIteration:
            raise
         except:
            pass
            global badLineCount
            badLineCount += 1

   def __init__(self, f):      
      if f is '-':
         self.f = sys.stdin
      else:
         if ".gz" in f:
            self.f = gzip.open(f,'r')
         else:
            self.f = open(f,'r') 

class flowFilterIterator(flowIterator):
   def __init__(self, source, filter):
      self.source = source
      self.filter = filter

   def __iter__(self):
      return self

   def next(self):
      tmp = self.source.next()
      while self.filter.match(tmp) is not True:
         tmp = self.source.next()
      return tmp

class flowStitchIterator(flowIterator):
   def __init__(self, source):
      self.source = source
      self.active_flows = collections.OrderedDict()
   
      for f in source:
         key = (f['sa'], f['da'], f['sp'], f['dp'], f['pr'])
         revkey = (f['da'], f['sa'], f['dp'], f['sp'], f['pr'])
         if key in self.active_flows:
            self.active_flows[key] = self.merge(self.active_flows[key], f)
            pass
         elif revkey in self.active_flows:
            self.active_flows[revkey] = self.merge_reverse(self.active_flows[revkey], f)
            pass
         else:
            self.active_flows[key] = f

      self.flows = iter(self.active_flows.values())

   def __iter__(self):
      return self

   def next(self):
      return self.flows.next()

   # merge f2 into f1, where both flows are in the same direction, and
   # f1 preceeds f2 (f1.ts < f2.ts)
   #
   def merge(self, f1, f2):
      global mergeCount
      mergeCount += 1
      for k, v in f2.items():
         if k not in f1:
            f1[k] = f2[k]
         else:
            if k == 'te': 
               f1[k] = max(f1[k],f2[k])
            elif k == 'ip' or k == 'ib':
               f1[k] += f2[k]
            elif k == 'op' or k == 'ob':
               f1[k] += f2[k]
            elif k == 'bd':
               for i, e in enumerate(f2[k]):
                  f1[k][i] += e
            else:
               pass
         return f1

   # merge f2 into f1, where f2 is in the reverse direction to f1, and
   # f1 preceeds f2 (f1.ts < f2.ts)
   #
   def merge_reverse(self, f1, f2):
      global mergeCount
      mergeCount += 1
      for k, v in f2.items():
         if k not in f1:
            if k == 'op':
               f1['ip'] += f2[k]
            elif k == 'ob':
               f1['ib'] += f2[k]
            else:
               f1[k] = f2[k]
         else:
            if k == 'te':
               f1[k] = max(f1[k],f2[k])
            elif k == 'ip':
               f1[k] += f2['ob']
            elif k == 'op':
               f1[k] += f2['ib']
            elif k == 'bd':
               for i, e in enumerate(f2[k]):
                  f1[k][i] += e
            else:
               pass
         return f1



class flowProcessor:
   def __init__(self):
      self.flowset = []

   def processFlow(self, flow):
      self.flowset.append(flow)

   def preProcess(self, context=None):    
      pass

   def postProcess(self, proc=None):    
      for flow in self.flowset:
         json.dump(flow, sys.stdout)
         print ""

class splitProcessor(flowProcessor):
   def __init__(self, fpobj, field):
      self.fpobj = fpobj
      self.dict = dict()
      self.field = field

   def processFlow(self, flow):
      if flow[self.field] not in self.dict:
         self.dict[flow[self.field]] = copy.deepcopy(self.fpobj)
         self.dict[flow[self.field]].preProcess([self.field, flow[self.field]])
      self.dict[flow[self.field]].processFlow(flow)

   def preProcess(self, context=None):
      self.context = context
      pass

   def postProcess(self, proc=None):
      if self.context:
         print self.context
      for k, v in self.dict.items():
         v.postProcess(copy.deepcopy(proc))

class flowStitchProcessor:
   def __init__(self, fp):
      self.flowset = []
      self.active_flows = dict()
      self.fp

   def processFlow(self, flow):
      if 'x' in flow and flow['x'] == 'a':
         print "found active timeout"
      self.flowset.append(flow)

   def preProcess(self, context=None):    
      pass

   def postProcess(self, proc=None):    
      for flow in self.flowset:
         json.dump(flow, sys.stdout)
         print ""

     
class flowElementSelector(flowProcessor):

   def __init__(self, elements):
      self.flowset = []
      self.template = self.string_to_template_object(elements)

   def string_to_template_object(self, s):
      t = '{'
      needArg = False
      for x in re.split('([\{\}\[\],])', s):         
         if x == '':
            pass
         elif x == '{' or x == '[':
            t += x
            needArg = False
         elif x == '}' or x == ']' or x == ',':
            if needArg:
               t += "None"
               needArg = False
            t += x
         else:
            t += '\"' + x + '\":'
            needArg = True
      if needArg:
         t += "None"
      t += '}'
      # print "t: " + t
      return eval(t)
      
   def copySelectedElements(self, tmplDict, flow):
      outDict = dict()
      for k, v in tmplDict.items():
         if k in flow:
            if isinstance(v, list):
               flowList = flow[k]
               if flowList:
                  outDict[k] = list()
                  for x in flowList:
                     for y in v:
                        tmp = self.copySelectedElements(y, x)
                        if tmp:
                           outDict[k].append(tmp)
                  if not outDict[k]:
                     outDict = None
            elif isinstance(v, dict):
               tmp = self.copySelectedElements(v, flow[k])
               if tmp:
                  outDict[k] = tmp
            else:
               if v:
                  if flow[k] == v:
                     outDict[k] = flow[k]
               else:
                  outDict[k] = flow[k]
      if outDict:
         return outDict
      else:
         return None

   def processFlow(self, flow):
      output = self.copySelectedElements(self.template, flow)
      if output:
         self.flowset.append(output)

   def preProcess(self, context=None):    
      self.context = context

   def postProcess(self, proc=flowProcessor()):    
      proc.preProcess(self.context)
      for flow in self.flowset:
         proc.processFlow(flow)
      proc.postProcess()



class flowProcessorDistribution:
   def __init__(self):
      self.dist = dict()
      self.total = 0

   def processFlow(self, flow):
      value = pickle.dumps(flow)
      # self.key = tuple(flow.keys())
      if value in self.dist:
         self.dist[value] += 1
      else:
         self.dist[value] = 1
      self.total += 1

   def preProcess(self, context=None):    
      self.context = context

   def postProcess(self):    
      output = list()
      for k, v in self.dist.iteritems():
         d = pickle.loads(k)
         d["count"] = v   
         d["total"] = self.total   
         # d["fraction"] = v/self.total   
         output.append(d)
      output.sort(key=lambda x: x["count"], reverse=True)
      for d in output:
         json.dump(d, sys.stdout)
         print ""

class flowProcessorSum:
   def __init__(self, sumvars):
      self.sums = dict()
      self.fixed_fields = dict()
      self.total = 0
      self.sumvars = sumvars

   def processFlow(self, flow):
      self.key = tuple(flow.keys())
      for k, v in flow.iteritems():
         if k in self.sumvars: # assume isinstance(v, int):
            if k in self.sums:
               self.sums[k] += v
            else:
               self.sums[k] = 0
         else:
            if k not in self.fixed_fields:
               self.fixed_fields[k] = set()
            self.fixed_fields[k].add(v)
      self.total += 1

   def preProcess(self, context=None):    
      self.context = context

   def postProcess(self):    
      d = dict()
      for k, v in self.fixed_fields.iteritems():
         if len(v) == 1:
            d[k] = list(v)[0]
         else:
            d[k] = list(v)
      for k, v in self.sums.iteritems():
         klist = list(k)
         for i, x in enumerate(list(self.key)):
            if x in self.sums:
               d[x] = self.sums[x]
      d["sum_over"] = self.total   
      print d

class flowProcessorDelta:
   def __init__(self, deltavars):
      self.delta = dict()
      self.deltavars = deltavars

   def processFlow(self, flow):
      self.key = tuple(flow.keys())
      for k, v in flow.iteritems():
         if k in self.deltavars: 
            if k in self.delta:
               flow[k] -= self.delta[k]
            else:
               self.delta[k] = flow[k]
      json.dump(flow, sys.stdout)
      print ""

   def preProcess(self, context=None):    
      self.context = context

   def postProcess(self):    
      pass         

class filter:
   def __init__(self):
      self.filters = [ ]
  
   def match(self, flow):
      if not self.filters:     
         return True       # by default, match everything
      for f in self.filters:
         if f.match(flow):
            return True
      return False

   def addFilter(self, f):
      self.filters.append(f)

class conjunctionFilter(filter):

   def match(self, flow):
      if not self.filters:     
         return False     # by default, match nothing
      else:
         tval = True
         for f in self.filters:
            tval = tval and f.match(flow)
         return tval

def identity(x):
   return x

def alwaysTrue(x,y):
   return True

class matchType:
   base = 0
   list_any = 1
   list_all = 2

class flowFilter(filter):

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


#
# main function 
#
if __name__=='__main__':

   parser = OptionParser()
   parser.set_description("filter JSON flow data and print out matching flows, selected fields, or stats")
   parser.add_option("--where",  dest="filter", help="filter flows")
   parser.add_option("--select", dest="selection", help="select field to output")
   parser.add_option("--split",  dest="splitfield", help="split processing by field")
   parser.add_option("--dist",   action="store_true", help="compute distribution over selected element(s)")
   parser.add_option("--stitch", action="store_true", help="stitch together successive flows separated by active timeouts")
   parser.add_option("--sum",    dest="sumvars", help="compute sum over selected element(s)")
   parser.add_option("--delta",  dest="deltavars", help="compute deltas of selected element(s)")

   # parse command line, and check arguments
   (opts, args) = parser.parse_args()
   if not args:
      args.append('-')   # no input files, so assume stdin 

   if opts.selection is not None:
      fp = flowElementSelector(opts.selection)
   else:
      fp = flowProcessor()      

   if opts.splitfield:
      fp = splitProcessor(fp, opts.splitfield)

   if opts.dist:
      dist = flowProcessorDistribution()
   elif opts.sumvars:
      dist = flowProcessorSum(opts.sumvars)
   elif opts.deltavars:
      dist = flowProcessorDelta(opts.deltavars)
   else:
      dist = flowProcessor()

   # create filter
   # 
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

   # process all files, with pre- and post-processing
   #
   fp.preProcess()
   for x in args:
      try:
         if opts.stitch:
            flowSource = flowStitchIterator(flowFilterIterator(flowIteratorFromFile(x), ff))
         else:
            flowSource = flowFilterIterator(flowIteratorFromFile(x), ff)
         for flow in flowSource:
            fp.processFlow(flow)
      except KeyboardInterrupt:
         sys.exit()
      except:
         raise
   fp.postProcess(dist)

   sys.stderr.write("read " + str(lineCount) + " JSON lines\n")
   sys.stderr.write("merged " + str(mergeCount) + " flows\n")
   if badLineCount > 0:
      sys.stderr.write("warning: could not read " + str(badLineCount) + " lines\n")
