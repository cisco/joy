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
import sys
import gzip
import bz2
import json
import pickle
import copy
import re
import fnmatch


"""
Dictionary Iterator Classes
"""


class DictStreamIterator(object):
    def __init__(self):
        pass

    def __iter__(self):
        return self

    def next(self):
        n = dict()
        return n


class DictStreamIteratorFromFile(DictStreamIterator):
    """
    Create a new DictIterator instance from the given input file.
    This allows iteration over all JSON objects within the file.
    """
    def __init__(self, stdin=None, file_name=None, skip_lines=[]):
        if not stdin and not file_name:
            raise ValueError("api_error: need stdin or file_name")

        self.stdin = stdin
        self.file_name = file_name
        self.f = None
        self.skip_lines = skip_lines
        self.badLineCount = 0
        self.lineCount = 0

        # Run any initialization functions
        self._load_file()

    def _cleanup(self):
        try:
            self.f.close()
        except IOError:
            pass

    def _load_file(self):
        if self.stdin:
            self.f = self.stdin
        elif self.file_name:
            ft = SleuthFileType(self.file_name)
            if ft.is_gz():
                self.f = gzip.open(self.file_name, 'r')
            elif ft.is_bz2():
                self.f = bz2.BZ2File(self.file_name, 'r')
            else:
                self.f = open(self.file_name, 'r')

    def next(self):
        while True:
            try:
                line = self.f.readline()
                if line == '':
                    raise StopIteration

                tmp = json.loads(line)

                for key in self.skip_lines:
                    # Skip any line that contains a particular key
                    if key not in tmp:
                        self.lineCount += 1
                        return tmp
            except StopIteration:
                sys.stderr.write("read " + str(self.lineCount) + " lines\n")

                if self.badLineCount > 0:
                    sys.stderr.write("warning: could not parse " + str(self.badLineCount) + " lines\n")

                self._cleanup()
                raise
            except:
                # sys.stderr.write(line)
                self.badLineCount += 1


class DictStreamFilterIterator(DictStreamIterator):
    def __init__(self, source, filter):
        self.source = source
        self.filter = filter

    def next(self):
        """
        Find the next JSON object from source that matches the given filter
        :return:
        """
        tmp = self.source.next()

        while self.filter.match(tmp) is not True:
            tmp = self.source.next()

        return tmp

    
class DictStreamSelectIterator(DictStreamIterator):
    def __init__(self, source, elements):
        self.source = source
        self.template = SleuthTemplateDict(elements)

    def next(self):
        while True:
            tmp = self.source.next()
            output = self.template.copy_selected_elements(self.template.template, tmp)
            if output:
                return output


class DictStreamNormalizeIterator(DictStreamIterator):
    def __init__(self, source, elements):
        self.source = source
        self.template = SleuthTemplateDict(elements)

    def next(self):
        tmp = self.source.next()
        output = self.template.normalize_selected_elements(self.template.template, tmp)

        return output

class DictStreamApplyIterator(DictStreamIterator):
    def __init__(self, source, elements, func):
        self.source = source
        self.template = SleuthTemplateDict(elements)
        self.func = func

    def next(self):
        tmp = self.source.next()
        output = self.template.apply_to_selected_elements(self.template.template, tmp, self.func)

        return output

    
class DictStreamEnrichIterator(DictStreamIterator):
    def __init__(self, source, name, function, **kwargs):
        self.source = source
        self.name = name
        self.function = function
        self.kwargs = kwargs

    def next(self):
        nextval = self.source.next()
        tmp = self.function(nextval, self.kwargs)
        if tmp:
            nextval[self.name] = tmp
        return nextval


class DictStreamEnrichIntoIterator(DictStreamIterator):
    def __init__(self, source, name, function, **kwargs):
        self.source = source
        self.name = name
        self.function = function
        self.kwargs = kwargs

    def next(self):
        nextval = self.source.next()
        tmp = self.function(nextval, self.kwargs)
        if tmp:
            if self.name not in nextval:
                nextval[self.name] = {}
            for key, value in tmp.items():
                nextval[self.name][key] = value
        return nextval

class DictStreamDistributionIterator(DictStreamIterator):
    def __init__(self, source, indent=None):
        self.source = source
        self.dist = dict()
        self.total = 0
        self.indent = indent

    def __iter__(self):
        return self

    def next(self):
        try:
            obj = self.source.next()
            value = pickle.dumps(obj)
            self.key = tuple(obj.keys())
            if value in self.dist:
                self.dist[value] += 1
            else:
                self.dist[value] = 1
            self.total += 1
        except StopIteration:
            output = list()
        
            for k, v in self.dist.iteritems():
                d = pickle.loads(k)
                d["count"] = v
                d["total"] = self.total
                # d["fraction"] = v/self.total
                output.append(d)
            output.sort(key=lambda x: x["count"], reverse=True)

            for d in output:
                json.dump(d, sys.stdout, indent=self.indent)
                print ""

            raise StopIteration


        

"""
Dictionary Processor Classes
"""


class DictStreamProcessor(object):
    def __init__(self, indent=None):
        self.obj_set = list()
        self.indent = indent

    def main_process(self, obj):
        self.obj_set.append(obj)

    def pre_process(self, context=None):
         self.context = context

    def post_process(self, proc=None):
        if proc:
            proc.pre_process(self.context)
            for obj in self.obj_set:
                proc.main_process(obj)
            proc.post_process()
        else:
            for obj in self.obj_set:
                try:
                    json.dump(obj, sys.stdout, indent=self.indent)
                    print ""
                except IOError:
                    # Broken pipe, exit loop
                    break


class DictStreamGroupProcessor(DictStreamProcessor):
    def __init__(self, fpobj, field):
        self.fpobj = fpobj
        self.dict = dict()
        self.field = field
        self.template = SleuthTemplateDict(field)

    def main_process(self, obj):
        value = pickle.dumps(self.template.copy_selected_elements(self.template.template, obj))

        if value not in self.dict:
            self.dict[value] = copy.deepcopy(self.fpobj)
            self.dict[value].pre_process([self.field, value])

        self.dict[value].main_process(obj)

    def post_process(self, proc=None):
        if self.context:
            print self.context

        for k, v in self.dict.items():
            v.post_process(copy.deepcopy(proc))


class DictStreamSumProcessor(DictStreamProcessor):
    def __init__(self, sumvars, indent=None):
        self.sums = dict()
        self.fixed_fields = dict()
        self.total = 0
        self.sumvars = sumvars
        self.indent = indent

    def main_process(self, obj):
        self.key = tuple(obj.keys())

        for k, v in obj.iteritems():
            if k in self.sumvars: # assume isinstance(v, int):
                if k in self.sums:
                    self.sums[k] += v
                else:
                    self.sums[k] = v
            else:
                if k not in self.fixed_fields:
                    self.fixed_fields[k] = set()
                self.fixed_fields[k].add(v)
        self.total += 1

    def post_process(self):
        d = dict()
        for k, v in self.fixed_fields.iteritems():
            if len(v) == 1:
                d[k] = list(v)[0]
            else:
                d[k] = list(v)
        for k, v in self.sums.iteritems():
            for i, x in enumerate(list(self.key)):
                if x in self.sums:
                    d[x] = self.sums[x]

        # NOTE: sum_over might interfere with --dist
        d["sum_over"] = self.total
        json.dump(d, sys.stdout, indent=self.indent)
        print ""


class DictStreamDistributionProcessor(DictStreamProcessor):
    def __init__(self, indent=None):
        self.dist = dict()
        self.total = 0
        self.indent = indent
        
    def main_process(self, obj):
        value = pickle.dumps(obj)
        self.key = tuple(obj.keys())
        if value in self.dist:
            self.dist[value] += 1
        else:
            self.dist[value] = 1
        self.total += 1

    def post_process(self):
        output = list()
        
        for k, v in self.dist.iteritems():
            d = pickle.loads(k)
            d["count"] = v
            d["total"] = self.total
            # d["fraction"] = v/self.total
            output.append(d)
        output.sort(key=lambda x: x["count"], reverse=True)

        for d in output:
            json.dump(d, sys.stdout, indent=self.indent)
            print ""


"""
Sleuth Utility Classes
"""


class SleuthTemplateDict(object):
    def __init__(self, elements):
        whitespace_pattern = re.compile(r'\s+')
        elements = re.sub(whitespace_pattern, '', elements)
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
                t += 'u\'' + x + '\':'
                needArg = True
        if needArg:
            t += "None"
        t += '}'
        #print "t: " + t
        return eval(t)

    def copy_selected_elements(self, tmplDict, obj):
        outDict = dict()
        for k, v in tmplDict.items():
            if k in obj:
                if isinstance(v, list):
                    obj_list = obj[k]
                    if obj_list:
                        outDict[k] = list()
                        for x in obj_list:
                            for y in v:
                                tmp = self.copy_selected_elements(y, x)
                                if tmp:
                                    outDict[k].append(tmp)
                        if not outDict[k]:
                            outDict = {}
                elif isinstance(v, dict):
                    tmp = self.copy_selected_elements(v, obj[k])
                    if tmp:
                        outDict[k] = tmp
                else:
                    if v:
                        if obj[k] == v:
                            outDict[k] = obj[k]
                    else:
                        outDict[k] = obj[k]
        if outDict:
            return outDict
        else:
            return None

    def get_selected_element(self, tmplDict, obj):
        outDict = dict()
        for k, v in tmplDict.items():
            if k in obj:
                if isinstance(v, list):
                    obj_list = obj[k]
                    if obj_list:
                        outDict[k] = list()
                        if v:
                            for x in obj_list:
                                for y in v:
                                    tmp = self.get_selected_element(y, x)
                                    if tmp:
                                        outDict[k].append(tmp)
                        else:
                            outDict[k] = obj[k] 
                        if not outDict[k]:
                            outDict = {}
                elif isinstance(v, dict):
                    tmp = self.get_selected_element(v, obj[k])
                    if tmp:
                        outDict[k] = tmp
                else:
                    if v:
                        if obj[k] == v:
                            outDict[k] = obj[k]
                    else:
                        outDict[k] = obj[k]
        if outDict:
            return outDict
        else:
            return None

    def normalize_selected_elements(self, tmplDict, obj):
        if not obj:
            return {}
        for k, v in tmplDict.items():
            if k in obj:
                if isinstance(v, list):
                    obj_list = obj[k]
                    if obj_list:
                        for x in obj_list:
                            for y in v:
                                self.normalize_selected_elements(y, x)
                elif isinstance(v, dict):
                    self.normalize_selected_elements(v, obj[k])
                else:
                    obj[k] = None
        return obj

    def apply_to_selected_elements(self, tmplDict, obj, func):
        if not obj:
            return {}
        for k, v in tmplDict.items():
            if k in obj:
                if isinstance(v, list):
                    obj_list = obj[k]
                    if obj_list:
                        for x in obj_list:
                            for y in v:
                                self.apply_to_selected_elements(y, x, func)
                elif isinstance(v, dict):
                    self.apply_to_selected_elements(v, obj[k], func)
                else:
                    obj[k] = func(obj[k])
        return obj

        
# fnmatch
# *	  matches everything
# ?       matches any single character
# [seq]	  matches any character in seq       *** DOES NOT WORK YET ***
# [!seq]  matches any character not in seq   *** DOES NOT WORK YET ***


class SimplePredicate(object):
    def __init__(self, elements):
        self.flowset = []
        if elements:
            tokens = re.split('([=<>~])', elements)
            self.template = SleuthTemplateDict(tokens[0])
            self.op = tokens[1]
            self.arg = tokens[2]

            if self.arg.isdigit():
                self.arg = int(self.arg)
            else:
                try:
                    self.arg = float(self.arg)
                except:
                    pass

            self.matchAll = False
        else:
            self.matchAll = True

    def eval(self, flow):
        # print 'flow: ' + str(flow)
        # print 'op: ' + str(self.op)
        # print 'arg: ' + str(self.arg)

        # If flow is list, match any element in it
        if isinstance(flow, list):
            listMatch = False
            if flow:
                for x in flow:
                    if isinstance(x, dict):
                        x = x.values()[0]
                        if self.eval(x):
                            listMatch = True
                    else:
                        if self.eval(x):
                            listMatch = True
            return listMatch
        elif isinstance(flow, dict):
            # print 'dict flow: ' + str(flow)
            x = flow.values()[0]
            return self.eval(x)

        if self.op == '=':
            if self.arg == '*':
                return True
            elif isinstance(self.arg, int):
                return self.arg == flow
            else:
                # print '------------------'
                # print 'flow: ' + str(flow)
                # print 'arg:  ' + str(self.arg)
                return fnmatch.fnmatch(flow, self.arg)
        elif self.op == '~':
            if self.arg == '*':
                return False
            elif isinstance(self.arg, int):
                return self.arg != flow
            else:
                return not fnmatch.fnmatch(flow, self.arg)
        elif self.op == '>':
            return flow > self.arg
        elif self.op == '<':
            return flow < self.arg

    def match(self, flow):
        if self.matchAll is True:
            return True
        else:
            output = self.template.get_selected_element(self.template.template, flow)
            if output:
                return self.eval(output.values()[0])
            else:
                if self.op == '~' and self.arg == '*':
                    # True because element is absent from flow
                    return True
                return False


class AndFilter:
    def __init__(self, L, R):
        self.L = L
        self.R = R

    def match(self, flow):
        return self.L.match(flow) & self.R.match(flow)


class OrFilter:
    def __init__(self, L, R):
        self.L = L
        self.R = R

    def match(self, flow):
        return self.L.match(flow) | self.R.match(flow)


def predicate_from_postfix(tokens):
    stack = list()

    for t in tokens:
        if t == ',':
            if len(stack) > 1:
                stack.append(AndFilter(stack.pop(), stack.pop()))
        elif t == '|':
            if len(stack) > 1:
                stack.append(OrFilter(stack.pop(), stack.pop()))
        else:
            stack.append(SimplePredicate(t))

    return stack.pop()


def infix_to_postfix(s):
    """
    Tokenize s into operators (',' or '|') and predicates, then
    convert token list to postfix output.
    :param s:
    :return:
    """
    # Operator precedence
    prec = {'|': 3, ',': 2, '(': 1}

    # Remove whitespace from input string
    s = s.replace(' ', '')

    stack = list()
    output = []
    for t in re.findall("[\w><=~.*\{\}\[\]?\-+]+|[\(,|\)]", s):
        if '>' in t or '<' in t or '=' in t or '~' in t:
            output.append(t)
        elif t == '(':
            stack.append(t)
        elif t == ')':
            topToken = stack.pop()
            while topToken != '(':
                output.append(topToken)
                topToken = stack.pop()
        else:
            while (not stack == []) and (prec[stack[-1]] >= prec[t]):
                output.append(stack.pop())
            stack.append(t)
    while stack:
        output.append(stack.pop())
    return output


class SleuthPredicate(object):
    def __init__(self, pred):
        if pred:
            self.pred = predicate_from_postfix(infix_to_postfix(pred))
        else:
            self.pred = None

    def match(self, flow):
        if self.pred:
            return self.pred.match(flow)
        else:
            return True


class SleuthFileType(object):
    def __init__(self, filename):
        self.filename = filename

    def is_gz(self):
        magic = "\x1f\x8b\x08"

        with open(self.filename) as f:
            data = f.read(len(magic))

            if data.startswith(magic):
                return True

        return False

    def is_bz2(self):
        magic = "\x42\x5a\x68"

        with open(self.filename) as f:
            data = f.read(len(magic))

            if data.startswith(magic):
                return True

        return False
