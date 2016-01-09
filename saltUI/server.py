'''
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
'''

from bottle import route, view, run, request, response, template
from data_parser import DataParser
from collections import OrderedDict
import cPickle as pickle
import operator
import colorsys
import numpy as np
import tempfile
import urllib2
import json
import math
import time
import os

import subprocess
import re

classifiers_to_display = []
classifier_names = []

paramserver = '' 
out_dir = '/var/p2f/'
count_flocap = 100
try:
    fp = open('../linux.cfg','r')
    for line in fp:
        if line.startswith("outdir"):
            out_dir = line.split()[2]
            if not out_dir.endswith(os.path.sep):
                out_dir += os.path.sep
        elif line.startswith("count"):
            count_flocap = int(line.split()[2])
except:
    out_dir = '/var/p2f/'

# read in ciphersutie information
fp = open('ciphersuites.txt','r')
ciphers = {}
for line in fp:
    tok = line.split()
    ciphers[tok[0]] = (tok[1],tok[2])
fp.close()

def getOrgName(ip):
    p = subprocess.Popen(['whois', ip], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    r = p.communicate()[0]

    sn = re.findall(r'country:\s?(.+)', r, re.IGNORECASE)
    country = ''
    if len(sn) > 0:
        country = sn[0].strip()

    sn = re.findall(r'OrgName:\s?(.+)', r, re.IGNORECASE)
    orgName = ''
    if len(sn) > 0:
        orgName = sn[0].strip()

    if orgName == '':
        sn = re.findall(r'org-name:\s?(.+)', r, re.IGNORECASE)
        if len(sn) > 0:
            orgName = sn[0].strip()
    if orgName == '':
        sn = re.findall(r'descr:\s?(.+)', r, re.IGNORECASE)
        if len(sn) > 0:
            orgName = sn[0].strip()

    return orgName + ', ' + country

@route('/')
@route('/home')
@view('home')
def home():
    return

@route('/contact')
@view('contact')
def contact():
    return

@route('/admin')
@view('admin')
def admin():
    return template('admin',flags=None)

@route('/update_malware')
@view('admin')
def update_malware():
    flag_splt = False
    try:
        response = urllib2.urlopen(paramserver + 'logreg_parameters.txt')
        html = response.read()
        tmp = {}
        if html != None:
            params = html.split()
            params = map((lambda x: float(x)), params)
            params = np.array(params)
            np.savetxt('logreg_parameters.txt',params)
            flag_splt = True
    except:
        flag_splt = False

    flag_bd = False
    try:
        response = urllib2.urlopen(paramserver + 'logreg_parameters_bd.txt')
        html = response.read()
        tmp = {}
        if html != None:
            params = html.split()
            params = map((lambda x: float(x)), params)
            params = np.array(params)
            np.savetxt('logreg_parameters_bd.txt',params)
            flag_bd = True
    except:
        flag_bd = False

    flags = {}
    flags['malware_splt'] = flag_splt
    flags['malware_bd'] = flag_bd

    return template('admin',flags=flags)

flows = {}
data = []
metadata = []

@route('/advancedInfo/<key>')
@view('advancedInfo')
def advancedInfo(key):
    (sa,da,sp,dp,splt,bd) = flows[key]
    sOrgName = getOrgName(sa)
    dOrgName = getOrgName(da)


    tmp = {}
    tmp['sOrgName'] = sOrgName
    tmp['dOrgName'] = dOrgName
    tmp['sa'] = sa
    tmp['da'] = da
    tmp['sp'] = sp
    tmp['dp'] = dp

    lns = []
    times = []
    dirs = []
    current = 0
    for tmp_dict in splt:
        if 'b' not in tmp_dict:
            continue
        lns.append(tmp_dict['b']/1500.0)
        if tmp_dict['dir'] == '>':
            dirs.append(1.0)
        else:
            dirs.append(-1.0)
        current += tmp_dict['ipt']
        times.append(current)

    tmp['lengths'] = lns
    tmp['times'] = times
    tmp['dirs'] = dirs
    if current == 0:
        current = 1
    tmp['total_time'] = current
    tmp['tmp'] = str(splt)

    if bd != None and max(bd) != 0:
        new_bd = []
#        bd = list(np.array(bd)/float(sum(bd)))
        bd = list(np.array(bd)/float(max(bd)))
        count = 0
        tmp_bd = []
        for b in bd:
            if b == 0:
#                tmp_bd.append('AAAAAA')
                tmp_bd.append('FFFFFF')
            else:
#                tmp_bd.append(getColor(b))
                tc = int(256-b*256)
                tch = hex(tc)[2:4]
                tmp_bd.append(tch*3)
            count += 1
            if count % 16 == 0:
                new_bd.append(tmp_bd)
                tmp_bd = []
        tmp['bd'] = new_bd
    else:
        new_bd = []
        bd = list(np.zeros(256))
        count = 0
        tmp_bd = []
        for b in bd:
            tmp_bd.append('FFFFFF')
            count += 1
            if count % 16 == 0:
                new_bd.append(tmp_bd)
                tmp_bd = []
        tmp['bd'] = new_bd

    return template('advancedInfo',info=tmp)

@route('/upload')
@view('upload')
def upload():
    return

def classify_samples(data, metadata):

    params = []
    for (name, t, param_1, param_2) in classifiers_to_display:
        if t == 'logreg':
            A = np.loadtxt(param_1)
            A_bd = np.loadtxt(param_2)

            b = A[0]
            w = A[1:]
            b_bd = A_bd[0]
            w_bd = A_bd[1:]

            params.append([t,b,w,b_bd,w_bd])
        elif t == 'mapping':
            params.append([t,param_1, param_2])
        else:
            continue

    results = []
    for i in range(len(data)):
        tmp_results = []
        for x in params:
            if x[0] == 'logreg':
                d = data[i]
                b = x[1]
                w = x[2]
                b_bd = x[3]
                w_bd = x[4]

                if len(d) == len(w) or (d[4]+d[5] < 100):
                    tmp = np.dot(d[0:207],w)
                    tmp += b
                else:
                    tmp = np.dot(d,w_bd)
                    tmp += b_bd

                tmp_results.append(round(1.0/(1.0+math.exp(min(-tmp,500))),2))
            elif x[0] == 'mapping':
                d = str(metadata[i][x[2]]) # 10=client_key_length, maybe refactor as dict
                if d in x[1]:
                    tmp_results.append(x[1][d])
                else:
                    tmp_results.append(x[1]['_'])
                    
            else:
                continue

        results.append(tmp_results)

    return results

lookup = {}
num_params = 207

def get_files_by_time(path):
    mtime = lambda f: os.stat(os.path.join(path, f)).st_mtime
    if os.path.exists(path) == False:
        return []
    else:
        return list(sorted(os.listdir(path), key=mtime))

def get_color(p):
    h = (1.0-p)*.4
    s = .9
    v = .9
    (r,g,b) = colorsys.hsv_to_rgb(h,s,v)
    red = str(hex(int(255.*r)))[2:]
    if len(red) == 1:
        if red == '0':
            red += '0'
        else:
            red = '0' + red
    green = str(hex(int(255.*g)))[2:]
    if len(green) == 1:
        if green == '0':
            green += '0'
        else:
            green = '0' + green
    blue = str(hex(int(255.*b)))[2:]
    if len(blue) == 1:
        if blue == '0':
            blue += '0'
        else:
            blue = '0' + blue
    return red + green + blue

@route('/results',method='POST')
@route('/results')
@view('results')
def results():
#def results(data={}):
    global flows
    global data
    global metadata
    global count_flocap
    global classifiers_to_display
    global classifier_names
        
    classifiers_to_display = []
    classifier_names = []
    display_fields = OrderedDict({})
    config_file = 'laui.cfg'
    fp = open(config_file,'r')
    for line in fp:
        if line.startswith('display_field'):
            tokens = line.split()
            display_fields[int(tokens[3])] = (tokens[1],tokens[2].replace('_',' '))
            continue
        elif line.strip() == '' or line.startswith('#') or not line.startswith('classifier'):
            continue
        tokens = line.split()
        if tokens[2] == 'logreg':
            classifiers_to_display.append((tokens[1], tokens[2], tokens[3], tokens[4]))
            classifier_names.append(tokens[1])
        elif tokens[2] == 'mapping':
            tmp_map = {}
            with open(tokens[4],'r') as fp2:
                for line2 in fp2:
                    tokens2 = line2.split()
                    tmp_map[tokens2[0]] = float(tokens2[1])
            classifiers_to_display.append((tokens[1], tokens[2], tmp_map, int(tokens[3])))
            classifier_names.append(tokens[1])
    fp.close()

    file_names = []
    is_upload = False
    if request.files.get('upload') != None:
#    if False:
        upload = request.files.get('upload')

        dir_name = tempfile.mkdtemp()
        upload.save(dir_name + 'temp.json')

        file_names.append(dir_name+'temp.json')
        is_upload = True
    else:
        tmp_files = get_files_by_time(out_dir)
        tmp_files.reverse()
        if len(tmp_files) > 0:
            file_names.append(out_dir+tmp_files[0])
        if len(tmp_files) > 1:
            file_names.append(out_dir+tmp_files[1])
        if len(tmp_files) > 2:
            file_names.append(out_dir+tmp_files[2])
        if len(tmp_files) > 3:
            file_names.append(out_dir+tmp_files[3])
        if len(tmp_files) > 4:
            file_names.append(out_dir+tmp_files[4])
        if len(tmp_files) > 5:
            file_names.append(out_dir+tmp_files[5])

    start_time = time.time()
    data = []
    metadata = []
    total_flows = 0
    for f in file_names:

        try: # just a robustness check
            parser = DataParser(f)
            tmpBD = parser.getByteDistribution()
            tmpIPT = parser.getIndividualFlowIPTs()
            tmpPL = parser.getIndividualFlowPacketLengths()
            tmp,tmp_m = parser.getIndividualFlowMetadata()
        except:
            continue
#        flows += parser.advancedInfo
        if parser.advancedInfo == None:
            continue
        for k in parser.advancedInfo:
            flows[k] = parser.advancedInfo[k]

        if tmp != None and tmpPL != None and tmpIPT != None:
            for i in range(len(tmp)):
                tmp_data = []
                tmp_data.extend(tmp[len(tmp)-i-1])
                tmp_data.extend(tmpPL[len(tmp)-i-1])
                tmp_data.extend(tmpIPT[len(tmp)-i-1])
                tmp_data.extend(tmpBD[len(tmp)-i-1])

                # nga issue, will fix when pcaps start flowing again
                if tmp_data[2] == 0 and tmp_data[4] > 0:
                    continue
                if tmp_data[3] == 0 and tmp_data[5] > 0:
                    continue

#                if len(tmp_data) != num_params:
#                    continue
                data.append(tmp_data)
                metadata.append(tmp_m[len(tmp)-i-1])
                total_flows += 1

                if total_flows == count_flocap*2 and not is_upload:
                    break
        if total_flows == count_flocap*2 and not is_upload:
            break

    if request.files.get('upload') != None:
        os.removedirs(dir_name)

    results = classify_samples(data, metadata)

    lhost = {}
    for i in range(len(metadata)):
        if metadata[i][0] not in lhost:
            lhost[metadata[i][0]] = 1
        else:
            lhost[metadata[i][0]] += 1
    sorted_lhost = sorted(lhost.items(), key=operator.itemgetter(1))
    sorted_lhost.reverse()
    if len(sorted_lhost) > 0:
        (lh,_) = sorted_lhost[0]
    else:
        lh = None

    tmp = []
    to_display = []
    to_display_names = []
    for key in display_fields:
        to_display_names.append(display_fields[key])
    for i in range(len(results)):
        color = []
        for j in range(len(results[i])):
            color.append(get_color(results[i][j]))

        s_orgName = ''
        d_orgName = ''
        if metadata[i][0] == lh:
            s_orgName = 'localhost'
        if metadata[i][1] == lh:
            d_orgName = 'localhost'

        tmp_to_display = []
        for key in display_fields:
            tmp_to_display.append(metadata[i][key])

        tmp.append((results[i],metadata[i][0],metadata[i][1],metadata[i][2],metadata[i][3],metadata[i][4],metadata[i][5],metadata[i][6],metadata[i][7],color,s_orgName,d_orgName,metadata[i][8],tmp_to_display))
    end_time = time.time()-start_time
    tmp = sorted(tmp,key=lambda x: x[0])
    tmp.reverse()

    return template('results',results=tmp,num_flows=len(results),t=end_time,classifier_names=classifier_names,
                    to_display_names=to_display_names)

@route('/devices',method='POST')
@route('/devices')
@view('devices')
def devices():
    global flows
    global data
    global metadata
    global count_flocap
    global classifiers_to_display
    global classifier_names

    classifiers_to_display = []
    classifier_names = []
    display_fields = OrderedDict({})
    config_file = 'laui.cfg'
    fp = open(config_file,'r')
    for line in fp:
        if line.startswith('display_field'):
            tokens = line.split()
            display_fields[int(tokens[3])] = (tokens[1],tokens[2].replace('_',' '))
            continue
        elif line.strip() == '' or line.startswith('#') or not line.startswith('classifier'):
            continue
        tokens = line.split()
        if tokens[2] == 'logreg':
            classifiers_to_display.append((tokens[1], tokens[2], tokens[3], tokens[4]))
            classifier_names.append(tokens[1])
        elif tokens[2] == 'mapping':
            tmp_map = {}
            with open(tokens[4],'r') as fp2:
                for line2 in fp2:
                    tokens2 = line2.split()
                    tmp_map[tokens2[0]] = float(tokens2[1])
            classifiers_to_display.append((tokens[1], tokens[2], tmp_map, int(tokens[3])))
            classifier_names.append(tokens[1])
    fp.close()

    subnet = '10.0.2.'
    devices_ = {}

    file_names = []
    is_upload = False
    if request.files.get('upload') != None:
        upload = request.files.get('upload')

        dir_name = tempfile.mkdtemp()
        upload.save(dir_name + 'temp.json')

        file_names.append(dir_name+'temp.json')
        is_upload = True
    else:
        tmp_files = get_files_by_time(out_dir)
        tmp_files.reverse()
        if len(tmp_files) > 0:
            file_names.append(out_dir+tmp_files[0])
        if len(tmp_files) > 1:
            file_names.append(out_dir+tmp_files[1])
        if len(tmp_files) > 2:
            file_names.append(out_dir+tmp_files[2])
        if len(tmp_files) > 3:
            file_names.append(out_dir+tmp_files[3])
        if len(tmp_files) > 4:
            file_names.append(out_dir+tmp_files[4])
        if len(tmp_files) > 5:
            file_names.append(out_dir+tmp_files[5])

    start_time = time.time()
    data = []
    metadata = []
    total_flows = 0
    for f in file_names:
        try: # just a robustness check
            parser = DataParser(f)
            tmpBD = parser.getByteDistribution()
            tmpIPT = parser.getIndividualFlowIPTs()
            tmpPL = parser.getIndividualFlowPacketLengths()
            tmp,tmp_m = parser.getIndividualFlowMetadata()
        except:
            continue
#        flows += parser.advancedInfo
        if parser.advancedInfo == None:
            continue
        for k in parser.advancedInfo:
            flows[k] = parser.advancedInfo[k]

        if tmp != None and tmpPL != None and tmpIPT != None:
            for i in range(len(tmp)):
#                if not parser.flows['appflows'][i]['flow']['sa'].startswith(subnet) and \
#                   not parser.flows['appflows'][i]['flow']['da'].startswith(subnet):
#                    continue
                tmp_id = ''
                if tmp_m[len(tmp)-i-1][0].startswith(subnet):
                    tmp_id = tmp_m[len(tmp)-i-1][0]
                elif tmp_m[len(tmp)-i-1][1].startswith(subnet):
                    tmp_id = tmp_m[len(tmp)-i-1][1]
                else:
                    continue

                tmp_data = []
                tmp_data.extend(tmp[len(tmp)-i-1])
                tmp_data.extend(tmpPL[len(tmp)-i-1])
                tmp_data.extend(tmpIPT[len(tmp)-i-1])
                tmp_data.extend(tmpBD[len(tmp)-i-1])

                data.append(tmp_data)
                metadata.append(tmp_m[len(tmp)-i-1])
                total_flows += 1

                if total_flows == count_flocap*2 and not is_upload:
                    break
        if total_flows == count_flocap*2 and not is_upload:
            break

    if request.files.get('upload') != None:
        os.removedirs(dir_name)

    results = classify_samples(data, metadata)

    tmp = {}
    to_display = []
    to_display_names = []
    for key in display_fields:
        to_display_names.append(display_fields[key])
    for i in range(len(results)):
        color = []
        for j in range(len(results[i])):
            color.append(get_color(results[i][j]))

        tmp_id = ''
        if metadata[i][0].startswith(subnet):
            tmp_id = metadata[i][0]
        elif metadata[i][1].startswith(subnet):
            tmp_id = metadata[i][1]
        else:
            continue

        tmp_to_display = []
        for key in display_fields:
            tmp_to_display.append(metadata[i][key])

        if tmp_id not in devices_:
            devices_[tmp_id] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            tmp[tmp_id] = []
        devices_[tmp_id][0] += 1 # total flows

        if metadata[i][9] in ciphers:
            (name_, rec_) = ciphers[metadata[i][9]]
            if rec_ == 'RECOMMENDED':
                devices_[tmp_id][1] += 1
            elif rec_ == 'LEGACY':
                devices_[tmp_id][2] += 1
            elif rec_ == 'AVOID':
                devices_[tmp_id][3] += 1

        if metadata[i][10] != -1:
            devices_[tmp_id][metadata[i][12]+4] += 1

        tmp[tmp_id].append((results[i],metadata[i][0],metadata[i][1],metadata[i][2],metadata[i][3],metadata[i][4],metadata[i][5],metadata[i][6],metadata[i][7],color,'','',metadata[i][8],tmp_to_display))

    return template('devices',devices=devices_,subnet=subnet+'*',results=tmp,num_flows=len(results),classifier_names=classifier_names,
                    to_display_names=to_display_names)


## specifically to work with the julia NN classifier
@route('/windows',method='POST')
@route('/windows')
@view('windows')
def windows():
    global data
    global metadata
    global count_flocap
    global classifiers_to_display
    global classifier_names

    classifiers_to_display = []
    classifier_names = []
    display_fields = OrderedDict({})
    config_file = 'laui.cfg'
    fp = open(config_file,'r')
    for line in fp:
        if line.startswith('display_field'):
            tokens = line.split()
            display_fields[int(tokens[3])] = (tokens[1],tokens[2].replace('_',' '))
            continue
        elif line.strip() == '' or line.startswith('#') or not line.startswith('classifier'):
            continue
    fp.close()

    subnet = '10.0.2.'

    file_names = []
    is_upload = False
    if request.files.get('upload') != None:
        upload = request.files.get('upload')

        dir_name = tempfile.mkdtemp()
        upload.save(dir_name + 'temp.json')

        file_names.append(dir_name+'temp.json')
        is_upload = True
    else:
        tmp_files = get_files_by_time(out_dir)
        tmp_files.reverse()
        if len(tmp_files) > 0:
            file_names.append(out_dir+tmp_files[0])
        if len(tmp_files) > 1:
            file_names.append(out_dir+tmp_files[1])

    start_time = time.time()
    flows_nn = []
    devices = {}
    for f in file_names:
        try: # just a robustness check
            data = ""
            with open(f,'r') as fp:
                for line in fp:
                    if "\"hd\"" in line:
                        continue
                    data += line.strip().replace('"x": i','"x": "i"').replace('"x": a','"x": "a"')
            try:
                tmp_flows = json.loads(data)
            except:
                if not data.endswith("] }"):
                    data += "] }"
                tmp_flows = json.loads(data)
        except:
            continue

        # organize flows in convenient way
        for tmp_f in tmp_flows['appflows']:
            if tmp_f['flow']['sa'] in devices:
                devices[tmp_f['flow']['sa']].append((tmp_f['flow']['ts'],tmp_f))
            else:
                devices[tmp_f['flow']['sa']] = [(tmp_f['flow']['ts'],tmp_f)]
            if tmp_f['flow']['da'] in devices:
                devices[tmp_f['flow']['da']].append((tmp_f['flow']['ts'],tmp_f))
            else:
                devices[tmp_f['flow']['da']] = [(tmp_f['flow']['ts'],tmp_f)]
            

    if request.files.get('upload') != None:
        os.removedirs(dir_name)


    results = []
    # find flows that belong to the same device, same 5 minute window
    for d in devices:
        devices[d].sort()
        times, flows = zip(*devices[d])
        cur_time = times[0] # time is in ms
        next_time = cur_time + 150000 # sliding window of 2.5 minutes
        cur_window = []
        next_window = []
        i = 0
        while i < len(times):
            if times[i] > next_time and times[i] < next_time + 300000: # five minute window
                next_window.append(flows[i])
            if times[i] < cur_time + 300000: # five minute window
                cur_window.append(flows[i])
            else: # classify and flush window
                # as julia classify.jl input_json output_json 
                dir_name = tempfile.mkdtemp()
                tmp_json = {}
                tmp_json['appflows'] = cur_window

                with open(dir_name + '/tmp.json','wb') as fp:
                    json.dump(tmp_json, fp, indent=4, separators=(',', ': '))

                subprocess.call(["julia","julia_classifier/classify.jl",dir_name+"/tmp.json",dir_name+"/tmp_o.json"])

                with open(dir_name + '/tmp_o.json','rb') as fp:
                    tmp_results = json.load(fp)
                    for tmp in tmp_results:
                        results.append((tmp['output'],tmp['ip'],tmp['flows']))

                os.removedirs(dir_name)

                cur_window = next_window
                cur_time = next_time
                next_window = []
                next_time = cur_time + 150000
                
            i += 1

        # clean up to make sure we don't miss anything
        dir_name = tempfile.mkdtemp()
        tmp_json = {}
        tmp_json['appflows'] = cur_window
        with open(dir_name + '/tmp.json','wb') as fp:
            json.dump(tmp_json, fp, indent=4, separators=(',', ': '))
        subprocess.call(["julia","julia_classifier/classify.jl",dir_name+"/tmp.json",dir_name+"/tmp_o.json"])
        with open(dir_name + '/tmp_o.json','rb') as fp:
#        with open('julia_classifier/output.json','rb') as fp:
            tmp_results = json.load(fp)
            for tmp in tmp_results:
                results.append((tmp['output'],tmp['ip'],tmp['flows']))
#        os.removedirs(dir_name)
#        break
#    devices[str(results)]
    results.sort()
    results.reverse()
    return template('windows',results=results)

run(host='localhost', port=8080, debug=True)
#run(host='192.168.0.96', port=80, debug=True)


