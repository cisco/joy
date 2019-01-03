#!/usr/bin/python

"""
fingerprint_ui provides a bottle-based web UI to visualize TLS fingerprinting.

 *
 * Copyright (c) 2019 Cisco Systems, Inc.
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

import os
import tempfile
from sys import path

from bottle import route, run, template, static_file, view, request

path.append('../')
from fingerprinter import *


path_ = os.path.abspath(__file__)
dir_path = os.path.dirname(path_)


fingerprinter = Fingerprinter('resources/fingerprint_db.json.gz')

@route('/')
@route('/index')
def index():
    return template('index')

@route('/upload')
@view('upload')
def upload():
    return

fps_ = []
@route('/fingerprint')
@route('/fingerprint/<pcap_file>',method='POST')
def fingerprint(pcap_file=None):
    global fps_
    dir_name = None

    if pcap_file == 'upload' and request.files.get('upload') != None:
        upload = request.files.get('upload')
        dir_name = tempfile.mkdtemp()
        upload.save(dir_name + 'temp.pcap')

        fps_ = fingerprinter.extract_fingerprints([dir_name + 'temp.pcap'], detailed=True)

    # clean up temporary directories
    if dir_name != None and os.path.isdir(dir_name):
        os.removedirs(dir_name)

    return template('fingerprint', fps=fps_)


@route('/detailed_fp/<idx>')
def detailed_fp(idx=None):
    global fps_

    if int(idx) < len(fps_):
        return template('detailed_fp', fp_=fps_[int(idx)])


@route('/client_info/<client_ip>')
def client_info(client_ip):
    global fps_

    return template('client_info', client_info=fingerprinter.get_client_info(client_ip, fps_))


@route('/static/<filename:path>')
def send_static(filename):
    return static_file(filename, root=dir_path+'/static/')

run(host='localhost', port=8080)
