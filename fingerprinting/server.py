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

        fps_ = fingerprinter.extract_fingerprints(dir_name + 'temp.pcap')

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
