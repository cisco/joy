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
import os
import json
from sleuth import SleuthTemplateDict

class fingerprinter(object):
    fingerprint_dict = {
        'tls': {
            'select': 'tls{c_extensions,cs}',
            'normalize': 'tls{c_extensions[{server_name,signed_certificate_timestamp,session_ticket,padding,application_layer_protocol_negotiation,data}]}'
        },
        'http': {
            'select': 'http[{out[{User-Agent}]}]',
            'normalize': ''
        },
        'tcp': {
            'select': 'tcp{out{opt_len,opts}}',
            'normalize': 'tcp{out{opts[{ts}]}}'
        },
    }
        
    def __init__(self, select, normalize):
        self.select_template = SleuthTemplateDict(select)
        self.normalize_template = SleuthTemplateDict(normalize)

    def get_fingerprint(self, flow, kwargs):
        tmp = self.select_template.copy_selected_elements(self.select_template.template, flow)
        output = self.normalize_template.normalize_selected_elements(self.normalize_template.template, tmp)
        return output

    @classmethod
    def types(cls):
        return cls.fingerprint_dict
        
    @classmethod
    def get_instance(cls, typename):
        return fingerprinter(**cls.fingerprint_dict[typename])
