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
import operator

UNKNOWN = 0
INVALID = 1
VALID = 2

unknowns = 'report'

OPS = {
    "<": operator.lt,
    "<=": operator.le,
    "default": operator.eq,
    ">": operator.gt,
    ">=": operator.ge
}


class Policy:
    "Class to import seclevel policy"

    def __init__(self, filename, failure_threshold):
        cur_dir = os.path.dirname(__file__)
        policy_path = os.path.join(cur_dir, filename)
        with open(policy_path) as f:
            policy_data = json.load(f)
            self.classifications = policy_data["classification"]
            self.rules = policy_data["rules"]
            self.failure_threshold = int(failure_threshold) if failure_threshold else policy_data["default_failure_threshold"]
            self.trusted_ca_list = policy_data["trusted_ca_list"]
            self.min_seclevel = min(self.classifications.values())
            self.max_seclevel = max(self.classifications.values())

    def seclevel(self, x):
        for classification, value in self.classifications.iteritems():
            if x == value:
                return classification
        return "unknown"


def check_compliance(compliance_policy, scs):
    """
    It should be noted that this is a soft check on whether or not the selected
    cipher suite would be acceptable to the specified compliance policy
    """
    if not scs:
        return 'unknown'

    if not compliance_policy:
        return 'unknown'

    cur_dir = os.path.dirname(__file__)
    check_data_file = "data_tls_params.json"
    check_data_path = os.path.join(cur_dir, check_data_file)

    compliance_data_file = "compliance.json"
    compliance_data_path = os.path.join(cur_dir, compliance_data_file)

    with open(check_data_path) as check_f:
        with open(compliance_data_path) as compliance_f:
            check_data = json.load(check_f)
            compliance_data = json.load(compliance_f)

            if compliance_policy not in compliance_data:
                return "unknown - undefined policy"
            else:
                scs_desc = check_data["tls_params"][scs]["desc"]
                return "yes" if scs_desc in compliance_data[compliance_policy] else "no"

    return "error loading file"
    
    
def audit_certs_issuer(certs, trusted_ca_list):
    """
    As implemented now, we will get the tls certs in order, the root cert is at the end. We check to see if the issuer
    is in our trusted_ca_list; if not, we report it as a concern
    """
    try:
        org_name = certs[-1]['issuer']['organizationName']
    except KeyError:
        return None
    
    if org_name not in trusted_ca_list:
        return 'CA not trusted: ' + org_name

    return None


def get_seclevel_with_param(policy, attr, value, param):
    """
    This funciton evaluates the seclevel of a crypto attribute that has conditions, such as key-exchange which
    can assign a different seclevel based on key size

    :param policy: the policy object containing seclevel rules
    :param attr: the crypto attribute to evaluate against the policy
    :param value: value of the attribute
    :param param: the additional paramter that dictates a more specific secelevel
    :return: integer value of seclevel
    """
    current_seclevel = None

    if param == None:
        return policy.rules[attr][value]["default"]

    if attr == "kex":
        param_rules = policy.rules[attr][value]["client_key_length"]
    elif attr == "cert_sig_alg":
        param_rules = policy.rules[attr][value]["sig_key_size"]

    try:
        op = OPS[param_rules['operator']]
    except KeyError:
        op = OPS['default']

    # now check each value in the policy using the operator to ensure that the best fit seclevel is chosen
    for each in param_rules:
        if each == 'operator':
            continue
        if op(param, int(each)):
            temp_seclevel = param_rules[each]
            if not current_seclevel or op(temp_seclevel, current_seclevel):
                current_seclevel = temp_seclevel

    # if we make it through each value in the policy attribute and compare with the defined operator, but seclevel
    # is still undefined, the number is more stringent than the policy defines, so is assigned max_seclevel
    if not current_seclevel:
        current_seclevel = policy.max_seclevel

    return current_seclevel


def get_certs_seclevel(policy, certs):
    """
    This function analyzes the minimum security level for the certs found in the tls flow
    based on the supplied policy

    :param policy: the policy object containing seclevel rules
    :param certs: the certs list containing crypto and issuer info
    :return: integer value of seclevel, minimum of evaluated certs
    """
    certs_seclevels = []
    concerns = []

    if certs:
        for index, cert in enumerate(certs):
            current_seclevel = UNKNOWN

            if 'cert_sig_alg' in policy.rules:
                sig_rules = policy.rules['cert_sig_alg']

                if cert['cert_sig_alg'] in sig_rules:
                    current_seclevel = get_seclevel_with_param(policy, 'cert_sig_alg', cert['cert_sig_alg'], cert['sig_key_size'])

            if current_seclevel <= policy.failure_threshold:
                concern_string = "cert_sig_alg - " + cert['cert_sig_alg'] + " sig_key_size " + str(cert['sig_key_size']) + " in cert " + str(index)
                concerns.append(concern_string)

            certs_seclevels.append(current_seclevel)

        # fetch min seclevel element based on whether or not 'unknown' elements should be reported.
        # default here is 'report'
        if unknowns == "ignore":
            certs_seclevel_floor = min([x for x in certs_seclevels if x != UNKNOWN])
        else:
            certs_seclevel_floor = min(certs_seclevels)

        ca_result = audit_certs_issuer(certs, policy.trusted_ca_list)
        if ca_result:
            concerns.append(ca_result)

    else:
        certs_seclevel_floor = None
        concerns.append('no certs data')

    return certs_seclevel_floor, concerns


def get_scs_seclevel(policy, scs, client_key_length):
    """
    This function grabs the scs from the reference file and analyzes the minimum security level
    for the selected cipher suite of the flows based on the supplied policy

    :param policy: the policy object containing seclevel rules
    :param scs: the hex code of the selected cipher suite
    :param client_key_length: the int value of the key exchange key length
    :return: integer value of seclevel, minimum of evaluated scs params
    """
    if not scs:
        return 'unknown', []

    cur_dir = os.path.dirname(__file__)
    data_file = "data_tls_params.json"
    data_path = os.path.join(cur_dir, data_file)

    with open(data_path) as f:
        data = json.load(f)
        params = data["tls_params"][scs]
        seclevel_inventory = {}
        concerns = []

        # loop through the items that need to be evaluated against the policy
        for alg_type, alg_value in params.iteritems():
            if alg_type == "desc":
                continue

            current_seclevel = UNKNOWN

            if alg_type in policy.rules:
                if alg_value in policy.rules[alg_type]:
                    if alg_type == "kex":
                        current_seclevel = get_seclevel_with_param(policy, alg_type, alg_value, client_key_length)
                    else:
                        current_seclevel = policy.rules[alg_type][alg_value]

            # build a list of items whose seclevel falls below the failure_threshold
            # and the value that caused the failure
            if current_seclevel <= policy.failure_threshold:
                concern_string = alg_type + " - " + alg_value
                if alg_type == "kex":
                    concern_string += " client_key_length " + str(client_key_length)
                concerns.append(concern_string)
            seclevel_inventory[alg_type] = current_seclevel

        # fetch min seclevel element based on whether or not 'unknown' elements should be reported.
        # default here is 'report'
        if unknowns == "ignore":
            seclevel_floor = min([v for k, v in seclevel_inventory.iteritems() if v != UNKNOWN])
        else:
            seclevel_floor = min(seclevel_inventory.values())

        return seclevel_floor, concerns


def enrich_tls(flow, kwargs):
    if 'tls' not in flow:
        return None

    tls = flow['tls']

    # Client key length
    try:
        # Subtract 16 encoding bits
        client_key_length = tls['c_key_length'] - 16
    except KeyError:
        client_key_length = None

    # Server extensions
    try:
        server_extensions = tls['s_extensions']
    except KeyError:
        server_extensions = None

    # Selected cipher suite
    try:
        scs = tls['scs']
    except KeyError:
        scs = None

    if 's_cert' in tls:
        certs = list()
        for x in tls['s_cert']:
            tmp = dict()
            tmp['cert_sig_alg'] = x['signature_algo']
            tmp['sig_key_size'] = x['signature_key_size']
            tmp['issuer'] = x['issuer']
            certs.append(tmp)
    else:
        certs = None

    seclevel_policy = Policy(kwargs["policy_file"], kwargs["failure_threshold"])
    unknowns = kwargs["unknowns"]

    certs_seclevel, certs_concerns = get_certs_seclevel(seclevel_policy, certs)
    scs_seclevel, scs_concerns = get_scs_seclevel(seclevel_policy, scs, client_key_length)

    tls_sec_info = {}
    concerns = certs_concerns + scs_concerns
    seclevels = [ certs_seclevel, scs_seclevel ]

    classification = seclevel_policy.seclevel(min(x for x in seclevels if x is not None))

    if not concerns:
        tls_sec_info["seclevel"] = classification
    else:
        tls_sec_info["seclevel"] = { "classification": classification,
                                           "concerns": concerns }

    # if compliance argument was passed, assess and add to tls_sec_info. It should be noted that this is a soft
    # check on whether or not the selected cipher suite would be acceptable to the specified compliance policy
    #
    if kwargs["compliance"]:
        for policy in kwargs["compliance"]:
            tls_sec_info[policy + "_compliant"] = check_compliance(policy, scs)

    return tls_sec_info
