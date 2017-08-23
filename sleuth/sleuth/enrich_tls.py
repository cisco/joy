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


# It should be noted that this is a soft check on whether or not the selected
# cipher suite would be acceptable to the specified compliance policy
#
def check_compliance(compliance_policy, scs):
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


# This function builds a list of parameters that will correspond to values
# in the JSON policy. This consolidates the list of certs and the selected
# cipher suite attributes into one list that can be processed in tls_seclevel
#
def build_iterable_params(params, client_key_length, certs):
    iterable_params = []
    for each in params:
        param = {}
        if each == "desc":
            continue
        elif each == "kex" and client_key_length:
            param["secondary_param"] = "client_key_length"
            param["secondary_value"] = client_key_length
        param["primary_param"] = each
        param["primary_value"] = params[each]
        iterable_params.append(param)
    
    if certs:
        for each in certs:
            param["primary_param"] = "sig_alg"
            param["primary_value"] = each["sig_alg"]
            param["secondary_param"] = "sig_key_size"
            param["secondary_value"] = each["sig_key_size"]
            iterable_params.append(param)
        
    return iterable_params
    
# This function opens the policy file, consolidates the certs (if they exist)
# with the selected cipher suite attributes, and analyzes the minimum
# security level of the flows
#
def tls_seclevel(policy, unknowns, scs, client_key_length, certs):
    if not scs:
        return 'unknown'

    cur_dir = os.path.dirname(__file__)
    data_file = "data_tls_params.json"
    data_path = os.path.join(cur_dir, data_file)

    with open(data_path) as f:
        data = json.load(f)
        params = data["tls_params"][scs]
        seclevel_inventory = {}
        concerns = []

        # consolidate parameters so that they have a consistent architecture to
        # be compared to the policy in the JSON file
        iterable_params = build_iterable_params(params, client_key_length, certs)
    
        # loop through the items that need to be evaluated against the policy
        for attr in iterable_params:
            current_seclevel = None
            current_policy = policy.rules[attr["primary_param"]]
            if current_policy[attr["primary_value"]]:
                policy_value = current_policy[attr["primary_value"]]
                # if the policy value is a raw seclevel, assign the seclevel
                # and move on
                if isinstance(policy_value, int):
                    current_seclevel = policy_value
                # else, we know it is an object with further attributes needed
                # to accurately asses seclevel
                else:
                    if "secondary_param" in attr:
                        if attr["secondary_param"] in policy_value:
                            attribute = policy_value[attr["secondary_param"]]
                            
                            value = str(attr["secondary_value"])
                            # the operator tells us how to compare each value with
                            # the value in the policy
                            if 'operator' in attribute:
                                op = OPS[attribute['operator']]
                                del attribute['operator']
                            else:
                                op = OPS['default']
                            
                            # now check each value in the policy using the operator
                            # to ensure that the best fit seclevel is chosen
                            for each in attribute:
                                if op(int(value), int(each)):
                                    temp_seclevel = attribute[each]
                                    if not current_seclevel or op(temp_seclevel, current_seclevel):
                                        current_seclevel = temp_seclevel
                    else:
                        current_seclevel = policy_value["default"]
                        
            else:
                current_seclevel = UNKNOWN
            
            # build a list of items whose seclevel falls below the failure_threshold
            # and the value that caused the failure
            if current_seclevel <= policy.failure_threshold:
                concerns.append(attr["primary_param"] + ": " + attr["primary_value"])
            seclevel_inventory[attr["primary_param"]] = current_seclevel

        # fetch min seclevel element based on whether or not 'unknown' elements should be reported.
        # default here is 'report'
        #
        if unknowns == "ignore":
            seclevel_floor = min([ v for k, v in seclevel_inventory.iteritems() if v != UNKNOWN])
        else:
            seclevel_floor = min(seclevel_inventory.values())

        classification = policy.seclevel(seclevel_floor)
 
        if not concerns:
            return classification
        else:
            return { "classification": classification,
                     "concerns": concerns }


def enrich_tls(flow, kwargs):
    if 'tls' not in flow:
        return None
    else:
        # Get security-relevant parameters from flow record
        tls = flow['tls']

        if 'tls_client_key_length' in tls:
            # Subtract 16 encoding bits
            client_key_length = tls['tls_client_key_length'] - 16
        else:
            client_key_length = None

        if 's_tls_ext' in tls:
            server_extensions = tls['s_tls_ext']
        else:
            server_extensions = None

        if 'scs' in tls:
            scs = tls['scs']
        else:
            scs = None

        if 'server_cert' in tls:
            certs = list()
            for x in tls['server_cert']:
                tmp = dict()
                tmp['sig_alg'] = x['signature_algorithm']
                tmp['sig_key_size'] = x['signature_key_size']
                tmp['issuer'] = x['issuer']
                certs.append(tmp)
        else:
            certs = None

        seclevel_policy = Policy(kwargs["policy_file"], kwargs["failure_threshold"])

        tls_sec_info = {}
        tls_sec_info["seclevel"] = tls_seclevel(seclevel_policy, kwargs["unknowns"], scs, client_key_length, certs)

        # if compliance argument was passed, assess and add to tls_sec_info object.
        # It should be noted that this is a soft check on whether or not the selected
        # cipher suite would be acceptable to the specified compliance policy
        #
        if kwargs["compliance"]:
            for policy in kwargs["compliance"]:
                tls_sec_info[policy + "_compliant"] = check_compliance(policy, scs)

        return tls_sec_info
