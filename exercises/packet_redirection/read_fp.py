#!/usr/bin/env python2

import os
import sys
from copy import deepcopy
from pprint import pprint

# Path of fingerprint database file
FP_PATH = 'p0f.fp'
# Used to calculate minimum TTL accepted for some signature
MAX_DIST = 35
# Prefix for each metadata field in P4 file
PREFIX = 'meta.p0f_metadata.'

class P0fDatabaseReader(object):
    def __init__(self):
        self.id_to_label_dict = {}  # For mapping an integer id to an OS label
        self.sig_list = _read_fp_file(self.id_to_label_dict)
        _assign_priorities(self.sig_list)

    def get_signature_list(self):
        '''
        Get a list of complete P0fSignature objects from a fingerprint
        database file.

        :return: A list of P0fSignature objects.
        '''
        return self.sig_list

    def id_to_label(self, id):
        '''
        :param: A string containing the name of a label
        :return: An int containing the integer id of the label
        '''
        return self.id_to_label_dict[id]

class P0fSignature(object):
    def __init__(self, label, label_id, match_fields, is_fuzzy=False):
        self.label = label
        self.label_id = label_id 
        self.is_generic = True if label.startswith('g:') else False
        self.is_fuzzy = is_fuzzy
        self.priority = 0
        self.match_fields = match_fields

    def get_match_fields_dict(self):
        '''
        :return: A dict containing all match fields for the table rule
                 corresponding to this P0fSignature object
        '''
        return self.match_fields.as_dict()

# store just information for the match fields of a table rule
# that correspond to one (fuzzy or non-fuzzy) p0f signature
class P0fRuleMatchFields(object):
    def __init__(self):
        self.ver = None
        self.ttl = None
        self.min_ttl = None
        self.olen = None
        self.mss = None
        self.wsize = None
        self.wsize_div_mss = None
        self.scale = None
        self.olayout = None
        self.quirk_df = 0
        self.quirk_nz_id = 0
        self.quirk_zero_id = 0
        self.quirk_ecn = 0
        self.quirk_nz_mbz = 0
        self.quirk_zero_seq = 0
        self.quirk_nz_ack = 0
        self.quirk_zero_ack = 0
        self.quirk_nz_urg = 0
        self.quirk_urg = 0
        self.quirk_push = 0
        self.quirk_opt_zero_ts1 = 0                   
        self.quirk_opt_nz_ts2 = 0
        self.quirk_opt_eol_nz = 0
        self.quirk_opt_exws = 0
        self.quirk_opt_bad = 0
        self.pclass = None

    def as_dict(self):
        '''
        :return: A dict containing all match fields for the table rule
                 corresponding to this P0fRuleMatchFields object
        '''
        match_fields_dict = {
            "ver": _set_ternary_field(self.ver, 4),
            "ttl": _set_range_field(self.min_ttl, self.ttl),
            "olen": self.olen,
            "mss": _set_ternary_field(self.mss, 16),
            "wsize": _set_ternary_field(self.wsize, 16),
            "wsize_div_mss": _set_ternary_field(self.wsize_div_mss, 16),
            "scale": _set_ternary_field(self.scale, 8),
            "olayout": self.olayout,
            "quirk_df": _set_ternary_field(self.quirk_df, 1),
            "quirk_nz_id": _set_ternary_field(self.quirk_nz_id, 1),
            "quirk_zero_id": _set_ternary_field(self.quirk_zero_id, 1),
            "quirk_ecn": _set_ternary_field(self.quirk_ecn, 1),
            "quirk_nz_mbz": self.quirk_nz_mbz,
            "quirk_zero_seq": self.quirk_zero_seq,
            "quirk_nz_ack": self.quirk_nz_ack,
            "quirk_zero_ack": self.quirk_zero_ack,
            "quirk_nz_urg": self.quirk_nz_urg,
            "quirk_urg": self.quirk_urg,
            "quirk_push": self.quirk_push,
            "quirk_opt_zero_ts1": self.quirk_opt_zero_ts1,      
            "quirk_opt_nz_ts2": self.quirk_opt_nz_ts2,
            "quirk_opt_eol_nz": self.quirk_opt_eol_nz,
            "quirk_opt_exws": self.quirk_opt_exws,
            "quirk_opt_bad": self.quirk_opt_bad,
            "pclass": 0
        }

        # filter out None values (wildcard) and append prefix
        formatted_dict = {(PREFIX+k): v \
                          for (k, v) in match_fields_dict.items() \
                          if v is not None}

        return formatted_dict


def _assign_priorities(signature_list):
    '''
    Assigns a priority to each signature in signature_list depending on
    the following factors:
    (1) if the signature is specific/generic
    (2) if the signature is fuzzy/non-fuzzy
    (3) the signature's position (line number) in the database relative
        to the other signatures

    :param signature_list: A list of P0fSignature objects
    :return:
    '''
    # Base priorities
    s_priority = 1  # Base priority for specific rules
    g_priority = len(signature_list) + 1  # Base priority for generic rules
    f_priority = 2*len(signature_list) + 1  # Base priority for fuzzy rules
    
    for sig in signature_list:
        # Determine priority
        if sig.is_generic:
            sig.priority = g_priority
            g_priority += 1
        elif sig.is_fuzzy:
            sig.priority = f_priority
            f_priority += 1
        else:
            sig.priority = s_priority
            s_priority += 1


def _process_match_fields(line_cleaned):
    '''
    Translate one line of the fingerprint database file containing one
    signature into a P0fRuleMatchFields object.
    
    :param line_cleaned: A line from the fingerprint database containing
                         one (non-fuzzy) signature
    :return: A tuple of type (P0fRuleMatchFields, bool) 
    '''
    # flag for if we have encountered a "bad_ttl"
    # (ttl ends in '-')
    bad_ttl = False
    
    line_sep_sig = line_cleaned.split('=', 1)
    if len(line_sep_sig) < 2:
        raise Exception('Malformed TCP SYN signature')
    
    # process signature
    sig_fields = line_sep_sig[1].strip().split(':')
    match_fields = P0fRuleMatchFields()

    # ver
    if sig_fields[0] != '*':
        if sig_fields[0] == '6':
            # IPv6 packets are currently not supported
            # TODO: write error message to log
            return None
        match_fields.ver = int(sig_fields[0])
        
    # ttl
    if sig_fields[1].endswith('-'):  # "bad_ttl"
        bad_ttl = True
        match_fields.ttl = int(sig_fields[1].split('-')[0])
        match_fields.min_ttl = 0
    else:
        ttl_operands = sig_fields[1].split('+')
        match_fields.ttl = sum(int(op) for op in ttl_operands)
        # see p0fv3.09b/fp_tcp.c:171
        match_fields.min_ttl = max(0, match_fields.ttl - MAX_DIST + 1)

    # olen
    match_fields.olen = int(sig_fields[2])
    
    # mss
    if sig_fields[3] != '*':
        match_fields.mss = int(sig_fields[3])

    # split wsize and scale fields
    wsize_scale = sig_fields[4].split(',')
    if len(wsize_scale) != 2:
        raise Exception('Malformed TCP SYN signature field: wsize,scale')
    
    # wsize / wsize_div_mss
    wsize = wsize_scale[0]
    
    # do nothing if wsize == '*' (wildcard)
    if wsize != '*':
        if '*' in wsize:
            # wsize field is expressed in the form 'mss*N' or 
            # 'mtu*N', where N is a constant
            wsize_fields = wsize.split('*')
            if len(wsize_fields) != 2:
                raise Exception('Malformed TCP SYN signature field: wsize')
            elif wsize_fields[0] != 'mss':
                if wsize_fields[0] == 'mtu':
                    # TODO: write error message to log
                    # 'Expressing wsize in the notation N*mtu, where N is'
                    return None
                    # 'a constant, is currently not supported'
                else:
                    raise Exception('wsize cannot be a multiple of some'
                                    'value other than MSS or MTU')
            else:
                match_fields.wsize_div_mss = int(wsize_fields[1])
        elif '%' in wsize:
            # the notation '%N', where N is a constant, is currently 
            # not supported 
            # TODO: write error message to log
            # 'Expressing wsize in the notation "%N",'
            # 'where N is a constant, is currently not'
            # 'supported'
            return None
        else:
            # TODO: regex match to ensure wsize can be cast to int?
            match_fields.wsize = int(wsize)
        
    # scale
    if wsize_scale[1] != '*':
        match_fields.scale = int(wsize_scale[1])
        
    # olayout
    olayout = 0
    olayout_entries = sig_fields[5].split(',')
    for option in olayout_entries:
        olayout = olayout << 4
        if option.startswith('eol'):
            eol_split = option.split('+', 1)
            if len(eol_split) != 2:
                raise Exception('End-of-line TCP option in olayout '
                                'field must be formatted as '
                                '"eol+n", where n represents bytes '
                                'of padding')
            # append the bytes of padding that follow eol option
            olayout = olayout << (4 * int(eol_split[1]))
        elif option == 'nop':
            olayout += 1
        elif option == 'mss':
            olayout += 2
        elif option == 'ws':
            olayout += 3
        elif option == 'sok':
            olayout += 4
        elif option == 'sack':
            olayout += 5
        elif option == 'ts':
            olayout += 8
        else:
            raise Exception('Unknown TCP option in olayout field of '
                            'signature')

    match_fields.olayout = olayout
        
    # quirks
    quirk_entries = sig_fields[6].split(',')
    for quirk in quirk_entries:
        if quirk == '':
            # no quirks
            continue
        elif quirk == 'df':
            match_fields.quirk_df = 1
        elif quirk == 'id+':
            match_fields.quirk_nz_id = 1
        elif quirk == 'id-':
            match_fields.quirk_zero_id = 1
        elif quirk == 'ecn':
            match_fields.quirk_ecn = 1
        elif quirk == '0+':
            match_fields.quirk_nz_mbz = 1
        elif quirk == 'flow':
            # ignore: IPv6 not supported
            continue
        elif quirk == 'seq-':
            match_fields.quirk_zero_seq = 1
        elif quirk == 'ack+':
            match_fields.quirk_nz_ack = 1
        elif quirk == 'ack-':
            match_fields.quirk_zero_ack = 1
        elif quirk == 'uptr+':
            match_fields.nz_urg = 1
        elif quirk == 'urgf+':
            match_fields.urg = 1
        elif quirk == 'pushf+':
            match_fields.quirk_push = 1
        elif quirk == 'ts1-':
            match_fields.quirk_opt_zero_ts1 = 1
        elif quirk == 'ts2+':
            match_fields.quirk_opt_nz_ts2 = 1
        elif quirk == 'opt+':
            match_fields.quirk_opt_eol_nz = 1
        elif quirk == 'exws':
            match_fields.quirk_opt_exws = 1
        elif quirk == 'bad':
            match_fields.quirk_opt_bad = 1
        else:
            raise Exception('Unknown quirk in quirks field of '
                            'fingerprint')
        
    # pclass
    match_fields.pclass = int(sig_fields[7])
    
    return (match_fields, bad_ttl)

def _read_fp_file(id_to_label_dict):
    '''
    Read in fingerprints from the fingerprint database file. Assign
    an id to each operating system label in the database file. Return
    a list of P0fSignature objects.
    
    :return: A list of P0fSignature objects
    '''
    # list of table entries
    signature_list = []
    
    # flag for when to start processing signatures
    # we only want to process signatures under the "[tcp:request]" label
    process_line = False
    
    # current OS label -- all signatures correspond to closest preceding OS 
    # label in the fingerprint file
    curr_label = ""
    curr_label_id = -1

    # read fingerprint file line-by-line
    with open(FP_PATH) as f:
        count = 0
        for line in f:
            # reached TCP SYN section: start processing signatures
            if line.strip() == '[tcp:request]':
                process_line = True
                continue

            # end of TCP SYN section: stop processing signatures
            elif line.startswith('['):
                process_line = False
                continue

            # not in TCP SYN section: do not process signatures
            if not process_line:
                continue

            # separate comments
            line_sep_comments = line.strip().split(';', 1)
            # skip empty lines
            if len(line_sep_comments) < 1:
                continue
            if line_sep_comments[0] == '':
                continue

            # clean line
            line_cleaned = line_sep_comments[0].strip()

            # line contains label
            if line_cleaned.startswith('label'):
                line_sep_label = line_cleaned.split('=', 1)
                if len(line_sep_label) < 2:
                    raise Exception('Malformed TCP SYN signature group label')
                # store label
                curr_label = line_sep_label[1].strip()
                if not (curr_label.startswith('g:')
                        or curr_label.startswith('s:')):
                    raise Exception('Cannot determine if signature group label'
                                    'is specific or generic')
                curr_label_id += 1
                id_to_label_dict[curr_label_id] = curr_label

            # line contains 'sys': describes expected operating systems for this
            # particular application label
            elif line_cleaned.startswith('sys'):
                line_sep_sys = line_cleaned.split('=', 1)
                if len(line_sep_sys) < 2:
                    raise Exception('Malformed TCP SYN signature group sys')
                # append to label
                curr_label += '/{}'.format(line_sep_sys[1].strip())

            # line contains signature
            elif line_cleaned.startswith('sig'):
                res = _process_match_fields(line_cleaned)
                if res:
                    (match_fields, bad_ttl) = res
                    # append signature object
                    sig_object = P0fSignature(curr_label,
                                              curr_label_id,
                                              match_fields)
                    signature_list.append(sig_object)

                    # check if we can add a fuzzy object
                    if (not sig_object.is_generic  # specific signature
                        and ((match_fields.quirk_df == 1
                              or match_fields.quirk_nz_id == 1
                              or match_fields.quirk_zero_id == 0
                              or match_fields.quirk_ecn == 0)  # fuzzy match quirks
                             or not bad_ttl)):  # fuzzy match ttl
                        fuzzy_match_fields = deepcopy(match_fields)

                        # set fuzzy quirks
                        # disappearing 'df'
                        fuzzy_match_fields.quirk_df = \
                            None if fuzzy_match_fields.quirk_df == 1 else 0
                        # disappearing 'id+'
                        fuzzy_match_fields.quirk_nz_id = \
                            None if fuzzy_match_fields.quirk_nz_id == 1 else 0
                        # appearing 'id-'
                        fuzzy_match_fields.quirk_zero_id = \
                            None if fuzzy_match_fields.quirk_zero_id == 0 else 1
                        # appearing 'ecn'
                        fuzzy_match_fields.quirk_ecn = \
                            None if fuzzy_match_fields.quirk_ecn == 0 else 1

                        # set fuzzy ttl
                        fuzzy_match_fields.ttl = None
                        fuzzy_match_fields.min_ttl = None

                        # append fuzzy signature
                        fuzzy_sig_object = P0fSignature(curr_label,
                                                        curr_label_id,
                                                        fuzzy_match_fields,
                                                        is_fuzzy=True)
                        signature_list.append(fuzzy_sig_object)

            else:
                raise Exception('Malformed line in TCP SYN section of '
                                'fingerprint file')

    return signature_list


def _set_range_field(min_value, max_value):
    '''
    Set a range field in the dictionary representation of a
    P0fRuleMatchFields object.

    :param min_value: The minimum int in the range
    :param max_value: The maximum int in the range
    :return: None if either min_value or max_value are None
             else a list containing the two parameters
    '''
    if (min_value is None) or (max_value is None):
        return None
    
    return [min_value, max_value]


def _set_ternary_field(value, size):
    '''
    Set a wildcard field in the dictionary representation of a
    P0fRuleMatchFields object.
    
    :param value: The value of the ternary field
                  If None, this field should be a wildcard
    :param size: The size of this field, in bits
    :return: None if value is None
             else a list of type [int, int]
    '''
    return None if (value is None) else [value, 2**size-1]


def main():
    reader = P0fDatabaseReader()
    signature_list = reader.get_signature_list()
    for sig in signature_list:
        sig_dict = vars(sig)
        sig_dict['match_fields'] = sig.get_match_fields_dict()
        pprint(sig_dict)

        
if __name__ == '__main__':
    main()
