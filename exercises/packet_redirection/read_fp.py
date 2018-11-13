#!/usr/bin/env python2

import os
import sys
import pprint

# Path of fingerprint database file
FP_PATH = 'p0f.fp'
# Used to calculate minimum TTL accepted for some signature
MAX_DIST = 35

class P0fSignature(object):
    def __init__(self, label):
        self.label = label
	self.is_generic = True if label.startswith('g:') else False

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


def read_fp_file():
    # list of table entries
    signature_list = []
    
    # flag for when to start processing signatures
    # we only want to process signatures under the "[tcp:request]" label
    process_line = False
    
    # current OS label -- all signatures correspond to closest preceding OS 
    # label in the fingerprint file
    curr_label = ""

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
            if not len(line_sep_comments):
                continue
            if line_sep_comments[0] == '':
                continue

            # clean line
            line_cleaned = line_sep_comments[0].strip()

            # line contains label
            if line_cleaned.startswith('label'):
                line_sep_label = line_cleaned.split('=', 1)
                if not len(line_sep_label):
                    # TODO: replace with error message in log
                    raise Exception('Malformed TCP SYN signature group label')
                # store label
                curr_label = line_sep_label[1].strip()
                if not (curr_label.startswith('g:')
                        or curr_label.startswith('s:')):
                    raise Exception('Cannot determine if signature group label'
                                    'is specific or generic')

            # line contains 'sys': describes expected operating systems for this
            # particular application label
            elif line_cleaned.startswith('sys'):
                line_sep_sys = line_cleaned.split('=', 1)
                if not len(line_sep_sys):
                    # TODO: replace with error message in log
                    raise Exception('Malformed TCP SYN signature group sys')
                # append to label
                curr_label += '/{}'.format(line_sep_sys[1].strip())

            # line contains signature
            elif line_cleaned.startswith('sig'):
                sig_object = process_signature(
                    line_cleaned,
                    curr_label
                )
                if sig_object:
                    signature_list.append(sig_object)

            else:
                # TODO: replace with error message in log
                raise Exception('Malformed line in TCP SYN section of '
                                'fingerprint file')

    return signature_list


def process_signature(line_cleaned, label):
    line_sep_sig = line_cleaned.split('=', 1)
    if not len(line_sep_sig):
        # TODO: replace with error message in log
        raise Exception('Malformed TCP SYN signature')
    
    # process signature
    sig_fields = line_sep_sig[1].strip().split(':')
    sig_object = P0fSignature(label)

    # ver
    if sig_fields[0] != '*':
        if sig_fields[0] == '6':
            # IPv6 packets are currently not supported
            # TODO: write error message to log
            return None
        sig_object.ver = int(sig_fields[0])
        
    # ttl
    if sig_fields[1].endswith('-'):
        sig_object.ttl = int(sig_fields[1].split('-')[0])
        sig_object.min_ttl = 0
    else:
        sig_object.ttl = int(sig_fields[1]) 
        # see p0fv3.09b/fp_tcp.c:171
        sig_object.min_ttl = sig_object.ttl - MAX_DIST + 1
    # olen
    sig_object.olen = int(sig_fields[2])
    
    # mss
    if sig_fields[3] != '*':
        sig_object.mss = int(sig_fields[3])

    # split wsize and scale fields
    wsize_scale = sig_fields[4].split(',')
    if len(wsize_scale) != 2:
        # TODO: replace with error message in log
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
                # TODO: error message in log
                raise Exception('Malformed TCP SYN signature field: wsize')
            elif wsize_fields[0] != 'mss' and wsize_fields[0] != 'mtu':
                # TODO: error message in log
                raise Exception('wsize cannot be a multiple of some'
                                'value other than MSS or MTU')
            else:
                # treat MTU as MSS 
                # TODO: check p0f source code for how to handle MTU
                sig_object.wsize_div_mss = int(wsize_fields[1])
        elif '%' in wsize:
            # the notation '%N', where N is a constant, is currently 
            # not supported 
            # TODO: write error message to log
            raise Exception('Expressing wsize in the notation "%N",'
                            'where N is a constant, is currently not'
                            'supported')
        else:
            # TODO: regex match to ensure wsize can be cast to int?
            sig_object.wsize = int(wsize)
        
    # scale
    if wsize_scale[1] != '*':
        sig_object.scale = int(wsize_scale[1])
        
    # olayout
    olayout = 0;
    olayout_entries = sig_fields[5].split(',')
    for option in olayout_entries:
        olayout = olayout << 4
        if option.startswith('eol'):
            eol_split = option.split('+', 1)
            if len(eol_split) != 2:
                # TODO: write error message in log
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
            # TODO: write error message in log
            raise Exception('Unknown TCP option in olayout field of '
                            'signature')

    sig_object.olayout = olayout
        
    # quirks
    quirk_entries = sig_fields[6].split(',')
    for quirk in quirk_entries:
        if quirk == '':
            # no quirks
            continue
        elif quirk == 'df':
            sig_object.quirk_df = 1
        elif quirk == 'id+':
            sig_object.quirk_nz_id = 1
        elif quirk == 'id-':
            sig_object.quirk_zero_id = 1
        elif quirk == 'ecn':
            sig_object.quirk_ecn = 1
        elif quirk == '0+':
            sig_object.quirk_nz_mbz = 1
        elif quirk == 'flow':
            # ignore: IPv6 not supported
            continue
        elif quirk == 'seq-':
            sig_object.quirk_zero_seq = 1
        elif quirk == 'ack+':
            sig_object.quirk_nz_ack = 1
        elif quirk == 'ack-':
            sig_object.quirk_zero_ack = 1
        elif quirk == 'uptr+':
            sig_object.nz_urg = 1
        elif quirk == 'urgf+':
            sig_object.urg = 1
        elif quirk == 'pushf+':
            sig_object.quirk_push = 1
        elif quirk == 'ts1-':
            sig_object.quirk_opt_zero_ts1 = 1
        elif quirk == 'ts2+':
            sig_object.quirk_opt_nz_ts2 = 1
        elif quirk == 'opt+':
            sig_object.quirk_opt_eol_nz = 1
        elif quirk == 'exws':
            sig_object.quirk_opt_exws = 1
        elif quirk == 'bad':
            sig_object.quirk_opt_bad = 1
        else:
            # TODO: replace with error message in log
            raise Exception('Unknown quirk in quirks field of '
                            'fingerprint')
        
    # pclass
    sig_object.pclass = int(sig_fields[7])
        
    return sig_object


def main():
    signature_list = read_fp_file()
    for sig in signature_list:
        pprint.pprint(vars(sig))

        
if __name__ == '__main__':
    main()
