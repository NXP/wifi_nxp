#!/usr/bin/python
#
# This file provides the support for EAP FAST pac binary data creation
# using pac file
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#

import os
import argparse

continue_loop = True
pac_file = None
out_file = None

def main():

    parser = argparse.ArgumentParser(description='nfcpy to wpa_supplicant integration for WPS NFC operations')
    parser.add_argument('--pac',
                        help='summary file for writing status updates')
    parser.add_argument('--out',
                        help='success file for writing success update')
    args = parser.parse_args()

    if args.pac:
        global pac_file
        pac_file = args.pac

    if args.out:
        global out_file
        out_file = args.out

    h = open(out_file, "w")
    h.write("const unsigned char pac_data[] = {\n")

    count = 0
    eap_fast_pac_magic=[" 0x6a,", " 0xe4,", " 0x92,", " 0x0c,\n"]
    h.writelines(eap_fast_pac_magic)
    count += 4

    eap_fast_pac_ver=[" 0x00,", " 0x00,\n"]
    h.writelines(eap_fast_pac_ver)
    count += 2

    f=open(pac_file)
    for line in f:
        x = line.find("PAC-Type")
        if x != -1:
            l = line.rsplit("=")
            h.write(" 0x00, ")
            h2 = "0x{:02x}".format(int(l[1].rstrip(), 16))
            h.write(h2+", \n")
            count += 2  
        x = line.find("PAC-Key")
        if x != -1:
            l = line.rsplit("=")
            data = l[1]
            for x in range(0, len(data) - 1, 2):
                h2 = "0x{:02x}".format(int(data[x:x+2], 16))
                h.write(" "+h2+", ")
                count += 1
            h.write("\n")
        x = line.find("PAC-Opaque")
        if x != -1:
            l = line.rsplit("=")
            data = l[1]
            h1 = hex(int((len(data) - 1)/2))
            h.write(" 0x00, "+h1+",\n")
            count += 2
            for x in range(0, len(data) -1, 2):
                h2 = "0x{:02x}".format(int(data[x:x+2], 16))
                h.write(" "+h2+", ")
                count += 1
            h.write("\n")
        x = line.find("PAC-Info")
        if x != -1:
            l = line.rsplit("=")
            data = l[1]
            h1 = hex(int((len(data) - 1)/2))
            h.write(" 0x00, "+h1+",\n")
            count += 2
            for x in range(0, len(data) -1, 2):
                h2 = "0x{:02x}".format(int(data[x:x+2], 16))
                h.write(" "+h2+", ")
                count += 1
            h.write("\n")

    h.write("};\n")
    h.write("\n")

    h.write("unsigned int pac_data_len = "+str(count)+";")
    f.close()
        
    raise SystemExit

if __name__ == '__main__':
    main()
