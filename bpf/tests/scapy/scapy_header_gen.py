#!/usr/bin/env python3

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

import sys

from scapy.all import *
import pkt_defs

# these paths are rooted to ./bpf/tests directory where eBPF unit test runner
# is ran.
BPF_TESTS_PATH = "."
MAX_PACKET_SIZE = 1518
HEADER_OUT_PATH = BPF_TESTS_PATH + "/output/scapy_bytes.h"
PACKET_BYTES_DEFINE_FMT = "#define scapy_{}_bytes {}\n"
HEADER_BANNER = '''#pragma once

/**
* This is an auto-generated header containing byte arrays of the scapy
* buffer definitions.
*/


'''

class ScapyHeaderGenerator:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.defines = []

    def write_headers(self):
        with open(self.output_dir, "w") as f:
            f.write(HEADER_BANNER)
            for define in self.defines:
                f.write(define)

    def generate_headers(self):
        for name, obj in vars(pkt_defs).items():
            if not isinstance(obj, Packet):
                continue

            # get C initializer output from Packet
            pkt_bytes = bytes(obj)

            if len(pkt_bytes) > MAX_PACKET_SIZE:
                print(f"[Error] Packet '{name}' exceeds max packet size of {MAX_PACKET_SIZE} bytes by {len(pkt_bytes) - MAX_PACKET_SIZE} bytes.")
                sys.exit(1)

            pkt_bytes_str = ", ".join([f"0x{b:02x}" for b in pkt_bytes])
            pkt_bytes_define = PACKET_BYTES_DEFINE_FMT.format(name, pkt_bytes_str)
            self.defines.append(pkt_bytes_define)


if __name__ == "__main__":
    gen = ScapyHeaderGenerator(HEADER_OUT_PATH)
    gen.generate_headers()
    gen.write_headers()
