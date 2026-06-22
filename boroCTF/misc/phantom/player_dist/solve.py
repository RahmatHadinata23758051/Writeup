#!/usr/bin/env python3
import socket
import struct
import sys

import dpkt


TARGET_DST = "198.51.100.22"
XOR_KEY = 0x2A


def extract_flag(pcap_path: str) -> str:
    packets = []

    with open(pcap_path, "rb") as f:
        reader = dpkt.pcap.Reader(f)
        for ts, buf in reader:
            ip = dpkt.ip.IP(buf)
            tcp = ip.data

            if socket.inet_ntoa(ip.dst) != TARGET_DST:
                continue

            tsval = None
            for kind, data in dpkt.tcp.parse_opts(tcp.opts):
                if kind == dpkt.tcp.TCP_OPT_TIMESTAMP:
                    tsval, _ = struct.unpack("!II", data)
                    break

            if tsval is None:
                continue

            packets.append((ts, tsval))

    if not packets:
        raise RuntimeError("No exfiltration packets found")

    packets.sort(key=lambda item: item[0])
    flag = "".join(chr(tsval ^ XOR_KEY) for _, tsval in packets)

    if not flag.startswith("boroCTF{") or not flag.endswith("}"):
        raise RuntimeError(f"Decoded data does not look like a flag: {flag!r}")

    return flag


def main() -> None:
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else "phantom.pcap"
    print(extract_flag(pcap_path))


if __name__ == "__main__":
    main()
