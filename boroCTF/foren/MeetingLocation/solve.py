#!/usr/bin/env python3
import struct
import socket
import base64

PCAP = "meeting.pcap"

NOISE = {
    b"network performance monitor probe",
    b"routine maintenance ping sequence",
    b"latency measurement probe response",
    b"infrastructure uptime monitor ping",
    b"system probe network utility scan",
    b"automated health check diagnostic",
    b"network diagnostic ping sweep tool",
    b"standard connectivity check packet",
}


def ip_to_str(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def iter_packets(path: str):
    with open(path, "rb") as f:
        global_header = f.read(24)
        if len(global_header) != 24:
            raise ValueError("invalid pcap header")

        magic = global_header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise ValueError(f"unknown pcap magic: {magic.hex()}")

        index = 0
        while True:
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", packet_header)
            data = f.read(incl_len)
            yield index, data
            index += 1


def main():
    hidden = []

    for index, data in iter_packets(PCAP):
        if len(data) < 20 or data[0] >> 4 != 4:
            continue

        ihl = (data[0] & 0x0F) * 4
        proto = data[9]
        if proto != 1 or len(data) < ihl + 8:  # ICMP only
            continue

        icmp = data[ihl:]
        payload = icmp[8:]

        # Normal probe strings are cover traffic. The last 24 ICMP packets carry
        # one printable byte each.
        if payload and payload not in NOISE:
            hidden.append(payload.decode("ascii"))

    encoded = "".join(hidden)
    flag = base64.b64decode(encoded).decode("ascii")
    print(flag)


if __name__ == "__main__":
    main()
