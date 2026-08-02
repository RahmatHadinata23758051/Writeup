#!/usr/bin/env python3
import struct
import re
import sys
from collections import defaultdict
from pathlib import Path

MASK = 0xFFFFFFFF
PORT = 13371

XTEA_KEY = [
    0xEBDA2075,
    0xDE70E310,
    0xE04B467B,
    0x758C6D04,
]


def u32(x):
    return x & MASK


def rol32(x, r):
    r &= 31
    x &= MASK
    return x if r == 0 else ((x << r) | (x >> (32 - r))) & MASK


def ror32(x, r):
    r &= 31
    x &= MASK
    return x if r == 0 else ((x >> r) | (x << (32 - r))) & MASK


def xtea_decrypt_block(block):
    v0 = int.from_bytes(block[:4], "big")
    v1 = int.from_bytes(block[4:8], "big")
    total = 0xC6EF3720

    for _ in range(32):
        v1 = u32(v1 - (((u32(v0 << 4) ^ (v0 >> 5)) + v0) ^ u32(total + XTEA_KEY[(total >> 11) & 3])))
        total = u32(total + 0x61C88647)
        v0 = u32(v0 - (((u32(v1 << 4) ^ (v1 >> 5)) + v1) ^ u32(total + XTEA_KEY[total & 3])))

    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")


def xtea_decrypt(data):
    return b"".join(xtea_decrypt_block(data[i:i + 8]) for i in range(0, len(data), 8))


def rc5_key_schedule(key):
    # RC5-32/12/16, key bytes are loaded as little-endian dwords.
    L = [int.from_bytes(key[i:i + 4], "little") for i in range(0, 16, 4)]

    S = [0] * 26
    S[0] = 0xB7E15163
    for i in range(1, 26):
        S[i] = u32(S[i - 1] + 0x9E3779B9)

    A = B = i = j = 0
    for _ in range(78):
        A = S[i] = rol32(S[i] + A + B, 3)
        B = L[j] = rol32(L[j] + A + B, A + B)
        i = (i + 1) % 26
        j = (j + 1) % 4

    return S


def rc5_decrypt_block(block, S):
    A = int.from_bytes(block[:4], "little")
    B = int.from_bytes(block[4:8], "little")

    for i in range(12, 0, -1):
        B = ror32(u32(B - S[2 * i + 1]), A) ^ A
        A = ror32(u32(A - S[2 * i]), B) ^ B

    A = u32(A - S[0])
    B = u32(B - S[1])
    return A.to_bytes(4, "little") + B.to_bytes(4, "little")


def decrypt_message(nonce, ciphertext):
    stage1 = xtea_decrypt(ciphertext)
    S = rc5_key_schedule(nonce)
    plaintext = b"".join(rc5_decrypt_block(stage1[i:i + 8], S) for i in range(0, len(stage1), 8))

    # PKCS#7-style padding, block size 8.
    if plaintext:
        pad = plaintext[-1]
        if 1 <= pad <= 8 and plaintext.endswith(bytes([pad]) * pad):
            plaintext = plaintext[:-pad]

    return plaintext


def parse_pcap(path):
    data = Path(path).read_bytes()
    if data[:4] != b"\xd4\xc3\xb2\xa1":
        raise ValueError("expected little-endian pcap")

    linktype = struct.unpack_from("<I", data, 20)[0]
    if linktype != 0:
        raise ValueError(f"expected DLT_NULL/linktype 0, got {linktype}")

    flows = defaultdict(bytearray)
    off = 24
    while off + 16 <= len(data):
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack_from("<IIII", data, off)
        off += 16
        pkt = data[off:off + incl_len]
        off += incl_len

        # DLT_NULL: 4-byte address family followed by IPv4 packet.
        if len(pkt) < 4 + 20:
            continue
        ip = pkt[4:]
        if ip[0] >> 4 != 4 or ip[9] != 6:
            continue

        ihl = (ip[0] & 0xF) * 4
        src_ip = ".".join(map(str, ip[12:16]))
        dst_ip = ".".join(map(str, ip[16:20]))
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue

        src_port, dst_port, seq, _ack = struct.unpack_from("!HHII", tcp, 0)
        data_offset = (tcp[12] >> 4) * 4
        payload = tcp[data_offset:]
        if not payload:
            continue
        if src_port != PORT and dst_port != PORT:
            continue

        key = (src_ip, src_port, dst_ip, dst_port)
        flows[key].extend(payload)

    return flows


def iter_framed_messages(stream):
    pos = 0
    stream = bytes(stream)
    while pos + 4 <= len(stream):
        length = struct.unpack_from(">I", stream, pos)[0]
        pos += 4
        if length < 24 or pos + length > len(stream):
            break
        body = stream[pos:pos + length]
        pos += length
        nonce = body[:16]
        ciphertext = body[16:]
        yield nonce, ciphertext


def main():
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else "challenge.pcap"
    flows = parse_pcap(pcap_path)

    found = []
    for key in sorted(flows):
        stream = flows[key]
        if not stream:
            continue
        print(f"\n[+] Stream {key[0]}:{key[1]} -> {key[2]}:{key[3]}")
        for idx, (nonce, ciphertext) in enumerate(iter_framed_messages(stream)):
            plaintext = decrypt_message(nonce, ciphertext)
            text = plaintext.decode("utf-8", errors="replace")
            print(f"[{idx:02d}] {text}")
            found.extend(re.findall(r"L3AK\{[^}]+\}", text))

    if found:
        print("\n[+] Flag:", found[0])
    else:
        print("\n[-] No flag found")


if __name__ == "__main__":
    main()
