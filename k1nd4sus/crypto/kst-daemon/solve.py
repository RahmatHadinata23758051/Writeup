#!/usr/bin/env python3
import re
import socket
import struct

HOST = "chall.k1nd4sus.it"
PORT = 30506

R = 0xE1000000000000000000000000000000
ONE = 1 << 127


def gf_mul(x: int, y: int) -> int:
    z = 0
    v = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
    return z


def gf_pow(x: int, e: int) -> int:
    r = ONE
    a = x
    while e:
        if e & 1:
            r = gf_mul(r, a)
        a = gf_mul(a, a)
        e >>= 1
    return r


def gf_inv(x: int) -> int:
    return gf_pow(x, (1 << 128) - 2)


def gf_div(x: int, y: int) -> int:
    return gf_mul(x, gf_inv(y))


def gf_sqrt(x: int) -> int:
    r = x
    for _ in range(127):
        r = gf_mul(r, r)
    return r


def b2i(b: bytes) -> int:
    return int.from_bytes(b, "big")


def i2b(i: int) -> bytes:
    return i.to_bytes(16, "big")


def ghash(H: int, aad: bytes, c: bytes) -> int:
    y = 0
    aad_padded = aad + b"\x00" * ((16 - len(aad) % 16) % 16)
    c_padded = c + b"\x00" * ((16 - len(c) % 16) % 16)

    for i in range(0, len(aad_padded), 16):
        y = gf_mul(y ^ b2i(aad_padded[i : i + 16]), H)

    for i in range(0, len(c_padded), 16):
        y = gf_mul(y ^ b2i(c_padded[i : i + 16]), H)

    l = (len(aad) * 8).to_bytes(8, "big") + (len(c) * 8).to_bytes(8, "big")
    y = gf_mul(y ^ b2i(l), H)
    return y


def make_hdr(msg_type: int, seq: int, length: int) -> bytes:
    return b"KS" + bytes([msg_type]) + struct.pack("<I", seq) + struct.pack("<H", length)


def recvn(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError("socket closed")
        data += chunk
    return data


def recv_pkt(sock: socket.socket) -> dict:
    hdr = recvn(sock, 9)
    if hdr[:2] != b"KS":
        raise ValueError("bad magic")
    msg_type = hdr[2]
    seq = struct.unpack("<I", hdr[3:7])[0]
    length = struct.unpack("<H", hdr[7:9])[0]
    body = recvn(sock, length + 16)
    return {
        "hdr": hdr,
        "type": msg_type,
        "seq": seq,
        "len": length,
        "ct": body[:length],
        "tag": body[length:],
    }


def send_pkt(sock: socket.socket, msg_type: int, seq: int, ct: bytes = b"", tag: bytes = b"") -> None:
    sock.sendall(make_hdr(msg_type, seq, len(ct)) + ct + tag)


def exploit() -> str:
    with socket.create_connection((HOST, PORT)) as sock:
        send_pkt(sock, 0, 0)
        init = recv_pkt(sock)

        # Reuse nonce n0 = s+1 through repeated invalid packets at fixed seq s.
        g = init["seq"]
        s = g + 1
        n0 = s + 1

        samples = []
        for i in range(4):
            req_ct = bytes([i, 0x11, 0x22, 0x33])
            send_pkt(sock, 2, s, req_ct, b"\x00" * 16)
            resp = recv_pkt(sock)
            known_pt = f"ERR: MAC_FAIL_ON_MSG_{req_ct.hex()}".encode()
            samples.append((resp, known_pt))

        r0, pt0 = samples[0]
        r1, _ = samples[1]

        c2_0 = (r0["ct"][16:] + b"\x00" * 16)[:16]
        c2_1 = (r1["ct"][16:] + b"\x00" * 16)[:16]
        d_c2 = b2i(bytes(a ^ b for a, b in zip(c2_0, c2_1)))
        d_t = b2i(bytes(a ^ b for a, b in zip(r0["tag"], r1["tag"])))

        H = gf_sqrt(gf_div(d_t, d_c2))
        S_n0 = b2i(r0["tag"]) ^ ghash(H, r0["hdr"], r0["ct"])

        ks_n0 = bytes(a ^ b for a, b in zip(r0["ct"], pt0))

        # Recover keystream for nonce n0+1 (future flag response nonce).
        req2 = b"\xaa\xbb\xcc\xdd"
        send_pkt(sock, 2, n0, req2, b"\x00" * 16)
        rn1 = recv_pkt(sock)
        pt_n1 = f"ERR: MAC_FAIL_ON_MSG_{req2.hex()}".encode()
        ks_n1 = bytes(a ^ b for a, b in zip(rn1["ct"], pt_n1))

        # Forge valid type=2 request decrypting to b"FLAG" at nonce n0.
        forged_ct = bytes(a ^ b for a, b in zip(b"FLAG", ks_n0[:4]))
        req_hdr = make_hdr(2, n0, 4)
        forged_tag = i2b(S_n0 ^ ghash(H, req_hdr, forged_ct))
        send_pkt(sock, 2, n0, forged_ct, forged_tag)

        flag_resp = recv_pkt(sock)
        flag_pt = bytes(a ^ b for a, b in zip(flag_resp["ct"], ks_n1[: flag_resp["len"]]))

        m = re.search(rb"KSUS\{[^}]+\}", flag_pt)
        if not m:
            raise RuntimeError(f"flag not found in decrypted plaintext: {flag_pt!r}")
        return m.group(0).decode()


if __name__ == "__main__":
    flag = exploit()
    print(flag)
