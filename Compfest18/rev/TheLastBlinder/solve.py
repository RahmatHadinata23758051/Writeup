#!/usr/bin/env python3
import argparse
import getpass
import os
import re
import select
import socket
import sys
from struct import pack, unpack

MASK64 = (1 << 64) - 1
K0 = 0xA6F1C0D93B5E2748
MUL2 = 0xFF51AFD7ED558CCD

REQUEST_RE = re.compile(rb'request:\s*([0-9a-fA-F]{32})', re.I)
CTFD_RE = re.compile(rb'ctfd_[A-Za-z0-9]+')


def rol64(x: int, n: int) -> int:
    return ((x << n) & MASK64) | (x >> (64 - n))


def bitbend(inp: bytes) -> bytes:
    if len(inp) != 16:
        raise ValueError('input must be exactly 16 bytes')

    a = unpack('<Q', inp[:8])[0] ^ K0
    b = unpack('<Q', inp[8:])[0]

    a = (a + ((a & 0xffffffff) * (b & 0xffffffff))) & MASK64
    b = rol64(b, 13)
    a ^= b

    b = (b + a) & MASK64
    b = rol64(b, 29)
    b = (b * MUL2) & MASK64
    a = (a + b) & MASK64
    a = rol64(a, 17)

    return pack('<QQ', a ^ b, (a + b) & MASK64)


def solve_one(req_hex: str) -> str:
    req_hex = req_hex.strip()
    if not re.fullmatch(r'[0-9a-fA-F]{32}', req_hex):
        raise ValueError('request harus 32 hex chars / 16 bytes')
    return bitbend(bytes.fromhex(req_hex)).hex()


def _get_token(token_arg: str | None) -> str:
    if token_arg:
        return token_arg.strip()

    env = os.environ.get('CTFD_TOKEN')
    if env:
        return env.strip()

    if not sys.stdin.isatty():
        raise RuntimeError(
            'service minta CTFd token; pakai --token TOKEN atau export CTFD_TOKEN=TOKEN'
        )

    return getpass.getpass('Masukkan CTFd access token: ').strip()


def remote(host: str, port: int, token: str | None = None, timeout: float = 20.0) -> int:
    try:
        s = socket.create_connection((host, port), timeout=10)
    except OSError as e:
        print(f'[!] connect gagal ke {host}:{port}: {e}', file=sys.stderr)
        print('[!] Instance kemungkinan mati/expired. Start ulang instance lalu pakai host/port baru.', file=sys.stderr)
        return 2

    buf = b''
    sent_token = False
    answered = set()
    seen_proofs = set()

    with s:
        s.setblocking(False)
        idle = 0.0

        while True:
            r, _, _ = select.select([s], [], [], 0.5)

            if not r:
                idle += 0.5
                if idle >= timeout:
                    print('\n[!] timeout nunggu data dari service', file=sys.stderr)
                    print('[!] Kalau sudah muncul "request:" tapi belum ada "answer", berarti parsing gagal.', file=sys.stderr)
                    return 1
                continue

            idle = 0.0
            data = s.recv(4096)

            if not data:
                return 0

            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

            buf += data
            low = buf.lower()

            if (not sent_token) and b'ctfd access token' in low:
                tail = low[low.rfind(b'ctfd access token'):]
                if not CTFD_RE.search(tail):
                    try:
                        tok = _get_token(token)
                    except Exception as e:
                        print(f'\n[!] {e}', file=sys.stderr)
                        return 1

                    s.sendall(tok.encode() + b'\n')
                    sent_token = True
                    print('\n[>] sent CTFd token', file=sys.stderr)

            for m in REQUEST_RE.finditer(buf):
                req = m.group(1).lower()

                if req in answered:
                    continue

                ans = solve_one(req.decode()).encode()
                s.sendall(ans + b'\n')
                answered.add(req)

                print(f'\n[>] response: {ans.decode()}', file=sys.stderr)

            for m in CTFD_RE.finditer(buf):
                proof = m.group(0).decode(errors='ignore')

                if proof not in seen_proofs:
                    seen_proofs.add(proof)
                    print(f'\n[+] CTFd token/proof received: {proof}', file=sys.stderr)

            if len(buf) > 32768:
                buf = buf[-2048:]


def main() -> int:
    ap = argparse.ArgumentParser(description='Solver The Last Bitbender / TheLastBlinder')
    ap.add_argument('host', nargs='?')
    ap.add_argument('port', nargs='?', type=int)
    ap.add_argument('-t', '--target', help='solve satu request hex 32 char secara offline')
    ap.add_argument('--token', help='CTFd access token; alternatif: export CTFD_TOKEN=...')
    ap.add_argument('--timeout', type=float, default=20.0)
    ap.add_argument('--selftest', action='store_true')

    args = ap.parse_args()

    if args.selftest:
        inp = bytes.fromhex('9c41e07db2f5361a8ad30c47e961b5f2')
        expected = '023a3db6ab0ec7efd2babd484c91f80f'
        got = bitbend(inp).hex()

        print(got)
        assert got == expected, (got, expected)
        print('selftest ok')
        return 0

    if args.target:
        print(solve_one(args.target))
        return 0

    if args.host and args.port:
        return remote(args.host, args.port, args.token, args.timeout)

    ap.print_help()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
