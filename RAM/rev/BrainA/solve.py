#!/usr/bin/env python3
import argparse
import os
import socket
import struct
import subprocess
import sys
import time
import select
import ctypes

MAGIC = 0x1000  # rol16(MAGIC, 4) == 1
PREFIX = b"GibsonBrainCell\x00GIZ_ME_FLAG_PLZ!"  # exactly 32 bytes
TAKEOVER = b"HostileTakeover".ljust(32, b"\x00")
FLAG_CMD = b"GIZ_ME_FLAG_PLZ!\x00"


def rol16(x: int, n: int) -> int:
    n &= 15
    x &= 0xffff
    return ((x << n) & 0xffff) | (x >> (16 - n))


def make_packet(cmd: int, payload: bytes) -> bytes:
    if not 0 <= cmd <= 2:
        raise ValueError("cmd must be 0, 1, or 2")
    if len(payload) > 255:
        raise ValueError("payload too large for one packet")

    # The binary checks the high command byte as signed(~low_byte).
    cmd_word = cmd | (((~cmd) & 0xff) << 8)
    length = len(payload)

    payload_xor = 0
    for b in payload:
        payload_xor ^= b

    header_sum = (
        rol16(MAGIC, 2)
        ^ rol16(cmd_word, 6)
        ^ rol16(length, 10)
        ^ rol16(payload_xor, 14)
    )

    return struct.pack("<HHBBH", MAGIC, cmd_word, length, payload_xor, header_sum) + payload


def packet_sequence() -> list[bytes]:
    auth_payload = PREFIX + TAKEOVER
    return [
        make_packet(2, struct.pack("<H", 1)),  # set dispatcher state to auth handler
        make_packet(1, auth_payload),           # authenticate as GibsonBrainCell
        make_packet(2, struct.pack("<H", 2)),  # set dispatcher state to flag handler
        make_packet(1, FLAG_CMD),               # ask for /flag.txt
    ]


def recvall_fd(fd, timeout: float = 2.0) -> bytes:
    end = time.time() + timeout
    out = bytearray()
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if not r:
            continue
        chunk = os.read(fd, 4096)
        if not chunk:
            break
        out.extend(chunk)
        end = time.time() + 0.25
    return bytes(out)


def recvall_sock(sock: socket.socket, timeout: float = 2.0) -> bytes:
    sock.setblocking(False)
    end = time.time() + timeout
    out = bytearray()
    while time.time() < end:
        r, _, _ = select.select([sock], [], [], 0.05)
        if not r:
            continue
        try:
            chunk = sock.recv(4096)
        except BlockingIOError:
            continue
        if not chunk:
            break
        out.extend(chunk)
        end = time.time() + 0.25
    return bytes(out)


def find_elf_base(pid: int, binary_path: str) -> int:
    real = os.path.realpath(binary_path)
    with open(f"/proc/{pid}/maps", "r", encoding="utf-8") as f:
        for line in f:
            # Keep the pathname intact even if it contains spaces, e.g. challenge (1).
            parts = line.rstrip("\n").split(None, 5)
            if len(parts) < 5:
                continue
            addr, perms, off = parts[0], parts[1], parts[2]
            path = parts[5] if len(parts) >= 6 else ""
            if "x" not in perms:
                continue
            if path and os.path.realpath(path) == real:
                start = int(addr.split("-")[0], 16)
                return start - int(off, 16)
    raise RuntimeError("could not find PIE base in /proc maps")



def patch_word_ptrace(pid: int, addr: int, data: bytes) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
    libc.ptrace.restype = ctypes.c_long

    PTRACE_PEEKTEXT = 1
    PTRACE_POKETEXT = 4
    word_size = ctypes.sizeof(ctypes.c_long)
    mask = (1 << (word_size * 8)) - 1

    pos = 0
    while pos < len(data):
        cur = addr + pos
        aligned = cur & ~(word_size - 1)
        offset = cur - aligned
        take = min(len(data) - pos, word_size - offset)

        ctypes.set_errno(0)
        old = libc.ptrace(PTRACE_PEEKTEXT, pid, ctypes.c_void_p(aligned), None)
        err = ctypes.get_errno()
        if old == -1 and err != 0:
            raise OSError(err, os.strerror(err))

        old_u = old & mask
        buf = bytearray(old_u.to_bytes(word_size, "little"))
        buf[offset:offset + take] = data[pos:pos + take]
        new_u = int.from_bytes(buf, "little")
        res = libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(aligned), ctypes.c_void_p(new_u))
        if res == -1:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        pos += take

def patch_with_ptrace(pid: int, patches: dict[int, bytes]) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
    libc.ptrace.restype = ctypes.c_long
    PTRACE_ATTACH = 16
    PTRACE_DETACH = 17

    if libc.ptrace(PTRACE_ATTACH, pid, None, None) == -1:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    try:
        os.waitpid(pid, 0)
        for addr, data in patches.items():
            patch_word_ptrace(pid, addr, data)
    finally:
        libc.ptrace(PTRACE_DETACH, pid, None, None)

def patch_local_validator(pid: int, binary_path: str) -> None:
    """Patch the uploaded binary's impossible command guard in memory only.

    Original code accepts a command only if it is 0, then 1, then 2 at the
    same time. This changes the two first conditional jumps into success
    branches, so cmd 0/1/2 behaves as the rest of the program expects.
    """
    base = find_elf_base(pid, binary_path)
    patches = {
        base + 0x138f: b"\x74\x15",  # jne fail -> je success for cmd 0
        base + 0x1396: b"\x74\x0e",  # jne fail -> je success for cmd 1
    }
    patch_with_ptrace(pid, patches)


def run_remote(host: str, port: int, delay: float) -> bytes:
    seq = packet_sequence()
    with socket.create_connection((host, port), timeout=5.0) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for pkt in seq:
            s.sendall(pkt)
            time.sleep(delay)
        return recvall_sock(s, timeout=3.0)


def run_local(binary: str, delay: float, patch_local: bool) -> bytes:
    seq = packet_sequence()
    p = subprocess.Popen(
        [binary],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        if patch_local:
            time.sleep(0.05)
            patch_local_validator(p.pid, binary)
        assert p.stdin is not None
        for pkt in seq:
            p.stdin.write(pkt)
            p.stdin.flush()
            time.sleep(delay)
        assert p.stdout is not None
        return recvall_fd(p.stdout.fileno(), timeout=3.0)
    finally:
        try:
            p.kill()
        except ProcessLookupError:
            pass


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="Solver for Brain A")
    ap.add_argument("host", nargs="?", help="remote host")
    ap.add_argument("port", nargs="?", type=int, help="remote port")
    ap.add_argument("-b", "--binary", default=os.path.join(here, "challenge"))
    ap.add_argument("--delay", type=float, default=0.25, help="delay between packets")
    ap.add_argument(
        "--patch-local",
        action="store_true",
        help="in-memory patch for the uploaded local binary's impossible guard",
    )
    ap.add_argument("--dump", action="store_true", help="print packet hex and exit")
    args = ap.parse_args()

    if args.dump:
        for i, pkt in enumerate(packet_sequence(), 1):
            print(f"packet {i}: {pkt.hex()}")
        return 0

    if args.host and args.port:
        out = run_remote(args.host, args.port, args.delay)
    else:
        out = run_local(args.binary, args.delay, args.patch_local)

    if out:
        sys.stdout.buffer.write(out)
        if not out.endswith(b"\n"):
            sys.stdout.write("\n")
    else:
        print("[!] no output received")
        if args.host and args.port:
            print("    Remote may be unpatched, unreachable, or not returning /flag.txt data.")
        elif args.patch_local:
            print("    Local validator was patched in memory, but /flag.txt is not present/readable here.")
        else:
            print("    For the uploaded local binary, use --patch-local to bypass its impossible command guard.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
