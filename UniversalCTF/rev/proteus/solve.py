#!/usr/bin/env python3

MOD = 2**32

target = 0x03dc4329

mul1 = 0x9e3779b1
add1 = 0x632be5ab
xor1 = 0x27d4eb2f
mul2 = 0x85ebca77

def ror32(x, r):
    return ((x >> r) | (x << (32 - r))) & 0xffffffff

def inv32(x):
    return pow(x, -1, MOD)

x = target
x = (x * inv32(mul2)) % MOD
x = ror32(x, 13)
x ^= xor1
x = (x - add1) % MOD
x = (x * inv32(mul1)) % MOD

serial = f"{x:08x}"

print("[+] serial:", serial)
print("[+] flag:", f"uctf{{{serial}}}")
