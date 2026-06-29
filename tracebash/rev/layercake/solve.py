#!/usr/bin/env python3

D = bytes.fromhex("08d3f82366c8111b474dfe3a5bc3cb9bbce04e7fd071624b5c9c")
N = len(D)

def rol3(b):
    return ((b << 3) | (b >> 5)) & 0xFF

def transform(R, K):
    out = bytearray(N)
    for i in range(N):
        t = (i * 7 + 11) & 0xFF
        v = D[i] ^ R ^ t
        v = rol3(v)
        v ^= K
        out[i] = v
    return bytes(out)

candidates = []
for R in range(100):
    for K in range(256):
        out = transform(R, K)
        if all(32 <= c < 127 for c in out):
            try:
                s = out.decode()
            except:
                continue
            if "{" in s and "}" in s:
                candidates.append((R, K, s))

for R, K, s in candidates:
    print(f"R={R:3d} K={K:3d} -> {s}")

print(f"\nTotal candidates: {len(candidates)}")
