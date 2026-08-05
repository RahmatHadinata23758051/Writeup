#!/usr/bin/env python3

ct = "1b99090e0a6109e30414099a090e0a6f211704f4060a20341b99058c060a1c2809d51cbd0a6104e60a6f1cbd21921c281b9921921cbd090320421cbd203f1b990a72"

pub = [14, 5937, 140, 213, 3, 1403, 901, 2009]

# ciphertext dibagi per 4 hex char = 16-bit block
blocks = [
    int(ct[i:i+4], 16)
    for i in range(0, len(ct), 4)
]

lookup = {}

# coba semua byte 0-255
for b in range(256):
    bits = [(b >> i) & 1 for i in range(8)]  # LSB-first

    s = sum(bit * key for bit, key in zip(bits, pub))

    lookup[s] = b

flag = ""

for c in blocks:
    flag += chr(lookup[c])

print(flag)
