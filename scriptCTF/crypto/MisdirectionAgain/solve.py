#!/usr/bin/env python3

enc = open("enc.txt").read().strip()

assert len(enc) % 12 == 0

def decrypt_block(bs):
    c = list(map(int, bs))

    p = [
        0,
        1,
        c[3] ^ c[11],
        c[3] ^ c[4] ^ c[7] ^ c[10],
        c[4] ^ c[10],
        c[0] ^ c[4] ^ c[6] ^ c[8] ^ c[9] ^ c[10],
        c[4] ^ c[5] ^ c[9] ^ c[10],
        c[5] ^ c[11],
    ]

    return chr(int("".join(map(str, p)), 2))

flag = "".join(
    decrypt_block(enc[i:i+12])
    for i in range(0, len(enc), 12)
)

print(flag)
