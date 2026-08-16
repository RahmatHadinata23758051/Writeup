#!/usr/bin/env python3

# 404 solver
# VM logic per byte:
#   v = input[i]
#   v ^= 0x20 + i
#   v += 0x07 + 3*i
#   v = rol8(v, i % 7)
#   v == target[i]

TARGET = [
    0x5d, 0xac, 0x2a, 0xd2,
    0xa6, 0x12, 0x58, 0x64,
    0xf6, 0x62, 0x63, 0x27,
    0xce, 0x9c, 0x7e, 0x84,
]


def ror8(x, n):
    n %= 8
    return ((x >> n) | ((x << (8 - n)) & 0xff)) & 0xff


def main():
    key = []

    for i, enc in enumerate(TARGET):
        rot = i % 7
        v = ror8(enc, rot)
        v = (v - (0x07 + 3 * i)) & 0xff
        v ^= (0x20 + i)
        key.append(v)

    key = bytes(key).decode()
    print(key)
    print("Run: ./404 '%s'" % key)


if __name__ == "__main__": 
   main()
