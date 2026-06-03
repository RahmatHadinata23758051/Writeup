#!/usr/bin/env python3

enc = bytes([
    0x01, 0x1C, 0x0B, 0x38, 0x17,
    0x19, 0x1C, 0x49, 0x5A, 0x1F,
    0x17, 0x1D, 0x43, 0x0C, 0x4F,
    0x17, 0x49, 0x03, 0x01, 0x4E,
])


def recover_flag(data: bytes) -> bytes:
    out = bytearray()
    prev = 0x55
    for value in data:
        cur = prev ^ value
        out.append(cur)
        prev = cur
    return bytes(out)


if __name__ == "__main__":
    flag = recover_flag(enc)
    print(flag.decode())
