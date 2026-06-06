#!/usr/bin/env python3
import struct
import subprocess


MASK = (1 << 64) - 1
A = 0xF451AF975D152CAD
B = 0xC2CEAADE1A351C23
INV_A = pow(A, -1, 1 << 64)

# Global ENC dari .data, hanya 6 qword non-zero yang diperlukan.
ENC = bytes.fromhex(
    "e57571e9ec9075ee"
    "7a8b0186fbf162ff"
    "edae17e7fbe4eb6c"
    "c171d16043214cfa"
    "1f06f91976d4aec1"
    "1f08274258dd79ae"
)


def undo_xor_shift_right(value: int, shift: int = 33) -> int:
    return (value ^ (value >> shift)) & MASK


def invert_hashy(value: int) -> int:
    value = undo_xor_shift_right(value)
    value ^= B
    value = undo_xor_shift_right(value)
    value = (value * INV_A) & MASK
    value = undo_xor_shift_right(value)
    return value


def main() -> None:
    blocks = struct.unpack("<6Q", ENC)
    flag = b"".join(struct.pack("<Q", invert_hashy(block)) for block in blocks)
    print(flag.decode())

    # Local validation, ignored if the binary is absent.
    try:
        result = subprocess.run(
            ["./specCTF", flag],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        print(result.stdout.decode(errors="replace").strip())
    except FileNotFoundError:
        pass


if __name__ == "__main__":
    main()
