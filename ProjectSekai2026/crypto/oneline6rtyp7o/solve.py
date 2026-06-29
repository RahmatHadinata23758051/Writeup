#!/usr/bin/env python3

import re


def main() -> None:
    modulus = 2**67 - 1

    # Start with a valid template whose 67-character body is all '6'.
    base_flag = "SEKAI{" + "6" * 67 + "}"
    base_value = int.from_bytes(base_flag.encode(), "big")

    # Each replacement '6' -> '7' adds exactly 1 to that byte position.
    # We need the total added value to cancel base_value modulo 2^67 - 1.
    target = (-base_value) % modulus

    body = []

    for index in range(67):
        # There are 67 body bytes after this position modulo 67.
        # Since 256 == 2^8 and 2^67 == 1 mod (2^67 - 1),
        # this byte contributes 2^(8 * (67 - index)) modulo the modulus.
        bit_position = (8 * (67 - index)) % 67
        bit = (target >> bit_position) & 1
        body.append("7" if bit else "6")

    flag = "SEKAI{" + "".join(body) + "}"

    # Reproduce the challenge checks exactly.
    assert re.match(r"SEKAI{[67]{67}}$", flag)
    assert not int.from_bytes(flag.encode()) % ~(6 + ~7) ** 67

    print(flag)


if __name__ == "__main__":
    main()
