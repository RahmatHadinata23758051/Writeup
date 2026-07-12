#!/usr/bin/env python3
"""
Solver for "Aperture Science: Stream Calibration"
Vulnerability: seed is masked with `& 0xFFFFF` (only 2^20 = 1,048,576
possible states), so the LCG keystream can be brute-forced entirely.
"""

MOD = 1 << 32
A = 1664525
C = 1013904223

CIPHERTEXT_HEX = (
    "1b89ad17b196d415f519f17c9bfa709ac9a7a71605c6d91a7f08fcbb08c2833298388913e8"
    "43bb0b8bd7bca262207fd861db5440715da4e2916b6245e450df243c6398e0c27fe8d83044"
    "b2a4100b83783e65fd27969f9a0adef8decede83339001f71e7fc83a3f7c415c0362d61a28"
    "d8d9e83970c840093a0fb6f0a1"
)

NEEDLE = b"grodno"  # known flag prefix to detect the correct seed


def keystream(seed: int, length: int) -> bytes:
    state = seed & 0xFFFFF
    out = bytearray()
    for _ in range(length):
        state = (A * state + C) % MOD
        out.append((state >> 24) & 0xFF)
    return bytes(out)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def main():
    ct = bytes.fromhex(CIPHERTEXT_HEX)

    for seed in range(1 << 20):  # brute force all 2^20 possible seeds
        pt = xor_bytes(ct, keystream(seed, len(ct)))
        if NEEDLE in pt:
            print(f"[+] Found seed: {seed}")
            print(f"[+] Plaintext:\n{pt.decode(errors='replace')}")

            # extract just the flag
            start = pt.find(b"grodno{")
            end = pt.find(b"}", start)
            if start != -1 and end != -1:
                print(f"[+] FLAG: {pt[start:end+1].decode()}")
            return

    print("[-] No matching seed found in range.")


if __name__ == "__main__":
    main()
