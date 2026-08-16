#!/usr/bin/env python3
from pathlib import Path

# Offsets are VA==file offset for this PIE's .rodata mapping.
BIN = Path(__file__).with_name("soul_dispatch")
FLAG_OFF = 0x3020
FLAG_LEN = 0x33
SBOX_OFF = 0x3880

ROUND_CONSTS = [
    bytes.fromhex("b1f2e57da0cc6c569108dfa0385951b0"),
    bytes.fromhex("222ffe47055b6d123addc0f665003f2f"),
    bytes.fromhex("e990f5c49056fceafe6ae841865239c2"),
    bytes.fromhex("882dfb4e1bbe399b6d75858ed6d2633a"),
    bytes.fromhex("a51845d31359fea0abca0c67a7f17b32"),
    bytes.fromhex("346a2836242060aff55c47d7d5f87f73"),
    bytes.fromhex("a1fb748b89403197e23ae8df81e348ef"),
    bytes.fromhex("6fa22510f4d8ce4d7e0ca1818a25c092"),
]
FINAL_CONST = bytes.fromhex("2a9f025450edb9268f30a14f1cbd29df")

# Key recovered from the VM constraints and confirmed by the original binary.
KEY = bytes.fromhex("4ba317f09c2e886135d47a0fc1563be9")


def vm_accepts(key: bytes, sbox: bytes) -> bool:
    """Reimplement the VM's check block after decrypting its bytecode."""
    r = list(key)

    for const in ROUND_CONSTS:
        # xor immediate constants, then S-box substitution
        for i in range(16):
            r[i] = sbox[r[i] ^ const[i]]

        # fixed register permutation from the bytecode
        r[4], r[5], r[6], r[7] = r[5], r[6], r[7], r[4]
        r[8], r[10] = r[10], r[8]
        r[9], r[11] = r[11], r[9]
        r[12], r[13], r[14], r[15] = r[15], r[12], r[13], r[14]

        # opcode 0x93 is ADD dst, src, chained from r1 through r15
        for i in range(1, 16):
            r[i] = (r[i] + r[i - 1]) & 0xFF

    acc = r[0] ^ FINAL_CONST[0]
    for i in range(1, 16):
        acc = (acc + (r[i] ^ FINAL_CONST[i])) & 0xFF
    return acc == 0


def main() -> None:
    blob = BIN.read_bytes()
    enc_flag = blob[FLAG_OFF:FLAG_OFF + FLAG_LEN]
    sbox = blob[SBOX_OFF:SBOX_OFF + 0x100]

    assert len(enc_flag) == FLAG_LEN
    assert len(sbox) == 0x100
    assert vm_accepts(KEY, sbox), "Recovered key does not satisfy VM check"

    flag = bytes(c ^ KEY[i % len(KEY)] for i, c in enumerate(enc_flag)).decode()
    print(f"key: {KEY.hex()}")
    print(flag)


if __name__ == "__main__":
    main()

