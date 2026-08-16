#!/usr/bin/env python3
from pathlib import Path

# 67 - solver
# Usage:
#   taruh intercepted.enc di folder yang sama
#   python3 67_solve.py


def parse_hexdump(text: str) -> bytes:
    out = []

    for line in text.splitlines():
        # Ambil kolom hex saja, buang bagian ASCII preview setelah tanda |
        left = line.split("|")[0]
        fields = left.split()

        if not fields:
            continue

        # Skip offset pertama: 00000000, 00000006, dst
        for token in fields[1:]:
            if len(token) == 2 and all(c in "0123456789abcdefABCDEF" for c in token):
                out.append(int(token, 16))

    return bytes(out)


# Hint "92nd street" -> Base92-style encoding
# Printable ASCII 33..126, tanpa double quote dan backslash
BASE92_ALPHABET = "".join(
    chr(i) for i in range(33, 127)
    if chr(i) not in '"\\'
)


def base92ish_decode(data: str) -> bytes:
    table = {ch: i for i, ch in enumerate(BASE92_ALPHABET)}
    bits = []

    i = 0
    while i < len(data):
        if i == len(data) - 1:
            bits.append(format(table[data[i]], "06b"))
            i += 1
        else:
            value = table[data[i]] * 91 + table[data[i + 1]]
            bits.append(format(value, "013b"))
            i += 2

    bitstream = "".join(bits)

    decoded = bytearray()
    for pos in range(0, len(bitstream) // 8 * 8, 8):
        decoded.append(int(bitstream[pos:pos + 8], 2))

    return bytes(decoded)


def affine_decrypt(text: str, a: int = 15, b: int = 15) -> str:
    inv_a = pow(a, -1, 26)
    out = []

    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            x = ord(ch) - base
            plain = (inv_a * (x - b)) % 26
            out.append(chr(plain + base))
        else:
            out.append(ch)

    return "".join(out)


def main() -> None:
    enc_path = Path("intercepted.enc")

    if enc_path.exists():
        dump_text = enc_path.read_text()
    else:
        # Fallback dari isi hexdump challenge
        dump_text = """00000000  3d 78 31 7b 61 51  |=x1{aQ|
00000006  65 33 62 29 48 78  |e3b)Hx|
0000000c  6b 45 52 45 43 55  |kERECU|
00000012  51 2e 63 7c 61 6c  |Q.c|al|
00000018  3a 42 56 3d 6b 2b  |:BV=k+|
0000001e  52 49 48 46 54 50  |RIHFTP|"""

    # Layer 1: hexdump text -> raw encoded string
    base92_text = parse_hexdump(dump_text).decode("ascii")

    # Layer 2: Base92-ish decode
    affine_cipher = base92ish_decode(base92_text).decode("ascii")

    # Layer 3: affine cipher decrypt
    flag = affine_decrypt(affine_cipher, a=15, b=15)

    print("[+] hexdump bytes :", base92_text)
    print("[+] after base92  :", affine_cipher)
    print("[+] after affine  :", flag)
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()

