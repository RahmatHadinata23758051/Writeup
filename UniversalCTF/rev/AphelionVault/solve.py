#!/usr/bin/env python3
from pathlib import Path
import subprocess

BINARY = Path(__file__).with_name("aphelion_vault")


def rol8(value: int, count: int) -> int:
    value &= 0xFF
    count &= 7
    return ((value << count) | (value >> (8 - count))) & 0xFF


def ror8(value: int, count: int) -> int:
    value &= 0xFF
    count &= 7
    return ((value >> count) | (value << (8 - count))) & 0xFF


def extract_vault(binary: bytes) -> bytes:
    """Ambil section .vault melalui marker unik NRD0."""
    marker = b"NRD0"
    offset = binary.find(marker)
    if offset < 0:
        raise RuntimeError("Marker .vault NRD0 tidak ditemukan")

    vault = binary[offset : offset + 0x40]
    if len(vault) != 0x40:
        raise RuntimeError("Data .vault tidak lengkap")
    return vault


def recover_alignment(vault: bytes) -> bytes:
    """Balik tiga tahap validasi untuk memperoleh input 24 byte."""
    target_a = []
    target_b = []
    target_c = []

    # Loop 0x401210 berjalan delapan kali dan membentuk tiga target 8-byte.
    for i in range(8):
        target_a.append(vault[4 + i] ^ ((0xA5 - 9 * i) & 0xFF))
        target_b.append(((vault[12 + i] - 11 * i - 7) & 0xFF) ^ 0x5C)
        target_c.append(ror8(vault[20 + i], 1) ^ ((0x33 + 4 * i) & 0xFF))

    phrase = [0] * 24

    # Tahap 1:
    # rol8((input[i] ^ (0x21 + 13*i)) + (3 + 7*i), 1) == target_a[i]
    for i in range(8):
        xor_key = (0x21 + 13 * i) & 0xFF
        add_key = (3 + 7 * i) & 0xFF
        phrase[i] = ((ror8(target_a[i], 1) - add_key) & 0xFF) ^ xor_key

    # Tahap 2 bergantung pada delapan karakter tahap pertama.
    for i in range(8):
        index = 3 + i
        xor_key = (0x5A - 3 * i) & 0xFF
        phrase[8 + i] = (
            (ror8(target_b[i], 2) ^ xor_key)
            - index
            - 0x14
            - phrase[index & 7]
        ) & 0xFF

    # Tahap 3 menghubungkan byte 16..23 dengan byte 15..8 secara terbalik.
    for i in range(8):
        mixed = (ror8(target_c[i], 3) - 5 * i - 0x33) & 0xFF
        phrase[16 + i] = phrase[15 - i] ^ mixed

    result = bytes(phrase)
    if len(result) != 24 or not all(0x21 <= byte <= 0x7E for byte in result):
        raise RuntimeError("Hasil alignment phrase tidak memenuhi validasi input")
    return result


def check_alignment(vault: bytes, phrase: bytes) -> None:
    """Reproduksi seluruh pembanding binary sebagai bukti hasil reversing."""
    target_a = [vault[4 + i] ^ ((0xA5 - 9 * i) & 0xFF) for i in range(8)]
    target_b = [(((vault[12 + i] - 11 * i - 7) & 0xFF) ^ 0x5C) for i in range(8)]
    target_c = [ror8(vault[20 + i], 1) ^ ((0x33 + 4 * i) & 0xFF) for i in range(8)]

    for i in range(8):
        got = rol8(((phrase[i] ^ ((0x21 + 13 * i) & 0xFF)) + (3 + 7 * i)), 1)
        assert got == target_a[i]

    for i in range(8):
        index = 3 + i
        got = rol8(
            (phrase[8 + i] + index + 0x14 + phrase[index & 7])
            ^ ((0x5A - 3 * i) & 0xFF),
            2,
        )
        assert got == target_b[i]

    for i in range(8):
        got = rol8((phrase[15 - i] ^ phrase[16 + i]) + 5 * i + 0x33, 3)
        assert got == target_c[i]


def decrypt_flag(vault: bytes, phrase: bytes) -> bytes:
    """Dekripsi 32 byte terakhir .vault memakai alignment phrase."""
    output = bytearray()
    encrypted = vault[0x20:0x40]

    for i, value in enumerate(encrypted):
        byte = (phrase[i % 24] + 0x17 + 0x11 * i) & 0xFF
        byte ^= value ^ ((0xA9 - 3 * i) & 0xFF)
        byte ^= rol8(phrase[(7 + 5 * i) % 24], 1)
        output.append(byte)

    flag = bytes(output)
    if not (flag.startswith(b"uctf{") and flag.endswith(b"}")):
        raise RuntimeError("Output tidak memiliki format flag yang benar")
    return flag


def main() -> None:
    vault = extract_vault(BINARY.read_bytes())
    phrase = recover_alignment(vault)
    check_alignment(vault, phrase)
    flag = decrypt_flag(vault, phrase)

    print(f"Alignment phrase: {phrase.decode()}")
    print(f"Flag: {flag.decode()}")

    # Validasi dinamis: binary harus menerima frasa dan mencetak flag yang sama.
    process = subprocess.run(
        [str(BINARY)],
        input=phrase + b"\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output = process.stdout.decode(errors="replace")
    if process.returncode != 0 or flag.decode() not in output:
        raise RuntimeError("Validasi dinamis terhadap binary gagal")

    print("\nValidasi binary:")
    print(output, end="" if output.endswith("\n") else "\n")


if __name__ == "__main__":
    main()
