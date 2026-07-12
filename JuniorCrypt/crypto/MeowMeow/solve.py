#!/usr/bin/env python3
import re
from datetime import datetime, timezone
from pathlib import Path

from sympy import nextprime

MASK64 = (1 << 64) - 1
GAMMA = 0x9E3779B97F4A7C15
MUL1 = 0xBF58476D1CE4E5B9
MUL2 = 0x94D049BB133111EB
STATE_XOR = 0x6A09E667F3BCC909
Q_XOR = 0xA5A5A5A5A5A5A5A5


def splitmix64_next(state: int) -> tuple[int, int]:
    state = (state + GAMMA) & MASK64
    z = state
    z = ((z ^ (z >> 30)) * MUL1) & MASK64
    z = ((z ^ (z >> 27)) * MUL2) & MASK64
    z ^= z >> 31
    return state, z & MASK64


def rol64(value: int, shift: int) -> int:
    shift %= 64
    return ((value << shift) | (value >> (64 - shift))) & MASK64


def bswap64(value: int) -> int:
    return int.from_bytes(value.to_bytes(8, "little"), "big")


def pack6_big_endian(words: list[int]) -> int:
    value = 0
    for word in words:
        value = (value << 64) | word
    return value


def decode_meow_program(path: Path) -> str:
    counts = [line.rstrip(";").count("Meow") for line in path.read_text(encoding="utf-8").splitlines()]
    if len(counts) % 3 != 0:
        raise RuntimeError("Unexpected Meow program layout")

    decoded = bytearray()
    for i in range(0, len(counts), 3):
        prefix, byte_value, newline = counts[i:i + 3]
        if prefix != 2 or newline != 10:
            raise RuntimeError(f"Unexpected triple at line group {i // 3}: {prefix}, {byte_value}, {newline}")
        decoded.append(byte_value)

    return decoded.decode("utf-8")


def parse_ciphertext(path: Path) -> tuple[int, int, int, int, int]:
    text = path.read_text(encoding="utf-8")

    window = re.search(
        r"window_utc\s*=\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.\.(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
        text,
    )
    if not window:
        raise RuntimeError("Timestamp window not found")

    start = int(datetime.strptime(window.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
    end = int(datetime.strptime(window.group(2), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp())

    values = {}
    for name in ("n", "e", "c"):
        match = re.search(rf"^{name}\s*=\s*(\d+)$", text, re.MULTILINE)
        if not match:
            raise RuntimeError(f"Missing {name}")
        values[name] = int(match.group(1))

    return start, end, values["n"], values["e"], values["c"]


def generate_raw_primes(seed: int) -> tuple[int, int]:
    state = seed ^ STATE_XOR
    skip = 0x80 + ((seed >> 12) & 0xFF) + (seed & 0x1F)

    for _ in range(skip):
        state, _ = splitmix64_next(state)

    p_words = []
    for i in range(6):
        state, output = splitmix64_next(state)
        p_words.append(output ^ rol64(seed, i + 3))

    q_words = []
    for i in range(6):
        state, output = splitmix64_next(state)
        q_word = bswap64(output ^ Q_XOR ^ p_words[i]) ^ rol64(seed, 11 + i)
        q_words.append(q_word & MASK64)

    p_raw = pack6_big_endian(p_words) | (1 << 383) | 1
    q_raw = pack6_big_endian(q_words) | (1 << 383) | 1
    return p_raw, q_raw


def find_seed(start: int, end: int, n: int) -> tuple[int, int, int]:
    for seed in range(start, end + 1):
        p_raw, q_raw = generate_raw_primes(seed)

        # Seed benar menghasilkan raw candidate yang sangat dekat ke faktor final.
        if abs(n - p_raw * q_raw).bit_length() > 430:
            continue

        p = int(nextprime(p_raw))
        q = int(nextprime(q_raw))
        if p * q == n:
            return seed, p, q

    raise RuntimeError("Seed not found")


def int_to_bytes(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def main() -> None:
    meow_path = Path("meow_rsa.meow")
    ciphertext_path = Path("ciphertext.txt")

    decoded = decode_meow_program(meow_path)
    print("[+] Decoded Meow program:")
    print(decoded)

    start, end, n, e, c = parse_ciphertext(ciphertext_path)
    seed, p, q = find_seed(start, end, n)

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    plaintext = int_to_bytes(m).decode("utf-8")

    if pow(m, e, n) != c:
        raise RuntimeError("RSA verification failed")

    match = re.search(r"grodno\{[^}\r\n]+\}", plaintext)
    if not match:
        raise RuntimeError("Flag not found")

    print(f"[+] Seed      : {seed}")
    print(f"[+] Timestamp : {datetime.fromtimestamp(seed, timezone.utc).isoformat()}")
    print(f"[+] p         : {p}")
    print(f"[+] q         : {q}")
    print(f"[+] Plaintext : {plaintext}")
    print(f"[+] FLAG      : {match.group(0)}")


if __name__ == "__main__":
    main()
