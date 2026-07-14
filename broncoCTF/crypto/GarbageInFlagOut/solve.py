#!/usr/bin/env python3
from __future__ import annotations

import itertools
import re
import string
import sys
from pathlib import Path

LOWERCASE = bytes(string.ascii_lowercase, "ascii")
FLAG_CHARS = set(string.ascii_lowercase + string.digits + "_{}")

# Dipakai hanya untuk memilih kandidat yang sesuai hint "valid English leetspeak".
COMMON_WORDS = {
    "a", "about", "after", "again", "all", "also", "an", "and", "any",
    "are", "as", "at", "be", "because", "been", "before", "but", "by",
    "can", "cipher", "code", "data", "do", "each", "enough", "even",
    "every", "flag", "for", "from", "get", "good", "have", "he", "her",
    "here", "how", "i", "if", "in", "into", "is", "it", "key", "know",
    "make", "message", "more", "new", "no", "not", "now", "of", "on",
    "one", "only", "or", "other", "our", "out", "random", "read", "same",
    "secret", "see", "so", "some", "that", "the", "their", "them", "then",
    "there", "they", "this", "time", "to", "two", "up", "use", "was",
    "we", "what", "when", "which", "who", "will", "with", "you", "your",
}

LEET_TABLE = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
})


def reverse_bits(value: int) -> int:
    """Implementasi satu byte dari scramble()."""
    result = 0
    for bit in range(8):
        result |= ((value >> bit) & 1) << (7 - bit)
    return result


def extension_high_nibble(key_byte: int) -> int:
    """
    Empat bit atas dari key extension bersifat deterministik.
    Empat bit bawah berasal dari random.getrandbits(4).
    """
    result = 0
    for pair_index in range(4):
        pair = (key_byte >> (2 * pair_index)) & 0b11
        parity = (pair & 1) ^ (pair >> 1)
        result |= parity << (7 - pair_index)
    return result & 0xF0


def parse_output(path: Path) -> tuple[bytes, bytes]:
    text = path.read_text(encoding="utf-8")

    garbage_match = re.search(r"Random garbage:\s*([0-9a-fA-F]+)", text)
    flag_match = re.search(r"The flag:\s*([0-9a-fA-F]+)", text)

    if not garbage_match or not flag_match:
        raise ValueError("Format output.txt tidak dikenali")

    garbage_cipher = bytes.fromhex(garbage_match.group(1))
    flag_cipher = bytes.fromhex(flag_match.group(1))

    if len(garbage_cipher) != 2 * len(flag_cipher):
        raise ValueError("Panjang garbage harus dua kali panjang flag")

    return garbage_cipher, flag_cipher


def candidates_per_position(
    garbage_cipher: bytes,
    flag_cipher: bytes,
) -> list[list[str]]:
    n = len(flag_cipher)
    first_half = garbage_cipher[:n]
    second_half = garbage_cipher[n:]

    all_candidates: list[list[str]] = []

    for index in range(n):
        chars: set[str] = set()

        # Bagian pertama garbage:
        #   G0[i] = key[i] XOR lowercase[i]
        for known_plain in LOWERCASE:
            key_byte = first_half[index] ^ known_plain
            expected_high = extension_high_nibble(key_byte)

            # Bagian kedua garbage menggunakan key extension.
            # Low nibble key extension acak, tetapi high nibble harus cocok.
            second_plain_exists = any(
                ((second_half[index] ^ candidate_plain) & 0xF0)
                == expected_high
                for candidate_plain in LOWERCASE
            )
            if not second_plain_exists:
                continue

            # Flag:
            #   F[i] = reverse_bits(key[i]) XOR flag_plain[i]
            flag_plain = flag_cipher[index] ^ reverse_bits(key_byte)
            char = chr(flag_plain)

            if char in FLAG_CHARS:
                chars.add(char)

        if not chars:
            raise ValueError(f"Tidak ada kandidat pada posisi {index}")

        all_candidates.append(sorted(chars))

    return all_candidates


def english_leetspeak_score(candidate: str) -> int:
    if not re.fullmatch(r"bronco\{[a-z0-9_]+\}", candidate):
        return -10**9

    body = candidate[len("bronco{"):-1].translate(LEET_TABLE)
    words = body.split("_")

    if any(not word or not word.isalpha() for word in words):
        return -10**9

    score = 0
    for word in words:
        if word in COMMON_WORDS:
            score += len(word) ** 2
        else:
            score -= len(word) ** 2

    return score


def recover_flag(garbage_cipher: bytes, flag_cipher: bytes) -> tuple[str, list[str]]:
    position_candidates = candidates_per_position(garbage_cipher, flag_cipher)

    candidates = [
        "".join(chars)
        for chars in itertools.product(*position_candidates)
    ]

    formatted = [
        candidate
        for candidate in candidates
        if re.fullmatch(r"bronco\{[a-z0-9_]+\}", candidate)
    ]

    if not formatted:
        raise ValueError("Tidak ada kandidat dengan format flag yang benar")

    ranked = sorted(
        formatted,
        key=lambda value: (english_leetspeak_score(value), value),
        reverse=True,
    )

    return ranked[0], ranked


def main() -> None:
    input_path = Path(sys.argv[1] if len(sys.argv) > 1 else "output.txt")
    garbage_cipher, flag_cipher = parse_output(input_path)
    flag, ranked = recover_flag(garbage_cipher, flag_cipher)

    print("[+] Kandidat setelah constraint:")
    for candidate in ranked:
        print(f"    {candidate}")

    print(f"[+] Flag: {flag}")


if __name__ == "__main__":
    main()
