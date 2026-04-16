#!/usr/bin/env python3
import re
from pathlib import Path


def extract_subject_bits(pdf_bytes: bytes) -> str:
    m = re.search(rb"/Subject \(([^)]*)\)", pdf_bytes)
    if not m:
        raise ValueError("Subject metadata not found")
    bits = m.group(1).decode()
    if not bits or any(c not in "01" for c in bits) or len(bits) % 8 != 0:
        raise ValueError("Subject is not a valid bitstring")
    return bits


def extract_key(pdf_bytes: bytes) -> bytes:
    nums = [int(x) for x in re.findall(rb"/Alt \(char\\\((\d+)\\\)\)", pdf_bytes)]
    if not nums:
        raise ValueError("No /Alt char(...) entries found")
    return "".join(chr(n) for n in nums).lower().encode()


def bits_to_bytes(bits: str) -> bytes:
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


def repeating_xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def main() -> None:
    pdf_path = Path("Untitled_document.pdf")
    pdf_bytes = pdf_path.read_bytes()

    subject_bits = extract_subject_bits(pdf_bytes)
    key = extract_key(pdf_bytes)
    ciphertext = bits_to_bytes(subject_bits)
    plaintext = repeating_xor(ciphertext, key)
    flag = plaintext.decode()

    print(f"key: {key.decode()}")
    print(f"flag: {flag}")


if __name__ == "__main__":
    main()
