#!/usr/bin/env python3
"""Decrypt the image used by LYKNCTF 2026 - I HATE THIS APP REVENGE."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as exc:
    raise SystemExit("[-] missing dependency: pip install cryptography") from exc

MARKER = b"FIXED_ENCRYPTION_KEY"
CHARACTER = "alolanvulpix"
MAGICS = {
    b"\xff\xd8\xff": ".jpg",
    b"\x89PNG\r\n\x1a\n": ".png",
    b"GIF87a": ".gif",
    b"GIF89a": ".gif",
    b"BM": ".bmp",
    b"RIFF": ".webp",
}


def build_iv(blob: bytes) -> tuple[bytes, int]:
    if len(blob) <= 12:
        raise ValueError("encrypted data is too short")

    nonce = blob[:8]
    counter = int.from_bytes(blob[8:12], "big")
    iv = nonce + counter.to_bytes(8, "big")
    return iv, counter


def aes_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


def detect_extension(data: bytes) -> str | None:
    for magic, extension in MAGICS.items():
        if data.startswith(magic):
            if magic == b"RIFF" and data[8:12] != b"WEBP":
                continue
            return extension
    return None


def printable_key_windows(data: bytes, start: int, end: int):
    """Yield 32-byte printable ASCII windows near the env-var marker."""
    region = data[max(0, start) : min(len(data), end)]
    base = max(0, start)

    for index in range(0, len(region) - 31):
        candidate = region[index : index + 32]
        if all(0x21 <= byte <= 0x7E for byte in candidate):
            yield base + index, candidate


def recover_key(binary: bytes, encrypted: bytes, iv: bytes) -> tuple[int, bytes]:
    marker_offset = binary.find(MARKER)
    if marker_offset < 0:
        raise ValueError("FIXED_ENCRYPTION_KEY marker was not found")

    # The fallback key is stored in the same nearby read-only data cluster.
    for offset, candidate in printable_key_windows(
        binary, marker_offset - 0x3000, marker_offset + 0x1000
    ):
        first_block = aes_ctr(encrypted[12:28], candidate, iv)
        if detect_extension(first_block) is not None:
            return offset, candidate

    raise ValueError("no 32-byte key produced a known image header")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("encrypted", nargs="?", default="challenge.enc.bin")
    parser.add_argument("binary", nargs="?", default="fuoverflow_learning.exe")
    parser.add_argument("-o", "--output", default="recovered.jpg")
    args = parser.parse_args()

    encrypted_path = Path(args.encrypted)
    binary_path = Path(args.binary)
    output_path = Path(args.output)

    for path in (encrypted_path, binary_path):
        if not path.is_file():
            print(f"[-] file not found: {path}", file=sys.stderr)
            return 1

    encrypted = encrypted_path.read_bytes()
    binary = binary_path.read_bytes()

    try:
        iv, counter = build_iv(encrypted)
        key_offset, key = recover_key(binary, encrypted, iv)
        plaintext = aes_ctr(encrypted[12:], key, iv)
    except (OSError, ValueError) as exc:
        print(f"[-] failed: {exc}", file=sys.stderr)
        return 2

    extension = detect_extension(plaintext)
    if extension is None:
        print("[-] decrypted output has no recognized image signature", file=sys.stderr)
        return 3

    if output_path.suffix.lower() != extension:
        output_path = output_path.with_suffix(extension)

    output_path.write_bytes(plaintext)

    print(f"[+] Key offset : 0x{key_offset:x}")
    print(f"[+] AES key    : {key.decode('ascii')}")
    print(f"[+] Nonce      : {encrypted[:8].hex()}")
    print(f"[+] Counter    : {counter}")
    print(f"[+] IV         : {iv.hex()}")
    print(f"[+] Image      : {output_path} ({len(plaintext)} bytes)")
    print(f"[+] Character  : Alolan Vulpix")
    print(f"[+] Flag       : LYKNCTF{{{CHARACTER}}}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
