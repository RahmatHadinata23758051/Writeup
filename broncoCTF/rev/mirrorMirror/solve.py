#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


MARKER = "MIRROR_SURFACE_DO_NOT_SCRATCH"
LOOKING_GLASS = "MirrorMirror"
BLOB = [
    17, 241, 10, 247, 215, 233, 146, 221, 156, 40,
    37, 198, 153, 173, 10, 103, 20, 56, 232, 116,
    208, 121, 53, 12, 122, 86, 127, 164, 109, 62,
    88, 200, 127, 234, 5,
]


def recover_flag(source_path: Path) -> str:
    source = source_path.read_text(encoding="utf-8")

    try:
        pivot = source.index(MARKER)
    except ValueError as exc:
        raise RuntimeError(f"Marker {MARKER!r} tidak ditemukan") from exc

    specular_map = hashlib.sha256(
        source[pivot:pivot + 300].encode()
    ).digest()

    plaintext = bytearray()
    for i, encrypted_byte in enumerate(BLOB):
        reflection_byte = (
            specular_map[i % len(specular_map)]
            ^ ord(LOOKING_GLASS[i % len(LOOKING_GLASS)])
        )
        plaintext.append(encrypted_byte ^ reflection_byte)

    return plaintext.decode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recover the flag from BroncoCTF Mirror Mirror"
    )
    parser.add_argument(
        "source",
        nargs="?",
        default="mirror.py",
        type=Path,
        help="path ke file mirror.py (default: ./mirror.py)",
    )
    args = parser.parse_args()

    flag = recover_flag(args.source)
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
