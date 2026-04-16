#!/usr/bin/env python3
import tarfile
import lzma
from pathlib import Path

BASE = Path(__file__).resolve().parent
TAR_PATH = BASE / "ghost.tar.bz2"
OUT_DIR = BASE / "_solve_tmp"


def xor_decode(data: bytes, key: int = 0x5A) -> str:
    return bytes(b ^ key for b in data).decode("utf-8", errors="ignore")


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)

    with tarfile.open(TAR_PATH, "r:bz2") as tf:
        tf.extractall(OUT_DIR)

    loader_xz = OUT_DIR / "loader.bin"
    loader_elf = OUT_DIR / "loader"
    loader_elf.write_bytes(lzma.decompress(loader_xz.read_bytes()))

    blob = loader_elf.read_bytes()

    # Encoded string from .rodata (XOR 0x5a) found via reversing
    enc = bytes.fromhex(
        "1c363b3d607a2f34336c211d326a292e056b34052e326905176e39326b346905161c0908051d1d27"
    )
    decoded = xor_decode(enc)

    if "uni6{" in decoded and "}" in decoded:
        flag = decoded[decoded.find("uni6{") : decoded.find("}") + 1]
        print(flag)
    else:
        raise RuntimeError("Flag not found")


if __name__ == "__main__":
    main()
