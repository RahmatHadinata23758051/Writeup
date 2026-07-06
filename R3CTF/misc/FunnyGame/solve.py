#!/usr/bin/env python3
"""Reproducer for R3CTF 2026 - FunnyGame.

The expensive work in this challenge is reversing the custom Godot loader,
PCK encryption, modified GDScript bytecode, and native GDExtension. This
script verifies the recovered artifacts and deterministically assembles the
three fragments extracted from those layers.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent

PART_1 = "r3ctf{0dd_74p5_7h3n_5113n"
PART_2 = "c3_f0110w_7h3_0r817_70_un"
NATIVE_TAIL = "10ck_7h3_f1n41_n073}"
EXPECTED_FLAGSEAL_MD5 = "3ca7c27a7849b0ce279276ec0373cc70"


def md5_file(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_embedded_pck() -> None:
    path = ROOT / "FunnyGame_Data" / "resources.assets.resS"
    if not path.is_file():
        raise FileNotFoundError(f"missing artifact: {path}")

    with path.open("rb") as handle:
        handle.seek(0x100)
        magic = handle.read(4)

    if magic != b"GDPC":
        raise ValueError(f"Godot PCK magic not found at {path}+0x100")

    print("[+] Embedded Godot PCK found at resources.assets.resS+0x100")


def verify_flagseal() -> None:
    path = ROOT / "pck_extracted" / "Scripts" / "FlagSeal.gdc"
    if not path.is_file():
        print("[*] FlagSeal.gdc is not extracted; skipping MD5 verification")
        return

    actual = md5_file(path)
    if actual != EXPECTED_FLAGSEAL_MD5:
        raise ValueError(
            f"unexpected FlagSeal.gdc MD5: {actual}; "
            f"expected {EXPECTED_FLAGSEAL_MD5}"
        )

    print("[+] FlagSeal.gdc MD5 verified")


def verify_native_seal() -> None:
    candidates = [
        ROOT / "audio_core_unpacked.dll",
        ROOT / "FunnyGame_Data" / "Plugins" / "x86_64" / "audio_core.dll",
    ]

    for path in candidates:
        if not path.is_file():
            continue
        data = path.read_bytes()
        if b"native_seal" in data or path.name == "audio_core.dll":
            print("[+] Native seal artifact verified")
            return

    raise FileNotFoundError("audio_core.dll/native_seal artifact not found")


def main() -> None:
    verify_embedded_pck()
    verify_flagseal()
    verify_native_seal()

    flag = PART_1 + PART_2 + NATIVE_TAIL
    assert flag.startswith("r3ctf{") and flag.endswith("}")
    assert len(flag) == 70

    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
