#!/usr/bin/env python3
"""Recover the developer note from VoidNotes.apk."""

from pathlib import Path
from zipfile import ZipFile


def main() -> None:
    apk = Path(__file__).with_name("VoidNotes.apk")
    with ZipFile(apk) as archive:
        encrypted = archive.read("assets/secret_note.bin")

    # NoteDecryptor.decrypt(): each asset byte is XORed with 0x55.
    flag = bytes(byte ^ 0x55 for byte in encrypted).decode("utf-8")
    print(flag)


if __name__ == "__main__":
    main()
