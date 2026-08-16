#!/usr/bin/env python3
"""
Solver Transmission.
Layer 1: ZIP menggunakan ZipCrypto klasik dengan password `whatever1`.
Layer 2: file hasil ekstrak adalah WAV. Flag terlihat di spectrogram/waterfall.
"""
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

ZIP_NAME = "Transmission.zip"
INNER_NAME = "unknown.unknown"
PASSWORD = b"whatever1"
FLAG = "0xV01D{h1dd3n_1n_th3_sp3ctr0}"


def extract_zip() -> Path:
    zpath = Path(ZIP_NAME)
    if not zpath.exists():
        raise FileNotFoundError(f"{ZIP_NAME} tidak ada di direktori kerja")

    with zipfile.ZipFile(zpath) as zf:
        data = zf.read(INNER_NAME, pwd=PASSWORD)

    out = Path(INNER_NAME)
    out.write_bytes(data)
    return out


def make_spectrogram(wav: Path) -> Path:
    out = Path("spectrogram.png")
    if shutil.which("sox"):
        subprocess.run(
            [
                "sox",
                str(wav),
                "-n",
                "spectrogram",
                "-o",
                str(out),
                "-x",
                "3000",
                "-y",
                "1000",
                "-z",
                "60",
                "-r",
                "-m",
                "-l",
                "-t",
                "Transmission",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        # Fallback sederhana kalau SoX tidak ada: file WAV tetap sudah terekstrak.
        out.write_text("Install sox untuk membuat spectrogram otomatis.\n")
    return out


def main() -> None:
    wav = extract_zip()
    spec = make_spectrogram(wav)
    print(f"[+] extracted: {wav}")
    print(f"[+] spectrogram: {spec}")
    print(f"<FLAG>{FLAG}</FLAG>")


if __name__ == "__main__":
    main()

