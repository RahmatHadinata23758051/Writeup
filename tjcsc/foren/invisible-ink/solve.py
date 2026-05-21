#!/usr/bin/env python3

from __future__ import annotations

import re
import subprocess
import sys
import zipfile
from pathlib import Path

PDF_PATH = Path("chall.pdf")
FLAG = "tjctf{p01yg10t_f1les_4r3_s0_c001}"
PASSWORD_RE = re.compile(r"password:\s*(\S+)", re.IGNORECASE)


def extract_password(pdf_path: Path) -> str:
    text = subprocess.check_output(["pdftotext", str(pdf_path), "-"], text=True)
    match = PASSWORD_RE.search(text)
    if not match:
        raise RuntimeError("Password ZIP tidak ditemukan di isi PDF")
    return match.group(1)


def extract_embedded_png(pdf_path: Path, password: str) -> Path:
    with zipfile.ZipFile(pdf_path) as archive:
        names = archive.namelist()
        if not names:
            raise RuntimeError("ZIP appended ke PDF tidak punya isi")
        output_path = Path(names[0])
        data = archive.read(names[0], pwd=password.encode())
        output_path.write_bytes(data)
        return output_path


def generate_dereferenced_view(image_path: Path) -> Path:
    output_path = Path("solved.png")
    subprocess.check_call(
        [
            "convert",
            str(image_path),
            "-background",
            "white",
            "-swirl",
            "-240",
            str(output_path),
        ]
    )
    return output_path


def main() -> int:
    if not PDF_PATH.exists():
        print("chall.pdf tidak ditemukan", file=sys.stderr)
        return 1

    password = extract_password(PDF_PATH)
    extracted_png = extract_embedded_png(PDF_PATH, password)
    solved_png = generate_dereferenced_view(extracted_png)

    print(f"[+] ZIP password: {password}")
    print(f"[+] Extracted image: {extracted_png}")
    print(f"[+] De-whirled preview: {solved_png}")
    print(f"[+] Flag: {FLAG}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
