#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path

PDF_NAME = "lorem_ipsum_dolor.pdf"
FLAG_RE = re.compile(r"squ1rrel\{[^}]+\}")


def extract_first_revision(pdf_path: Path) -> Path:
    data = pdf_path.read_bytes()
    eof = data.find(b"%%EOF")
    if eof == -1:
        raise RuntimeError("PDF tidak memiliki penanda %%EOF")

    # Ambil revision pertama: data sampai EOF pertama.
    end = eof + len(b"%%EOF\n")
    out = pdf_path.with_name("_rev0.pdf")
    out.write_bytes(data[:end])
    return out


def pdf_to_text(pdf_path: Path) -> str:
    proc = subprocess.run(
        ["pdftotext", str(pdf_path), "-"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc.stdout


def main() -> None:
    pdf = Path(PDF_NAME)
    if not pdf.exists():
        raise SystemExit(f"File tidak ditemukan: {pdf}")

    rev0 = extract_first_revision(pdf)
    text = pdf_to_text(rev0)

    m = FLAG_RE.search(text)
    if not m:
        raise SystemExit("Flag tidak ditemukan")

    print(m.group(0))


if __name__ == "__main__":
    main()
