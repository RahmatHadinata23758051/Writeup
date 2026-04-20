#!/usr/bin/env python3
import re
import subprocess
import sys

PDF_PATH = "challenge.pdf"


def extract_text_with_pdftotext(path: str) -> str:
    try:
        out = subprocess.check_output(["pdftotext", path, "-"], stderr=subprocess.STDOUT)
        return out.decode("utf-8", errors="ignore")
    except FileNotFoundError:
        print("Error: pdftotext tidak ditemukan. Install poppler-utils.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print("Gagal ekstrak text dari PDF:")
        print(e.output.decode("utf-8", errors="ignore"))
        sys.exit(1)


def find_flag(text: str) -> str | None:
    patterns = [
        r"CIT\{[^}]+\}",
        r"CTF\{[^}]+\}",
        r"FLAG\{[^}]+\}",
    ]
    for p in patterns:
        m = re.search(p, text)
        if m:
            return m.group(0)
    return None


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else PDF_PATH
    text = extract_text_with_pdftotext(path)
    flag = find_flag(text)

    if not flag:
        print("Flag tidak ditemukan.")
        sys.exit(2)

    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
