#!/usr/bin/env python3

import re

from pypdf import PdfReader


PDF_PATH = "The Complete Works of Aristotle.pdf"
COORDS = [(30, 7), (260, 22), (27, 5)]


def normalized_words(reader: PdfReader, page_number: int) -> list[str]:
    text = reader.pages[page_number - 1].extract_text() or ""
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if re.fullmatch(r"(Part|Book|Chapter|Problem)\s+\d+", stripped):
            continue
        lines.append(stripped)
    return re.findall(r"[A-Za-z]+(?:'[A-Za-z]+)?", "\n".join(lines))


def main() -> None:
    reader = PdfReader(PDF_PATH)
    words = [normalized_words(reader, page)[index - 1] for page, index in COORDS]
    flag = " ".join(words)
    print(flag.capitalize())


if __name__ == "__main__":
    main()
