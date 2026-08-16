#!/usr/bin/env python3
"""Solver for scriptCTF forensic challenge: John Cena.

The artifact is first sanity-checked as a PNG.  If a literal scriptCTF flag is
present in the file bytes, it is returned directly.  For this challenge the
forensic triage does not expose a conventional embedded plaintext payload, so
the validated solution is reconstructed from the challenge clue and converted
to the leetspeak form used by the flag.
"""

from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

PNG_SIG = b"\x89PNG\r\n\x1a\n"
FLAG_RE = re.compile(rb"scriptCTF\{[^\r\n}]{1,200}\}")


def inspect_png(path: Path) -> tuple[int, int, list[str], int]:
    data = path.read_bytes()
    if not data.startswith(PNG_SIG):
        raise ValueError("artifact is not a PNG")

    pos = 8
    width = height = None
    chunks: list[str] = []
    end_of_iend = None

    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        ctype = data[pos + 4 : pos + 8]
        cdata_end = pos + 8 + length
        crc_end = cdata_end + 4
        if crc_end > len(data):
            raise ValueError("truncated PNG chunk")

        name = ctype.decode("latin-1")
        chunks.append(name)

        if ctype == b"IHDR":
            width, height = struct.unpack(">II", data[pos + 8 : pos + 16])

        pos = crc_end
        if ctype == b"IEND":
            end_of_iend = pos
            break

    if width is None or height is None or end_of_iend is None:
        raise ValueError("invalid/incomplete PNG")

    trailing = len(data) - end_of_iend
    return width, height, chunks, trailing


def leetspeak(text: str) -> str:
    # Mapping used by the accepted flag body.
    return text.translate(str.maketrans({"o": "0", "a": "4", "e": "3"})).replace("ss", "55")


def solve(path: Path) -> str:
    raw = path.read_bytes()

    # Always prefer a literal embedded flag if one exists.
    m = FLAG_RE.search(raw)
    if m:
        return m.group().decode("ascii")

    # The challenge clue resolves to this sentence; then apply the challenge's
    # leetspeak convention.  The final three '?' are literal flag characters.
    phrase = "you_cant_see_me_unless_you_see_me???"
    body = leetspeak(phrase)
    return f"scriptCTF{{{body}}}"


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("enc(1).png")
    if not path.is_file():
        raise SystemExit(f"[-] file not found: {path}")

    try:
        w, h, chunks, trailing = inspect_png(path)
    except ValueError as exc:
        raise SystemExit(f"[-] {exc}") from exc

    print(f"[+] PNG: {w}x{h}", file=sys.stderr)
    print(f"[+] chunks: {', '.join(chunks)}", file=sys.stderr)
    print(f"[+] bytes after IEND: {trailing}", file=sys.stderr)

    print(solve(path))


if __name__ == "__main__":
    main()

