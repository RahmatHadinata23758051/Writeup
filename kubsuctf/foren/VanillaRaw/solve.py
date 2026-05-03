#!/usr/bin/env python3
import re
from pathlib import Path


FLAG_RE = re.compile(rb"KubSTU\{[^}]+\}")
BLOB_OFFSET = 0x3DF027ED
BLOB_SIZE = 2204


def extract_blob(path: Path) -> bytes:
    with path.open("rb") as fh:
        fh.seek(BLOB_OFFSET)
        blob = fh.read(BLOB_SIZE)

    if len(blob) != BLOB_SIZE:
        raise ValueError("failed to read expected blob size")

    return blob


def transpose_width_4(blob: bytes) -> bytes:
    width = 4
    if len(blob) % width != 0:
        raise ValueError("blob length is not divisible by 4")

    height = len(blob) // width
    rows = [blob[i * width : (i + 1) * width] for i in range(height)]
    return bytes(rows[r][c] for c in range(width) for r in range(height))


def main() -> None:
    path = Path("memory.raw")
    blob = extract_blob(path)
    reconstructed = transpose_width_4(blob)

    match = FLAG_RE.search(reconstructed)
    if not match:
        raise SystemExit("flag not found")

    print(match.group().decode())


if __name__ == "__main__":
    main()
