#!/usr/bin/env python3
from pathlib import Path
import hashlib


def main():
    digest_to_char = {}
    for image_path in Path(".").glob("*/*.jpg"):
        digest = hashlib.sha256(image_path.read_bytes()).hexdigest()
        digest_to_char[digest] = image_path.parent.name

    encoded = Path("what_could_this_mean.txt").read_text().strip()
    if len(encoded) % 64:
        raise SystemExit("encoded data is not aligned to SHA-256 hex digests")

    flag = "".join(
        digest_to_char[encoded[i : i + 64]]
        for i in range(0, len(encoded), 64)
    )
    print(flag)


if __name__ == "__main__":
    main()
