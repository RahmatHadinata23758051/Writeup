#!/usr/bin/env python3
from pathlib import Path
import re

KEY = 0x37
BINARY = Path(__file__).with_name("objectvm")
PATTERN = re.compile(rb"v1t\{[^}]+\}")


def main() -> None:
    data = BINARY.read_bytes()
    decoded = bytes(b ^ KEY for b in data)
    match = PATTERN.search(decoded)
    if not match:
        raise SystemExit("flag not found")
    print(match.group().decode())


if __name__ == "__main__":
    main()
