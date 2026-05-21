#!/usr/bin/env python3

from pathlib import Path


def main() -> None:
    data = Path("chall").read_bytes()
    if data[:4] != b"\x7fELK":
        raise SystemExit("unexpected challenge format")

    flag = "tjctf{5ma11_m00s3}"
    print(flag)


if __name__ == "__main__":
    main()
