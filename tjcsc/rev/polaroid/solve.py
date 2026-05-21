#!/usr/bin/env python3

from pathlib import Path


KEY = b"exposeTheNegative"
ENC_OFFSET = 0x720
ENC_SIZE = 0x18B4
FLAG = "tjctf{develop_the_picture}"


def main() -> None:
    data = Path("polaroid").read_bytes()
    enc = data[ENC_OFFSET:ENC_OFFSET + ENC_SIZE]
    out = bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(enc))
    Path("flag.png").write_bytes(out)
    print(f"[+] wrote flag.png ({len(out)} bytes)")
    print(FLAG)


if __name__ == "__main__":
    main()
