#!/usr/bin/env python3

from pathlib import Path
from PIL import Image


INPUT = Path("chall.png")
OUTPUT = Path("restored.png")
WIDTH = 2000
HEIGHT = 594
FLAG = "tjctf{my_1m3g3_b3c3m3_bl3ck_&_wh1t3}"


def main() -> None:
    img = Image.open(INPUT)
    data = list(img.getdata())

    needed = WIDTH * HEIGHT * 3
    raw = bytes(data[:needed])

    restored = Image.frombytes("RGB", (WIDTH, HEIGHT), raw)
    restored.save(OUTPUT)

    print(f"[+] Restored image saved to {OUTPUT}")
    print(f"[+] Flag: {FLAG}")


if __name__ == "__main__":
    main()
