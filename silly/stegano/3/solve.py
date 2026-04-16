#!/usr/bin/env python3
from PIL import Image
import numpy as np
import re

IMG_PATH = 'chall.png'
COLS, ROWS = 28, 16
STEP = 67
CELL = 65


def extract_flag(path: str) -> str:
    img = np.array(Image.open(path).convert('RGB'))

    # Ambil satu sampel piksel di tengah tiap blok 65x65 (grid 28x16)
    cells = []
    for r in range(ROWS):
        for c in range(COLS):
            y = r * STEP + CELL // 2
            x = c * STEP + CELL // 2
            cells.append(tuple(int(v) for v in img[y, x]))

    # Flag ada di kanal hijau sebagai plaintext
    green_stream = bytes(v[1] for v in cells)
    text = green_stream.decode('latin1', errors='ignore')

    m = re.search(r'sillyCTF\{[^}]+\}', text)
    if not m:
        raise RuntimeError('Flag tidak ditemukan')
    return m.group(0)


if __name__ == '__main__':
    flag = extract_flag(IMG_PATH)
    print(flag)
