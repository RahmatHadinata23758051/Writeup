#!/usr/bin/env python3
from PIL import Image
import numpy as np

IMG_PATH = 'punch-card.png'
PLAYFAIR_KEY = 'PUNCH'
FLAG_PREFIX = 'jctf'

# IBM punch card row order (top -> bottom)
ROW_NAMES = ['12', '11', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
Y_ROWS = [18, 61, 108, 144, 179, 216, 252, 288, 324, 359, 396, 432]
X0 = 38
PITCH = 13
CELL_W = 7
CELL_H = 14

ALPHA25 = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'


def hollerith_to_char(rows):
    rs = set(rows)
    if len(rs) == 1:
        d = next(iter(rs))
        if d in '0123456789':
            return d

    if len(rs) == 2:
        if '12' in rs:
            d = (rs - {'12'}).pop()
            if d in '123456789':
                return 'ABCDEFGHI'[int(d) - 1]
        if '11' in rs:
            d = (rs - {'11'}).pop()
            if d in '123456789':
                return 'JKLMNOPQR'[int(d) - 1]
        if '0' in rs:
            d = (rs - {'0'}).pop()
            if d in '23456789':
                return 'STUVWXYZ'[int(d) - 2]

    return '?'


def extract_card_text(path):
    arr = np.array(Image.open(path).convert('L'))
    cols = []

    for c in range(80):
        x = X0 + c * PITCH
        if x + CELL_W > arr.shape[1]:
            break

        punched_rows = []
        for i, y in enumerate(Y_ROWS):
            patch = arr[y:y + CELL_H, x:x + CELL_W]
            # A real punch-hole region is almost fully black.
            core = patch[1:12, 1:6]
            if (core < 40).all():
                punched_rows.append(ROW_NAMES[i])

        if punched_rows:
            cols.append((c, punched_rows))

    text = ''.join(hollerith_to_char(rows) for _, rows in cols)
    return cols, text


def make_playfair_key(key):
    key = ''.join(c for c in key.upper() if c.isalpha()).replace('J', 'I')
    out = ''
    for c in key + ALPHA25:
        if c not in out:
            out += c
    return out


def playfair_decrypt(ct, key):
    k = make_playfair_key(key)
    pos = {k[i]: (i // 5, i % 5) for i in range(25)}

    def at(r, c):
        return k[r * 5 + c]

    pt = []
    for i in range(0, len(ct), 2):
        a, b = ct[i], ct[i + 1]
        ra, ca = pos[a]
        rb, cb = pos[b]

        if ra == rb:
            pt.append(at(ra, (ca - 1) % 5))
            pt.append(at(rb, (cb - 1) % 5))
        elif ca == cb:
            pt.append(at((ra - 1) % 5, ca))
            pt.append(at((rb - 1) % 5, cb))
        else:
            pt.append(at(ra, cb))
            pt.append(at(rb, ca))

    return ''.join(pt)


def main():
    _, ct = extract_card_text(IMG_PATH)
    pt = playfair_decrypt(ct, PLAYFAIR_KEY)
    cleaned = []
    for i, ch in enumerate(pt):
        if 0 < i < len(pt) - 1 and ch == 'X' and pt[i - 1] == pt[i + 1]:
            continue
        cleaned.append(ch)
    cleaned_pt = ''.join(cleaned)
    flag = f'{FLAG_PREFIX}{{{cleaned_pt}}}'

    print('[+] Hollerith decoded:', ct)
    print('[+] Playfair key:', PLAYFAIR_KEY)
    print('[+] Playfair plaintext:', pt)
    print('[+] Playfair cleaned:', cleaned_pt)
    print('[+] Flag:', flag)


if __name__ == '__main__':
    main()
