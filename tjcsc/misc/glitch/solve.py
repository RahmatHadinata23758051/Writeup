#!/usr/bin/env python3
from collections import Counter
from pathlib import Path
from PIL import Image
import sys

# Resistor color values as they appear in the PNG after ignoring grayscale noise.
# The visible gold band is only a tolerance band, so it is not used as a digit.
DIGIT_BY_RGB = {
    (0, 0, 0): 0,          # black
    (84, 24, 9): 1,        # brown
    (255, 0, 0): 2,        # red
    (255, 122, 0): 3,      # orange
    (255, 229, 0): 4,      # yellow
    (51, 255, 0): 5,       # green
    (0, 2, 255): 6,        # blue
    (255, 10, 179): 7,     # violet
    (115, 115, 115): 8,    # grey
    (255, 255, 255): 9,    # white
}


def choose_input() -> Path:
    if len(sys.argv) > 1:
        return Path(sys.argv[1])
    pngs = sorted(p for p in Path('.').iterdir() if p.suffix.lower() == '.png')
    if not pngs:
        raise SystemExit('no PNG file found')
    return pngs[0]


def dominant_digit(img: Image.Image, x: int, y: int, radius: int = 6):
    """Return the dominant resistor digit around one pixel position."""
    w, h = img.size
    counts = Counter()
    for yy in range(max(0, y - radius), min(h, y + radius + 1)):
        for xx in range(max(0, x - radius), min(w, x + radius + 1)):
            digit = DIGIT_BY_RGB.get(img.getpixel((xx, yy)))
            if digit is not None:
                counts[digit] += 1
    if not counts:
        return None
    return counts.most_common(1)[0][0]


def decode(path: Path) -> str:
    img = Image.open(path).convert('RGB')
    w, h = img.size

    # Each horizontal strip is a resistor. The first two color bands encode two
    # decimal digits; the black band is multiplier x1 and the gold band is tolerance.
    x_first_digit = int(w * 0.0625)   # safely inside the first band
    x_second_digit = int(w * 0.625)   # safely inside the second band

    runs = []
    prev_pair = None
    start_y = None
    prev_y = None

    for y in range(h):
        pair = (
            dominant_digit(img, x_first_digit, y),
            dominant_digit(img, x_second_digit, y),
        )
        if None in pair:
            continue

        if pair == prev_pair and prev_y is not None and y == prev_y + 1:
            prev_y = y
            continue

        if prev_pair is not None:
            runs.append((start_y, prev_y, prev_pair))
        start_y = prev_y = y
        prev_pair = pair

    if prev_pair is not None:
        runs.append((start_y, prev_y, prev_pair))

    chars = []
    for y0, y1, (a, b) in runs:
        if y1 - y0 + 1 < 10:
            continue
        value = a * 10 + b
        if 32 <= value <= 126:
            chars.append(chr(value))

    return ''.join(chars)


def main():
    path = choose_input()
    inner = decode(path)
    print(f'<FLAG>tjctf{{{inner}}}</FLAG>')


if __name__ == '__main__':
    main()
