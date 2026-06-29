#!/usr/bin/env python3
from pathlib import Path
import sys

# Tiny rev solver.
# The ELF stores a 140x10 bitmap as RLE words. Every word is offset by
# the checksum of the input. The correct checksum is the one that makes
# every rendered row exactly 140 pixels wide.

DATA_START = 0x1B8
DATA_END = 0x37E
COUNT_START = 0x37E
COUNT_END = 0x388
WIDTH = 140
DOWNSAMPLE = 4
THRESHOLD = 2

GLYPHS = {
    (
        "#...#",
        "#...#",
        "#...#",
        "#...#",
        "#...#",
        "#...#",
        ".#.#.",
        ".#.#.",
        "..#..",
        "..#..",
    ): "V",
    (
        ".#.",
        ".#.",
        "##.",
        "##.",
        "##.",
        ".#.",
        ".#.",
        ".#.",
        "###",
        "###",
    ): "I",
    (
        "#####",
        "#####",
        "..#..",
        "..#..",
        "..#..",
        "..#..",
        "..#..",
        "..#..",
        "..#..",
        "..#..",
    ): "T",
    (
        "..##",
        "..##",
        "..#.",
        "..#.",
        "##..",
        "##..",
        "..#.",
        "..#.",
        "..##",
        "..##",
    ): "{",
    (
        "..#..",
        "..#..",
        ".#.#.",
        ".#.#.",
        "#...#",
        "#...#",
    ): "^",
    (
        "##..",
        "##..",
        ".#..",
        ".##.",
        ".###",
        "..##",
        ".#..",
        ".#..",
        "##..",
        "##..",
    ): "}",
}


def load_binary() -> bytes:
    candidates = []
    if len(sys.argv) > 1:
        candidates.append(Path(sys.argv[1]))
    candidates.extend([Path("./tini_rev"), Path("/mnt/data/tini_rev")])

    for path in candidates:
        if path.exists():
            return path.read_bytes()
    raise FileNotFoundError("tini_rev not found; pass the binary path as argv[1]")


def words_from(data: bytes):
    return [int.from_bytes(data[i:i + 2], "little") for i in range(DATA_START, DATA_END, 2)]


def recover_checksum(words, counts):
    idx = 3  # metadata: height, xscale, yscale
    candidates = []
    for count in counts:
        idx += 1      # encoded row count, duplicated in the count table
        idx += 1      # starting bit marker
        encoded_runs = words[idx:idx + count - 1]
        idx += count - 1
        numerator = sum(encoded_runs) - WIDTH
        denom = count - 1
        assert numerator % denom == 0
        candidates.append(numerator // denom)

    assert len(set(candidates)) == 1, candidates
    return candidates[0]


def render_bitmap(words, counts, checksum):
    decoded = [w - checksum for w in words]
    idx = 3
    rows = []
    for count in counts:
        idx += 1
        bit = decoded[idx] & 1
        idx += 1
        row = []
        for _ in range(count - 1):
            run = decoded[idx]
            idx += 1
            row.extend(str(bit) for _ in range(run))
            bit ^= 1
        assert len(row) == WIDTH
        rows.append("".join(row))
    return rows


def downsample(rows):
    low = []
    for row in rows:
        out = []
        for x in range(0, WIDTH, DOWNSAMPLE):
            out.append("#" if row[x:x + DOWNSAMPLE].count("1") >= THRESHOLD else ".")
        low.append("".join(out))
    return low


def components(grid):
    h, w = len(grid), len(grid[0])
    seen = [[False] * w for _ in range(h)]
    boxes = []
    for y in range(h):
        for x in range(w):
            if grid[y][x] != "#" or seen[y][x]:
                continue
            stack = [(y, x)]
            seen[y][x] = True
            pts = []
            while stack:
                cy, cx = stack.pop()
                pts.append((cy, cx))
                for dy in (-1, 0, 1):
                    for dx in (-1, 0, 1):
                        if dy == 0 and dx == 0:
                            continue
                        ny, nx = cy + dy, cx + dx
                        if 0 <= ny < h and 0 <= nx < w and grid[ny][nx] == "#" and not seen[ny][nx]:
                            seen[ny][nx] = True
                            stack.append((ny, nx))
            ys = [p[0] for p in pts]
            xs = [p[1] for p in pts]
            boxes.append((min(xs), max(xs), min(ys), max(ys)))
    return sorted(boxes)


def decode_flag(grid):
    chars = []
    for x0, x1, y0, y1 in components(grid):
        glyph = tuple(row[x0:x1 + 1] for row in grid[y0:y1 + 1])
        try:
            chars.append(GLYPHS[glyph])
        except KeyError:
            print("Unknown glyph:", file=sys.stderr)
            print("\n".join(glyph), file=sys.stderr)
            raise
    return "".join(chars)


def main():
    data = load_binary()
    if not data.startswith(b"\x7fELF"):
        raise ValueError("not an ELF file")

    words = words_from(data)
    counts = list(data[COUNT_START:COUNT_END])
    checksum = recover_checksum(words, counts)
    rows = render_bitmap(words, counts, checksum)
    grid = downsample(rows)
    flag = decode_flag(grid)

    print(flag)


if __name__ == "__main__":
    main()
