#!/usr/bin/env python3
from pathlib import Path

DATA = Path(__file__).with_name('data')
if not DATA.exists():
    DATA = Path('/mnt/data/data')

# The file consists of 408 organized chunks.  Each chunk is random-looking,
# but its bit population count is intentionally biased into one of 6 levels.
CHUNK_SIZE = 18_750
SKIP_NIBBLES = 4  # first 2 bytes are not part of the flag

# popcount lookup for bytes
POPCNT = bytes(bin(i).count('1') for i in range(256))

# Decoding tables recovered from the organized probability levels.
# A byte is encoded as two 4-symbol codewords: low nibble first, high nibble second.
LOW_NIBBLE = {
    '1000': 0x0, '1400': 0x1, '1040': 0x2, '1440': 0x3,
    '1022': 0x4, '1422': 0x5, '1052': 0x6, '1452': 0x7,
    '1004': 0x8, '1404': 0x9, '1044': 0xA, '1444': 0xB,
    '1025': 0xC, '1425': 0xD, '1055': 0xE, '1455': 0xF,
}
HIGH_NIBBLE = {
    '2223': 0x2, '5223': 0x3, '0423': 0x4,
    '4423': 0x5, '2523': 0x6, '5523': 0x7,
}


def classify_levels(counts):
    """Convert chunk popcounts to level digits 0..5 by sorting into clusters."""
    vals = sorted(counts)
    clusters = []
    cur = [vals[0]]
    # The intended clusters are separated by gaps of ~9500, while noise inside
    # each cluster is only hundreds. A 3000 gap is a safe separator.
    for x in vals[1:]:
        if x - cur[-1] > 3000:
            clusters.append(cur)
            cur = [x]
        else:
            cur.append(x)
    clusters.append(cur)

    centers = [sum(c) / len(c) for c in clusters]
    if len(centers) != 6:
        raise RuntimeError(f'expected 6 population-count levels, got {len(centers)}')

    out = []
    for x in counts:
        level = min(range(6), key=lambda i: abs(x - centers[i]))
        out.append(str(level))
    return ''.join(out)


def solve(path=DATA):
    blob = path.read_bytes()
    if len(blob) % CHUNK_SIZE != 0:
        raise RuntimeError('unexpected input size')

    counts = []
    for i in range(0, len(blob), CHUNK_SIZE):
        counts.append(sum(POPCNT[b] for b in blob[i:i + CHUNK_SIZE]))

    levels = classify_levels(counts)
    nibbles = [levels[i:i + 4] for i in range(0, len(levels), 4)]

    decoded = bytearray()
    for i in range(SKIP_NIBBLES, len(nibbles), 2):
        lo_code, hi_code = nibbles[i], nibbles[i + 1]
        if lo_code not in LOW_NIBBLE or hi_code not in HIGH_NIBBLE:
            raise RuntimeError(f'unknown codeword pair: {lo_code} {hi_code}')
        decoded.append((HIGH_NIBBLE[hi_code] << 4) | LOW_NIBBLE[lo_code])

    text = decoded.decode()
    start = text.index('GPNCTF{')
    end = text.index('}', start) + 1
    return text[start:end]


if __name__ == '__main__':
    print(solve())
