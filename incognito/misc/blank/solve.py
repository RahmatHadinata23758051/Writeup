#!/usr/bin/env python3
from pathlib import Path


def extract_flag(path: str = "blank.txt") -> str:
    lines = Path(path).read_text().splitlines()
    ws_lines = ["".join(ch for ch in line if ch in " \t") for line in lines]

    # Decode each pair of lines by XOR-ing corresponding whitespace bits.
    # Mapping: tab = 1, space = 0
    bits = ""
    for i in range(0, len(ws_lines), 2):
        a = ws_lines[i]
        b = ws_lines[i + 1]
        m = min(len(a), len(b))
        for j in range(m):
            ba = 1 if a[j] == "\t" else 0
            bb = 1 if b[j] == "\t" else 0
            bits += "1" if (ba ^ bb) else "0"

    flag = "".join(chr(int(bits[k:k + 8], 2)) for k in range(0, len(bits), 8))
    return flag


if __name__ == "__main__":
    print(extract_flag())
