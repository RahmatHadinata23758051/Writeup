#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

EMOJIS = ["🍎", "🦊", "🍐", "🐶", "🎈"]

# Polybius square yang tertulis pada wajah di artifact.png.
SQUARE = [
    ["b", "r", "o", "n", "c"],
    ["{", "e", "m", "0", "j"],
    ["1", "s", "_", "g", "3"],
    ["}", "a", "d", "f", "h"],
    ["i", "k", "l", "p", "q"],
]

LOOKUP = {
    EMOJIS[row] + EMOJIS[column]: SQUARE[row][column]
    for row in range(5)
    for column in range(5)
}


def decode(text: str) -> str:
    tokens = text.split()
    output: list[str] = []

    for token in tokens:
        try:
            output.append(LOOKUP[token])
        except KeyError as exc:
            raise ValueError(f"Pasangan emoji tidak dikenal: {token!r}") from exc

    return "".join(output)


def main() -> None:
    input_path = Path(
        sys.argv[1] if len(sys.argv) > 1 else "intercepted_signals.txt"
    )
    encoded = input_path.read_text(encoding="utf-8").strip()
    flag = decode(encoded)

    if not (flag.startswith("bronco{") and flag.endswith("}")):
        raise ValueError(f"Hasil decode tidak menyerupai flag: {flag}")

    print(flag)


if __name__ == "__main__":
    main()
