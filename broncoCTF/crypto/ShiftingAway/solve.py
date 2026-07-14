#!/usr/bin/env python3
"""Solver for the Crypto challenge: Grandma's Secret."""

from __future__ import annotations

from math import ceil

LABELS = "ADFGVX"
KEY = "SUGAR"
CIPHERTEXT = "GVXXFVXVAFXFXVGADAFF"

# Square copied from the image. Rows and columns both use A D F G V X.
SQUARE = (
    "B3MRLI",
    "A6F082",
    "C7SEUH",
    "Z9DXKV",
    "1QYW5P",
    "NJT4GO",
)


def undo_columnar_transposition(ciphertext: str, key: str) -> str:
    """Undo a standard columnar transposition read in sorted-key order."""
    width = len(key)
    length = len(ciphertext)
    rows = ceil(length / width)
    remainder = length % width

    # During encryption, columns before `remainder` in original order receive
    # one extra character when the final row is incomplete.
    original_lengths = [rows if remainder == 0 or i < remainder else rows - 1 for i in range(width)]
    sorted_indices = sorted(range(width), key=lambda i: (key[i], i))

    columns = [""] * width
    offset = 0
    for original_index in sorted_indices:
        column_length = original_lengths[original_index]
        columns[original_index] = ciphertext[offset : offset + column_length]
        offset += column_length

    stream: list[str] = []
    for row in range(rows):
        for column in range(width):
            if row < len(columns[column]):
                stream.append(columns[column][row])

    return "".join(stream)


def decode_adfgvx(stream: str) -> str:
    """Decode coordinate pairs using the supplied 6x6 ADFGVX square."""
    if len(stream) % 2:
        raise ValueError("ADFGVX coordinate stream must have an even length")

    coordinates = {
        LABELS[row] + LABELS[column]: SQUARE[row][column]
        for row in range(6)
        for column in range(6)
    }

    plaintext: list[str] = []
    for index in range(0, len(stream), 2):
        pair = stream[index : index + 2]
        try:
            plaintext.append(coordinates[pair])
        except KeyError as exc:
            raise ValueError(f"Invalid ADFGVX pair: {pair}") from exc

    return "".join(plaintext)


def main() -> None:
    coordinate_stream = undo_columnar_transposition(CIPHERTEXT, KEY)
    plaintext = decode_adfgvx(coordinate_stream)
    flag = f"grodno{{{plaintext.lower()}}}"

    print(f"key               : {KEY}")
    print(f"ciphertext        : {CIPHERTEXT}")
    print(f"coordinate stream : {coordinate_stream}")
    print(f"plaintext         : {plaintext}")
    print(f"flag              : {flag}")


if __name__ == "__main__":
    main()
