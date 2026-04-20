#!/usr/bin/env python3
from pathlib import Path


def extract_flag(path: str = "flag.txt") -> str:
    data = Path(path).read_text(encoding="utf-8")

    # Zero-width mapping discovered from challenge file
    zw_to_symbol = {
        0x200C: "A",  # ZERO WIDTH NON-JOINER
        0x200D: "B",  # ZERO WIDTH JOINER
        0x202C: "C",  # POP DIRECTIONAL FORMATTING
        0xFEFF: "D",  # ZERO WIDTH NO-BREAK SPACE / BOM
    }

    symbol_stream = "".join(
        zw_to_symbol[ord(ch)] for ch in data if ord(ch) in zw_to_symbol
    )

    if len(symbol_stream) % 4 != 0:
        raise ValueError("Invalid symbol stream length")

    symbol_to_bits = {
        "A": "00",
        "B": "01",
        "C": "10",
        "D": "11",
    }

    bitstream = "".join(symbol_to_bits[s] for s in symbol_stream)
    decoded = bytes(int(bitstream[i : i + 8], 2) for i in range(0, len(bitstream), 8))

    # Payload is UTF-16 big-endian text
    flag = decoded.decode("utf-16-be")
    return flag


if __name__ == "__main__":
    print(extract_flag())
