#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

# Mapping koordinat yang dipakai ciphertext.
# Format umum:
#   (period, group)        -> simbol unsur penuh
#   (period, group, index) -> karakter ke-index dari simbol unsur (1-based)
ELEMENTS: dict[tuple[int, int], str] = {
    (1, 1): "H", (1, 18): "He",

    (2, 1): "Li", (2, 2): "Be", (2, 13): "B", (2, 14): "C",
    (2, 15): "N", (2, 16): "O", (2, 17): "F", (2, 18): "Ne",

    (3, 1): "Na", (3, 2): "Mg", (3, 13): "Al", (3, 14): "Si",
    (3, 15): "P", (3, 16): "S", (3, 17): "Cl", (3, 18): "Ar",

    (4, 1): "K", (4, 2): "Ca", (4, 3): "Sc", (4, 4): "Ti",
    (4, 5): "V", (4, 6): "Cr", (4, 7): "Mn", (4, 8): "Fe",
    (4, 9): "Co", (4, 10): "Ni", (4, 11): "Cu", (4, 12): "Zn",
    (4, 13): "Ga", (4, 14): "Ge", (4, 15): "As", (4, 16): "Se",
    (4, 17): "Br", (4, 18): "Kr",

    (5, 1): "Rb", (5, 2): "Sr", (5, 3): "Y", (5, 4): "Zr",
    (5, 5): "Nb", (5, 6): "Mo", (5, 7): "Tc", (5, 8): "Ru",
    (5, 9): "Rh", (5, 10): "Pd", (5, 11): "Ag", (5, 12): "Cd",
    (5, 13): "In", (5, 14): "Sn", (5, 15): "Sb", (5, 16): "Te",
    (5, 17): "I", (5, 18): "Xe",

    # Baris aktinida yang ditulis terpisah di bawah tabel periodik.
    (9, 3): "Ac", (9, 4): "Th", (9, 5): "Pa", (9, 6): "U",
    (9, 7): "Np", (9, 8): "Pu", (9, 9): "Am", (9, 10): "Cm",
    (9, 11): "Bk", (9, 12): "Cf", (9, 13): "Es", (9, 14): "Fm",
    (9, 15): "Md", (9, 16): "No", (9, 17): "Lr",
}

TOKEN_RE = re.compile(
    r"\(\s*(\d+)\s*,\s*(\d+)(?:\s*,\s*(\d+))?\s*\)|[{}_]"
)


def decode_raw(encoded: str) -> str:
    output: list[str] = []

    for match in TOKEN_RE.finditer(encoded):
        token = match.group(0)

        if token in {"{", "}", "_"}:
            output.append(token)
            continue

        period = int(match.group(1))
        group = int(match.group(2))
        index_text = match.group(3)

        try:
            symbol = ELEMENTS[(period, group)]
        except KeyError as exc:
            raise ValueError(
                f"Koordinat tidak dikenal: ({period}, {group})"
            ) from exc

        if index_text is None:
            output.append(symbol)
            continue

        index = int(index_text)
        if index < 1 or index > len(symbol):
            raise ValueError(
                f"Indeks {index} tidak valid untuk simbol {symbol}"
            )

        output.append(symbol[index - 1])

    return "".join(output).lower()


def normalize_challenge_typos(raw_flag: str) -> str:
    """
    Ciphertext literal menghasilkan:
      bronco{my_favorite_messages_have_at_element_of_suprise}

    Flag yang diterima checker mengoreksi dua typo pada plaintext:
      have_at_element -> have_an_element
      suprise         -> surprise
    """
    return (
        raw_flag
        .replace("have_at_element", "have_an_element")
        .replace("suprise", "surprise")
    )


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "secret.txt")
    encoded = path.read_text(encoding="utf-8")

    raw_flag = decode_raw(encoded)
    final_flag = normalize_challenge_typos(raw_flag)

    print(f"[raw]   {raw_flag}")
    print(f"[final] {final_flag}")


if __name__ == "__main__":
    main()
