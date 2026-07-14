#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path


def extract_embedded_url(image_path: Path) -> str:
    """Extract the payload stored in the red-channel MSB bit plane."""
    try:
        from PIL import Image
    except ImportError as exc:
        raise SystemExit("Pillow belum terpasang: pip install pillow") from exc

    image = Image.open(image_path).convert("RGB")
    bits = [((red >> 7) & 1) for red, _, _ in image.getdata()]

    payload = bytearray()
    for offset in range(0, len(bits) - 7, 8):
        value = 0
        for bit in bits[offset : offset + 8]:
            value = (value << 1) | bit
        payload.append(value)

    match = re.search(rb"https?://[\x21-\x7e]+", bytes(payload))
    if not match:
        raise ValueError("URL tidak ditemukan pada MSB channel merah")
    return match.group().decode("ascii")


def evaluate_vector(vector: str, zero_i: int = 0) -> int:
    """Evaluate [neg_i, x_j, nx_{j-1}, ot_i] from the transistor circuit."""
    if len(vector) != 4 or any(bit not in "01" for bit in vector):
        raise ValueError(f"vektor input tidak valid: {vector!r}")

    neg_i, x_j, nx_j_minus_1, ot_i = map(int, vector)

    if zero_i:
        return 0

    # CMOS XOR network on the left side of the diagram.
    nx_j = neg_i ^ x_j

    # Transmission-gate multiplexer on the right side.
    # ot_i = 0 selects nx_{j-1}; ot_i = 1 selects nx_j.
    return nx_j if ot_i else nx_j_minus_1


def decode_sequence(sequence_path: Path) -> str:
    decoded = bytearray()

    for line_number, raw_line in enumerate(sequence_path.read_text().splitlines(), 1):
        vectors = raw_line.split()
        if not vectors:
            continue
        if len(vectors) != 8:
            raise ValueError(
                f"baris {line_number}: seharusnya 8 vektor, ditemukan {len(vectors)}"
            )

        output_bits = "".join(str(evaluate_vector(vector)) for vector in vectors)
        decoded.append(int(output_bits, 2))

    return decoded.decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract the hidden link and decode the Booth partial-product circuit"
    )
    parser.add_argument(
        "--image",
        type=Path,
        default=Path("Challenge.png"),
        help="gambar awal yang menyimpan URL pada red-channel MSB",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("inputsequence.b"),
        help="file input sequence dari Google Drive",
    )
    parser.add_argument(
        "--skip-image",
        action="store_true",
        help="langsung decode input sequence tanpa ekstraksi URL",
    )
    args = parser.parse_args()

    if not args.skip_image:
        url = extract_embedded_url(args.image)
        print(f"[+] Embedded URL : {url}")

    plaintext = decode_sequence(args.input)
    print(f"[+] Decoded bytes: {len(plaintext)}")
    print(f"<FLAG>{plaintext}</FLAG>")


if __name__ == "__main__":
    main()
