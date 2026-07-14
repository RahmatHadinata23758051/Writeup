#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
from pathlib import Path

from PIL import Image


# Urutan mengikuti petunjuk "RGB trifecta":
# Red   -> Tiger
# Green -> Snake
# Blue  -> Crane
#
# Jumlah heat bar yang menyala adalah 1, 3, dan 5.
# Karena indeks bit dimulai dari 0, bitplane-nya menjadi 0, 2, dan 4.
PARTS = [
    {
        "name": "Tiger",
        "filename": "Tiger.png",
        "channel": "R",
        "channel_index": 0,
        "heat_level": 1,
        "bit_index": 0,
    },
    {
        "name": "Snake",
        "filename": "Snake.png",
        "channel": "G",
        "channel_index": 1,
        "heat_level": 3,
        "bit_index": 2,
    },
    {
        "name": "Crane",
        "filename": "Crane.png",
        "channel": "B",
        "channel_index": 2,
        "heat_level": 5,
        "bit_index": 4,
    },
]


def extract_bitplane(
    image_path: Path,
    channel_index: int,
    bit_index: int,
    output_path: Path,
) -> None:
    """Extract one RGB bitplane as a black-and-white PNG."""
    image = Image.open(image_path).convert("RGB")
    channel = image.getchannel(channel_index)

    plane = channel.point(
        lambda value: 255 if ((value >> bit_index) & 1) else 0,
        mode="1",
    ).convert("L")

    plane.save(output_path)


def ocr_part(image_path: Path) -> str | None:
    """Read the visible text with Tesseract when available."""
    tesseract = shutil.which("tesseract")
    if tesseract is None:
        return None

    result = subprocess.run(
        [
            tesseract,
            str(image_path),
            "stdout",
            "--psm",
            "7",
            "-c",
            "tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )

    cleaned = re.sub(r"[^A-Z0-9]", "", result.stdout.upper())
    return cleaned or None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract the hidden text from Static Image"
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path("."),
        help="folder containing Tiger.png, Snake.png, and Crane.png",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("extracted"),
        help="folder for extracted bitplanes",
    )
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    recovered_parts: list[str] = []

    for item in PARTS:
        source = args.input_dir / item["filename"]
        if not source.exists():
            raise FileNotFoundError(f"File tidak ditemukan: {source}")

        output = args.output_dir / (
            f"{item['name']}_{item['channel']}_bit{item['bit_index']}.png"
        )

        extract_bitplane(
            image_path=source,
            channel_index=item["channel_index"],
            bit_index=item["bit_index"],
            output_path=output,
        )

        print(
            f"[+] {item['name']:5s}: "
            f"channel={item['channel']} "
            f"heat={item['heat_level']} "
            f"bit={item['bit_index']} "
            f"-> {output}"
        )

        text = ocr_part(output)
        if text is None:
            print("[*] Tesseract tidak tersedia; baca teks pada gambar hasil.")
        else:
            recovered_parts.append(text)
            print(f"    OCR: {text}")

    if len(recovered_parts) == len(PARTS):
        body = "".join(recovered_parts)
        print(f"<FLAG>bronco{{{body}}}</FLAG>")


if __name__ == "__main__":
    main()
