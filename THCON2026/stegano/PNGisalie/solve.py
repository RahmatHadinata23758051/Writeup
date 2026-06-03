#!/usr/bin/env python3

from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile

from PIL import Image, ImageEnhance, ImageOps


INPUT_FILE = Path("weird_file.thc")
OUTPUT_PNG = Path("decoded_from_emoji.png")
FLAG_RE = re.compile(r"THC\{[^}\s]+\}")


def decode_png_from_emoji(src: str) -> bytes:
    bits = []
    for ch in src:
        if ch == "👍":
            bits.append("1")
        elif ch == "👎":
            bits.append("0")

    usable = len(bits) - (len(bits) % 8)
    return bytes(int("".join(bits[i:i + 8]), 2) for i in range(0, usable, 8))


def ocr_flag(image_path: Path) -> str | None:
    img = Image.open(image_path)

    # The visible flag sits in the upper-right corner of the decoded PNG.
    crop = img.crop((760, 0, 1000, 80)).convert("L")
    crop = ImageOps.autocontrast(crop)
    crop = ImageEnhance.Sharpness(crop).enhance(3)
    crop = crop.point(lambda p: 255 if p > 180 else 0)

    with tempfile.NamedTemporaryFile(
        suffix=".png",
        dir=".",
        delete=False,
    ) as tmp:
        temp_path = Path(tmp.name)

    try:
        crop.save(temp_path)
        proc = subprocess.run(
            ["tesseract", str(temp_path), "stdout", "--psm", "7"],
            capture_output=True,
            text=True,
            check=False,
        )
        match = FLAG_RE.search(proc.stdout)
        return match.group(0) if match else None
    finally:
        if temp_path.exists():
            temp_path.unlink()


def main() -> int:
    if not INPUT_FILE.exists():
        print(f"missing input file: {INPUT_FILE}", file=sys.stderr)
        return 1

    src = INPUT_FILE.read_text(encoding="utf-8")
    png_data = decode_png_from_emoji(src)
    OUTPUT_PNG.write_bytes(png_data)

    flag = ocr_flag(OUTPUT_PNG)
    if flag:
        print(flag)
        return 0

    print(f"decoded image saved to {OUTPUT_PNG}")
    print("automatic OCR did not find the flag", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
