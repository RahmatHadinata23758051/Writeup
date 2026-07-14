#!/usr/bin/env python3
from __future__ import annotations

import argparse
import io
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from PIL import Image, ImageOps


FLAG_PATTERN = re.compile(rb"bronco\{[^}\r\n]{1,256}\}")

# Rilis "Never Gonna Give You Up" yang ditunjukkan oleh gambar Rick Astley.
PRIMARY_PASSWORD = "1987"


def extract_red_bit2(image_path: Path, output_path: Path) -> Image.Image:
    """
    Extract bit 2 from the red channel.

    The hidden hint is stored in this bitplane:
        pixel = (red >> 2) & 1
    """
    image = Image.open(image_path).convert("RGBA")
    red = image.getchannel("R")

    plane = red.point(
        lambda value: 255 if ((value >> 2) & 1) else 0,
        mode="1",
    ).convert("L")

    # The hidden text is black on white after inversion.
    plane = ImageOps.invert(plane)
    plane.save(output_path)
    return plane


def ocr_hint(image: Image.Image) -> str | None:
    """
    OCR the diagonal hint without writing temporary files.

    Tesseract reads each rotated PNG from stdin. Several nearby angles are
    attempted because the text is diagonal.
    """
    tesseract = shutil.which("tesseract")
    if tesseract is None:
        return None

    best_text = ""
    best_score = -1

    for angle in (20, 25, 30, 35, 40):
        rotated = image.rotate(angle, expand=True, fillcolor=255)

        stream = io.BytesIO()
        rotated.save(stream, format="PNG")

        result = subprocess.run(
            [tesseract, "stdin", "stdout", "--psm", "6"],
            input=stream.getvalue(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )

        text = result.stdout.decode("utf-8", errors="replace").strip()
        normalized = text.lower()

        score = sum(
            keyword in normalized
            for keyword in ("password", "release", "year", "song", "non-ost")
        )

        if score > best_score:
            best_score = score
            best_text = text

    return best_text or None


def run_steghide(
    audio_path: Path,
    password: str,
    output_path: Path,
) -> bool:
    """Try extracting the embedded payload with one password."""
    steghide = shutil.which("steghide")
    if steghide is None:
        raise RuntimeError(
            "steghide tidak ditemukan. Install dengan: "
            "sudo apt install steghide"
        )

    output_path.unlink(missing_ok=True)

    result = subprocess.run(
        [
            steghide,
            "extract",
            "-sf",
            str(audio_path),
            "-p",
            password,
            "-xf",
            str(output_path),
            "-f",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )

    return result.returncode == 0 and output_path.exists()


def search_flag(data: bytes) -> bytes | None:
    """Find the flag directly or inside a ZIP payload."""
    match = FLAG_PATTERN.search(data)
    if match:
        return match.group(0)

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue

                nested = archive.read(member)
                match = FLAG_PATTERN.search(nested)
                if match:
                    return match.group(0)
    except zipfile.BadZipFile:
        pass

    return None


def candidate_passwords(primary: str, brute_years: bool) -> list[str]:
    candidates = [primary]

    if brute_years:
        # Fallback if the image was interpreted incorrectly.
        for year in range(2026, 1949, -1):
            value = str(year)
            if value not in candidates:
                candidates.append(value)

    return candidates


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Solve BroncoCTF Suspicious Remix 2"
    )
    parser.add_argument(
        "audio",
        nargs="?",
        type=Path,
        default=Path("sg_remix2.wav"),
        help="stego WAV file",
    )
    parser.add_argument(
        "image",
        nargs="?",
        type=Path,
        default=Path("tolerate_this.png"),
        help="password-hint PNG",
    )
    parser.add_argument(
        "--password",
        default=PRIMARY_PASSWORD,
        help="steghide password (default: 1987)",
    )
    parser.add_argument(
        "--bruteforce-years",
        action="store_true",
        help="try years 1950-2026 if the primary password fails",
    )
    parser.add_argument(
        "--hint-output",
        type=Path,
        default=Path("R_bit2.png"),
        help="output path for the extracted hint bitplane",
    )
    parser.add_argument(
        "--payload-output",
        type=Path,
        default=Path("extracted_payload.bin"),
        help="output path for the steghide payload",
    )
    args = parser.parse_args()

    if not args.image.is_file():
        parser.error(f"image tidak ditemukan: {args.image}")
    if not args.audio.is_file():
        parser.error(f"audio tidak ditemukan: {args.audio}")

    hint_plane = extract_red_bit2(args.image, args.hint_output)
    print(f"[+] Hidden hint saved to: {args.hint_output}")

    hint_text = ocr_hint(hint_plane)
    if hint_text:
        cleaned = " ".join(hint_text.split())
        print(f"[+] OCR hint: {cleaned}")
    else:
        print("[*] Tesseract tidak tersedia; buka R_bit2.png secara manual.")

    for password in candidate_passwords(
        args.password,
        args.bruteforce_years,
    ):
        print(f"[*] Trying steghide password: {password}")

        if not run_steghide(
            args.audio,
            password,
            args.payload_output,
        ):
            continue

        payload = args.payload_output.read_bytes()
        print(
            f"[+] Payload extracted: {args.payload_output} "
            f"({len(payload)} bytes)"
        )

        flag = search_flag(payload)
        if flag is None:
            print("[!] Payload berhasil diekstrak, tetapi flag tidak ditemukan.")
            print(payload.decode("utf-8", errors="replace"))
            return

        decoded_flag = flag.decode("ascii")
        print(f"<FLAG>{decoded_flag}</FLAG>")
        return

    raise RuntimeError(
        "Tidak ada password yang berhasil. "
        "Coba --bruteforce-years atau cek kembali hint image."
    )


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError) as error:
        print(f"[-] {error}", file=sys.stderr)
        raise SystemExit(1)
