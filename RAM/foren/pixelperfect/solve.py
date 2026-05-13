#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


ARTIST_TAG = 0x013B
ZIP_LOCAL_FILE_HEADER = b"PK\x03\x04"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recover the hidden flag from the pixelperfect challenge image."
    )
    parser.add_argument(
        "image",
        nargs="?",
        default="chall.jpg",
        help="path to the challenge JPEG (default: chall.jpg)",
    )
    return parser.parse_args()


def iter_jpeg_segments(data: bytes):
    if not data.startswith(b"\xff\xd8"):
        raise ValueError("input is not a JPEG file")

    offset = 2
    data_len = len(data)

    while offset < data_len:
        if data[offset] != 0xFF:
            raise ValueError(f"invalid JPEG marker at offset 0x{offset:x}")

        while offset < data_len and data[offset] == 0xFF:
            offset += 1

        if offset >= data_len:
            break

        marker = data[offset]
        offset += 1

        if marker in {0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
            continue

        if offset + 2 > data_len:
            raise ValueError("truncated JPEG segment length")

        seg_len = struct.unpack(">H", data[offset : offset + 2])[0]
        payload_start = offset + 2
        payload_end = payload_start + seg_len - 2
        if payload_end > data_len:
            raise ValueError("truncated JPEG segment payload")

        yield marker, data[payload_start:payload_end]
        offset = payload_end


def parse_ifd_ascii_tag(exif_payload: bytes, tag_id: int) -> str | None:
    if not exif_payload.startswith(b"Exif\x00\x00"):
        return None

    tiff = exif_payload[6:]
    if len(tiff) < 8:
        raise ValueError("truncated TIFF header")

    byte_order = tiff[:2]
    if byte_order == b"II":
        endian = "<"
    elif byte_order == b"MM":
        endian = ">"
    else:
        raise ValueError("unsupported TIFF byte order")

    magic = struct.unpack(endian + "H", tiff[2:4])[0]
    if magic != 42:
        raise ValueError("invalid TIFF magic")

    ifd0_offset = struct.unpack(endian + "I", tiff[4:8])[0]
    if ifd0_offset + 2 > len(tiff):
        raise ValueError("invalid IFD0 offset")

    count = struct.unpack(endian + "H", tiff[ifd0_offset : ifd0_offset + 2])[0]
    entries_offset = ifd0_offset + 2

    for index in range(count):
        entry_offset = entries_offset + index * 12
        entry = tiff[entry_offset : entry_offset + 12]
        if len(entry) != 12:
            raise ValueError("truncated IFD entry")

        current_tag, field_type, value_count, value_or_offset = struct.unpack(
            endian + "HHII", entry
        )
        if current_tag != tag_id or field_type != 2 or value_count == 0:
            continue

        if value_count <= 4:
            raw = entry[8 : 8 + value_count]
        else:
            start = value_or_offset
            end = start + value_count
            raw = tiff[start:end]

        return raw.rstrip(b"\x00").decode("utf-8", errors="replace")

    return None


def extract_password(jpeg_path: Path) -> str:
    data = jpeg_path.read_bytes()
    for marker, payload in iter_jpeg_segments(data):
        if marker != 0xE1:
            continue
        artist = parse_ifd_ascii_tag(payload, ARTIST_TAG)
        if artist and artist.startswith("Password: "):
            return artist.split(": ", 1)[1].strip()
    raise ValueError("password not found in EXIF Artist tag")


def carve_zip(jpeg_path: Path, output_zip: Path) -> None:
    data = jpeg_path.read_bytes()
    start = data.find(ZIP_LOCAL_FILE_HEADER)
    if start == -1:
        raise ValueError("embedded ZIP archive not found")
    output_zip.write_bytes(data[start:])


def extract_flag(zip_path: Path, password: str) -> str:
    seven_zip = shutil.which("7z")
    if not seven_zip:
        raise RuntimeError("7z is required to extract the AES-encrypted ZIP archive")

    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir) / "out"
        out_dir.mkdir()

        result = subprocess.run(
            [
                seven_zip,
                "x",
                "-y",
                f"-p{password}",
                str(zip_path),
                f"-o{out_dir}",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())

        flag_file = out_dir / "flag.txt"
        if not flag_file.exists():
            raise ValueError("flag.txt was not extracted from the archive")
        content = flag_file.read_text(encoding="utf-8").strip()
        match = re.search(r"RAM\{[^}]+\}", content)
        return match.group(0) if match else content


def main() -> int:
    args = parse_args()
    jpeg_path = Path(args.image)
    if not jpeg_path.is_file():
        print(f"[!] file not found: {jpeg_path}", file=sys.stderr)
        return 1

    try:
        password = extract_password(jpeg_path)
        with tempfile.TemporaryDirectory() as tmpdir:
            carved_zip = Path(tmpdir) / "embedded.zip"
            carve_zip(jpeg_path, carved_zip)
            flag = extract_flag(carved_zip, password)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    print(f"[+] Password: {password}")
    print(f"[+] Flag: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
