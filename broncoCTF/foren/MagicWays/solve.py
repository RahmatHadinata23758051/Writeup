#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import shutil
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
CHANNELS_BY_COLOR_TYPE = {
    0: 1,  # grayscale
    2: 3,  # RGB
    3: 1,  # indexed color
    4: 2,  # grayscale + alpha
    6: 4,  # RGBA
}


def load_artifact(path: Path) -> tuple[bytes, str]:
    """Read a PNG directly or pull the first PNG member from a ZIP."""
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            members = [
                name for name in archive.namelist()
                if name.lower().endswith(".png") and not name.endswith("/")
            ]
            if not members:
                raise RuntimeError("ZIP tidak berisi file PNG")
            member = members[0]
            return archive.read(member), member

    return path.read_bytes(), path.name


def parse_chunks(data: bytes) -> list[tuple[int, int, bytes, bytes]]:
    """
    Parse PNG chunks starting at offset 8.

    The signature may be corrupt, but the chunk layout can still be intact.
    Returns: (chunk_offset, data_length, chunk_type, chunk_data)
    """
    chunks: list[tuple[int, int, bytes, bytes]] = []
    offset = 8

    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        chunk_type = data[offset + 4:offset + 8]
        data_start = offset + 8
        data_end = data_start + length
        crc_end = data_end + 4

        if crc_end > len(data):
            raise RuntimeError(
                f"Chunk {chunk_type!r} melewati akhir file pada offset {offset}"
            )

        chunk_data = data[data_start:data_end]
        chunks.append((offset, length, chunk_type, chunk_data))
        offset = crc_end

        if chunk_type == b"IEND":
            break

    return chunks


def infer_height(
    width: int,
    bit_depth: int,
    color_type: int,
    interlace_method: int,
    compressed_idat: bytes,
) -> tuple[int, int, int]:
    """Infer image height from the decompressed non-interlaced scanlines."""
    if interlace_method != 0:
        raise RuntimeError("Solver ini mengharapkan PNG non-interlaced")

    channels = CHANNELS_BY_COLOR_TYPE.get(color_type)
    if channels is None:
        raise RuntimeError(f"Color type PNG tidak didukung: {color_type}")

    raw = zlib.decompress(compressed_idat)
    row_bytes = (width * channels * bit_depth + 7) // 8
    scanline_size = 1 + row_bytes  # one filter byte per row

    if scanline_size <= 1 or len(raw) % scanline_size != 0:
        raise RuntimeError(
            "Panjang IDAT hasil dekompresi tidak cocok dengan struktur scanline"
        )

    return len(raw) // scanline_size, len(raw), scanline_size


def repair_png(data: bytes) -> tuple[bytes, dict[str, int]]:
    if len(data) < 33:
        raise RuntimeError("File terlalu kecil untuk menjadi PNG")

    if data[12:16] != b"IHDR":
        raise RuntimeError("Chunk IHDR tidak ditemukan pada posisi normal")

    chunks = parse_chunks(data)
    ihdr = next((chunk for chunk in chunks if chunk[2] == b"IHDR"), None)
    if ihdr is None:
        raise RuntimeError("IHDR tidak ditemukan")

    ihdr_offset, ihdr_length, _, ihdr_data = ihdr
    if ihdr_length != 13:
        raise RuntimeError(f"Panjang IHDR tidak valid: {ihdr_length}")

    width, stored_height, bit_depth, color_type, compression, filter_method, interlace = (
        struct.unpack(">IIBBBBB", ihdr_data)
    )

    if compression != 0 or filter_method != 0:
        raise RuntimeError("Metode compression/filter PNG tidak didukung")

    idat_data = b"".join(
        chunk_data
        for _, _, chunk_type, chunk_data in chunks
        if chunk_type == b"IDAT"
    )
    if not idat_data:
        raise RuntimeError("Chunk IDAT tidak ditemukan")

    inferred_height, raw_size, scanline_size = infer_height(
        width=width,
        bit_depth=bit_depth,
        color_type=color_type,
        interlace_method=interlace,
        compressed_idat=idat_data,
    )

    repaired = bytearray(data)
    repaired[:8] = PNG_SIGNATURE

    # IHDR data starts 8 bytes after the chunk offset.
    ihdr_data_start = ihdr_offset + 8
    repaired[ihdr_data_start + 4:ihdr_data_start + 8] = struct.pack(
        ">I", inferred_height
    )

    new_ihdr_data = bytes(
        repaired[ihdr_data_start:ihdr_data_start + ihdr_length]
    )
    new_crc = zlib.crc32(b"IHDR" + new_ihdr_data) & 0xFFFFFFFF
    crc_offset = ihdr_data_start + ihdr_length
    repaired[crc_offset:crc_offset + 4] = struct.pack(">I", new_crc)

    details = {
        "width": width,
        "stored_height": stored_height,
        "height": inferred_height,
        "raw_size": raw_size,
        "scanline_size": scanline_size,
        "ihdr_crc": new_crc,
    }
    return bytes(repaired), details


def extract_flag_with_tesseract(image_path: Path) -> str | None:
    """OCR the repaired image when tesseract is installed."""
    executable = shutil.which("tesseract")
    if executable is None:
        return None

    result = subprocess.run(
        [executable, str(image_path), "stdout", "--psm", "7"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    match = re.search(r"bronco\{[^}\r\n]+\}", result.stdout)
    return match.group(0) if match else None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Repair the corrupted PNG from Magic Ways"
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="chall.png",
        type=Path,
        help="chall.png atau ZIP yang berisi chall.png",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="repaired.png",
        type=Path,
        help="nama PNG hasil perbaikan",
    )
    args = parser.parse_args()

    artifact, member_name = load_artifact(args.input)
    repaired, details = repair_png(artifact)
    args.output.write_bytes(repaired)

    print(f"[+] Source           : {member_name}")
    print("[+] PNG signature    : 89504e470d0a1a0a")
    print(
        f"[+] Stored dimensions: "
        f"{details['width']}x{details['stored_height']}"
    )
    print(
        f"[+] IDAT raw size    : {details['raw_size']} bytes "
        f"({details['scanline_size']} bytes/scanline)"
    )
    print(
        f"[+] Repaired size    : "
        f"{details['width']}x{details['height']}"
    )
    print(f"[+] IHDR CRC         : {details['ihdr_crc']:08x}")
    print(f"[+] Output           : {args.output}")

    flag = extract_flag_with_tesseract(args.output)
    if flag:
        print(f"<FLAG>{flag}</FLAG>")
    else:
        print("[*] Buka repaired.png untuk membaca flag.")
        print("[*] OCR otomatis membutuhkan tesseract.")


if __name__ == "__main__":
    main()
