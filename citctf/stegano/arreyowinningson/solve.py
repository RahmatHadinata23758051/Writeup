#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path

JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"
PATTERN = bytes.fromhex("05145140")


def parse_sos_end(jpeg: bytes) -> int:
    if not jpeg.startswith(JPEG_SOI):
        raise ValueError("Bukan file JPEG valid (SOI tidak ditemukan)")

    i = 2
    n = len(jpeg)
    while i < n:
        if jpeg[i] != 0xFF:
            i += 1
            continue

        while i < n and jpeg[i] == 0xFF:
            i += 1
        if i >= n:
            break

        marker = jpeg[i]
        i += 1

        if marker == 0xD9:
            break

        if marker in (0x01,) or 0xD0 <= marker <= 0xD7:
            continue

        if i + 2 > n:
            raise ValueError("Marker length rusak")

        seg_len = int.from_bytes(jpeg[i : i + 2], "big")

        if marker == 0xDA:  # Start Of Scan
            return i + seg_len

        i += seg_len

    raise ValueError("Marker SOS tidak ditemukan")


def find_extraneous_start(scan_data: bytes) -> int:
    # Payload tersembunyi diawali run pattern 05 14 51 40 yang panjang.
    # Cari run minimal 64 kali (256 byte) agar tidak false positive.
    need = PATTERN * 64
    idx = scan_data.find(need)
    if idx == -1:
        raise ValueError("Tidak menemukan awal extraneous payload")
    return idx


def extract_flag_from_image(image_path: Path) -> str:
    # Pakai tesseract CLI karena tersedia di environment challenge.
    proc = subprocess.run(
        ["tesseract", str(image_path), "stdout"],
        capture_output=True,
        text=True,
        check=False,
    )

    ocr_text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    m = re.search(r"CIT\{[^}\n]+\}", ocr_text)
    if not m:
        raise ValueError("Flag tidak terdeteksi dari OCR")
    return m.group(0)


def main() -> None:
    chall = Path("chall.jpg")
    if not chall.exists():
        raise SystemExit("chall.jpg tidak ditemukan di folder ini")

    b = chall.read_bytes()
    eoi = b.rfind(JPEG_EOI)
    if eoi == -1:
        raise SystemExit("EOI JPEG tidak ditemukan")

    sos_end = parse_sos_end(b)
    scan_data = b[sos_end:eoi]

    extra_start = find_extraneous_start(scan_data)
    extra = scan_data[extra_start:]

    alt = b[:sos_end] + extra + JPEG_EOI
    alt_path = Path("recovered_hidden.jpg")
    alt_path.write_bytes(alt)

    flag = extract_flag_from_image(alt_path)
    print(flag)


if __name__ == "__main__":
    main()
