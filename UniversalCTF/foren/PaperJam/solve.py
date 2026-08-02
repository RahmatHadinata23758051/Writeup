#!/usr/bin/env python3
"""Repair shipping_notice.pdf and recover the authorization token."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np
from PIL import Image


OBJECT_RE = re.compile(rb"(?m)^([1-9][0-9]*) 0 obj(?:\r?\n)")
FLAG_RE = re.compile(r"uctf\{([0-9a-fA-F]{16})\}")
HEX_RE = re.compile(r"[0-9a-fA-F]{16}")


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"required command is missing: {name}")
    return path


def repair_pdf(source: Path, destination: Path) -> tuple[int, int]:
    data = source.read_bytes()

    if not data.startswith(b"%P0F-") and not data.startswith(b"%PDF-"):
        raise RuntimeError("unexpected file header; expected %P0F- or %PDF-")

    matches = list(OBJECT_RE.finditer(data))
    if not matches:
        raise RuntimeError("no indirect PDF objects were found")

    offsets = {int(match.group(1)): match.start() for match in matches}
    maximum = max(offsets)

    expected = set(range(1, maximum + 1))
    missing = sorted(expected - offsets.keys())

    if missing:
        raise RuntimeError(
            f"object sequence is incomplete; missing: {missing[:20]}"
        )

    # Perbaiki signature %P0F menjadi %PDF.
    # Panjang header tidak berubah sehingga offset object tetap valid.
    fixed = b"%PDF" + data[4:]

    if not fixed.endswith((b"\n", b"\r")):
        fixed += b"\n"

    xref_offset = len(fixed)

    xref = bytearray()
    xref += f"xref\n0 {maximum + 1}\n".encode("ascii")
    xref += b"0000000000 65535 f \n"

    for number in range(1, maximum + 1):
        xref += f"{offsets[number]:010d} 00000 n \n".encode("ascii")

    xref += (
        "trailer\n"
        f"<< /Size {maximum + 1} /Root 1 0 R >>\n"
        "startxref\n"
        f"{xref_offset}\n"
        "%%EOF\n"
    ).encode("ascii")

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(fixed + xref)

    return maximum, xref_offset


def render_second_page(
    pdf: Path,
    output_png: Path,
    dpi: int = 600,
) -> None:
    pdftoppm = require_tool("pdftoppm")
    prefix = output_png.with_suffix("")

    subprocess.run(
        [
            pdftoppm,
            "-f",
            "2",
            "-l",
            "2",
            "-singlefile",
            "-r",
            str(dpi),
            "-png",
            str(pdf),
            str(prefix),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    generated = prefix.with_suffix(".png")

    if generated != output_png:
        generated.replace(output_png)

    if not output_png.exists():
        raise RuntimeError("pdftoppm did not create the rendered page")


def extract_token_crop(
    page_png: Path,
    crop_png: Path,
) -> None:
    image = Image.open(page_png).convert("RGB")
    pixels = np.asarray(image)

    r = pixels[:, :, 0].astype(np.int16)
    g = pixels[:, :, 1].astype(np.int16)
    b = pixels[:, :, 2].astype(np.int16)

    # Stempel authorization merupakan area merah terbesar di halaman.
    red_mask = (
        (r > 100)
        & ((r - g) > 30)
        & ((r - b) > 30)
    )

    ys, xs = np.where(red_mask)

    if xs.size == 0:
        raise RuntimeError("red authorization stamp was not found")

    x0 = int(xs.min())
    x1 = int(xs.max()) + 1
    y0 = int(ys.min())
    y1 = int(ys.max()) + 1

    width = x1 - x0
    height = y1 - y0

    if width < image.width * 0.20:
        raise RuntimeError("detected red region is too small")

    if height < image.height * 0.03:
        raise RuntimeError("detected red region is too small")

    # Hilangkan border stempel dan tulisan label bagian bawah.
    # Token berada pada bagian atas stempel.
    search_x0 = x0 + int(width * 0.03)
    search_x1 = x1 - int(width * 0.03)

    search_y0 = y0 + int(height * 0.15)
    search_y1 = y0 + int(height * 0.62)

    inner_mask = red_mask[
        search_y0:search_y1,
        search_x0:search_x1,
    ]

    inner_y, inner_x = np.where(inner_mask)

    if inner_x.size == 0:
        raise RuntimeError("token line was not found inside the stamp")

    token_x0 = int(inner_x.min()) + search_x0
    token_x1 = int(inner_x.max()) + 1 + search_x0

    token_y0 = int(inner_y.min()) + search_y0
    token_y1 = int(inner_y.max()) + 1 + search_y0

    token_width = token_x1 - token_x0
    token_height = token_y1 - token_y0

    # Tambahkan margin agar karakter pertama dan terakhir tidak terpotong.
    left = max(
        0,
        token_x0 - int(token_width * 0.065),
    )

    right = min(
        image.width,
        token_x1 + int(token_width * 0.123),
    )

    top = max(
        0,
        token_y0 - int(token_height * 0.35),
    )

    bottom = min(
        image.height,
        token_y1 + int(token_height * 0.35),
    )

    token_crop = image.crop(
        (
            left,
            top,
            right,
            bottom,
        )
    )

    crop_png.parent.mkdir(parents=True, exist_ok=True)
    token_crop.save(crop_png)


def run_ocr(crop_png: Path) -> tuple[str, str]:
    tesseract = require_tool("tesseract")

    command = [
        tesseract,
        str(crop_png),
        "stdout",
        "--psm",
        "13",
        "-c",
        "tessedit_char_whitelist="
        "uctf{}0123456789abcdefABCDEF",
    ]

    result = subprocess.run(
        command,
        check=True,
        text=True,
        capture_output=True,
    )

    raw = result.stdout.strip()
    compact = re.sub(r"\s+", "", raw)

    flag_match = FLAG_RE.search(compact)

    if flag_match:
        token = flag_match.group(1).lower()
        return raw, token

    # Tesseract kadang tidak membaca kurung kurawal pembuka.
    # Prefix uctf dihapus, kemudian dicari 16 karakter hexadecimal.
    without_prefix = re.sub(
        r"(?i)uctf",
        "",
        compact,
    )

    hex_match = HEX_RE.search(without_prefix)

    if not hex_match:
        raise RuntimeError(
            "OCR did not produce a 16-character hexadecimal token: "
            f"{raw!r}"
        )

    token = hex_match.group(0).lower()
    return raw, token


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Repair the damaged Paper Jam PDF "
            "and recover its authorization token."
        )
    )

    parser.add_argument(
        "pdf",
        nargs="?",
        type=Path,
        default=Path("shipping_notice.pdf"),
        help="damaged PDF file",
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("paperjam_output"),
        help="output directory",
    )

    args = parser.parse_args()

    if not args.pdf.is_file():
        parser.error(
            f"input file does not exist: {args.pdf}"
        )

    repaired_pdf = (
        args.output_dir
        / "shipping_notice_repaired.pdf"
    )

    rendered_page = (
        args.output_dir
        / "page-2.png"
    )

    token_crop = (
        args.output_dir
        / "authorization_token.png"
    )

    try:
        maximum_object, xref_offset = repair_pdf(
            args.pdf,
            repaired_pdf,
        )

        render_second_page(
            repaired_pdf,
            rendered_page,
        )

        extract_token_crop(
            rendered_page,
            token_crop,
        )

        raw_ocr, token = run_ocr(
            token_crop,
        )

    except (
        OSError,
        RuntimeError,
        subprocess.CalledProcessError,
    ) as error:
        print(
            f"[-] {error}",
            file=sys.stderr,
        )
        raise SystemExit(1)

    print(
        f"[+] objects recovered : "
        f"1..{maximum_object}"
    )

    print(
        f"[+] xref offset       : "
        f"{xref_offset}"
    )

    print(
        f"[+] repaired PDF      : "
        f"{repaired_pdf}"
    )

    print(
        f"[+] rendered page     : "
        f"{rendered_page}"
    )

    print(
        f"[+] token crop        : "
        f"{token_crop}"
    )

    print(
        f"[+] OCR raw           : "
        f"{raw_ocr}"
    )

    print(
        f"[+] token             : "
        f"{token}"
    )

    print(f"uctf{{{token}}}")


if __name__ == "__main__":
    main()
