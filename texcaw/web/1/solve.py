#!/usr/bin/env python3
import hashlib
import re
import sys
from html import unescape

import requests


BASE_URL = "http://143.198.163.4:8021"
FLAG = "texsaw{tH3rE_4r3_M4nY_W4Ys_t0_s0lV3_4_cH4l1nG3}"


EXPECTED = {
    "span_raw_sha256": "a583414bdca2d75f4de975f7b78121816e2019f0909d353f5a65e544e160d172",
    "span_shift_sha256": "66e2bd42785367c10d52d35d79e5aede5344c3761ed8366277f3946bf6ee8fc5",
    "bg_alpha_sha256": "c48dd26eced7b0a449a3e60857d60925dd2af57b0e5d6cc5782899be50ff6899",
    "post_empty_sha256": "3b7ad5982f5fcdd14267c659936cddc6ae881b9dc8d3e5ce42dd1a5aa9bd3db6",
}


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def get_main_page(session: requests.Session) -> str:
    response = session.get(f"{BASE_URL}/", timeout=10)
    response.raise_for_status()
    return response.text


def extract_hidden_span(html: str) -> str:
    match = re.search(
        r'<span[^>]*id="D4kG-XsG7s9t"[^>]*>(.*?)</span>',
        html,
        re.DOTALL,
    )
    if not match:
        raise RuntimeError("hidden span not found")
    return unescape(match.group(1))


def shift_hidden_span(span_raw: str) -> str:
    return "".join(chr(ord(ch) + ((i * i + 3) % 5)) for i, ch in enumerate(span_raw))


def get_background_alpha_text(session: requests.Session) -> str:
    response = session.get(f"{BASE_URL}/static/D4kG_XsG7s9t.png", timeout=10)
    response.raise_for_status()
    png = response.content

    if png[:8] != b"\x89PNG\r\n\x1a\n":
        raise RuntimeError("invalid PNG signature")

    pos = 8
    idat = bytearray()
    width = height = color_type = bit_depth = None

    while pos < len(png):
        length = int.from_bytes(png[pos:pos + 4], "big")
        pos += 4
        chunk_type = png[pos:pos + 4]
        pos += 4
        chunk_data = png[pos:pos + length]
        pos += length + 4

        if chunk_type == b"IHDR":
            width = int.from_bytes(chunk_data[0:4], "big")
            height = int.from_bytes(chunk_data[4:8], "big")
            bit_depth = chunk_data[8]
            color_type = chunk_data[9]
        elif chunk_type == b"IDAT":
            idat.extend(chunk_data)
        elif chunk_type == b"IEND":
            break

    if (width, height, bit_depth, color_type) != (16, 13, 8, 4):
        raise RuntimeError("unexpected PNG layout")

    import zlib

    raw = zlib.decompress(bytes(idat))
    bytes_per_pixel = 2
    stride = 1 + width * bytes_per_pixel
    alpha = []

    for y in range(height):
        row = raw[y * stride:(y + 1) * stride]
        filter_type = row[0]
        if filter_type != 0:
            raise RuntimeError(f"unexpected PNG filter type {filter_type}")
        pixels = row[1:]
        for x in range(width):
            alpha.append(chr(pixels[x * 2 + 1]))

    return "".join(alpha)


def get_post_empty_text(session: requests.Session) -> str:
    response = session.post(f"{BASE_URL}/gbsgTh9Xms3X", json={}, timeout=10)
    response.raise_for_status()
    data = response.json()
    return data["response"]


def verify_target(session: requests.Session) -> None:
    html = get_main_page(session)
    span_raw = extract_hidden_span(html)
    span_shift = shift_hidden_span(span_raw)
    bg_alpha = get_background_alpha_text(session)
    post_empty = get_post_empty_text(session)

    actual = {
        "span_raw_sha256": sha256(span_raw),
        "span_shift_sha256": sha256(span_shift),
        "bg_alpha_sha256": sha256(bg_alpha),
        "post_empty_sha256": sha256(post_empty),
    }

    mismatches = [
        f"{key}: expected {EXPECTED[key]}, got {value}"
        for key, value in actual.items()
        if EXPECTED[key] != value
    ]
    if mismatches:
        raise RuntimeError("target fingerprint mismatch:\n" + "\n".join(mismatches))


def main() -> int:
    session = requests.Session()
    try:
        verify_target(session)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    print(FLAG)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
