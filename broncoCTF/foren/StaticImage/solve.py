#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

import numpy as np

GLYPH_HASHES: dict[str, str] = {
    "c9ddca4ecf858ec649e926ed2dd981a2747fb4269671293da92ca28a1a45926b": "b",
    "2ccbc43e2bd882c41e2960083c64e9405902d1c0836a51ad7736dabcd877d267": "r",
    "068d69c9822a3abfbbd15f2ea8a82f91de3f1f4861f44ee92faa0aaf6899bdb1": "o",
    "f4bebd4998d84d4f7d4ad8b0f3c337fbc79376613cce8fc1aadd15d47a86bdfd": "n",
    "475ab3396ea4f5b33f1d4efd67ffc370b8a59ab4c3d8a941b7e66119967243be": "c",
    "2aaf234080a16d1808debd14539f103a6d439d61c97f8cd772d202e91351fc24": "{",
    "62bd1e284b106e4eeb339b0fbeded5ab30a1d3119eb1fb5a30a88a4d204d6c75": "0",
    "9520e74a5bf310abdbc597fa97c31ad1918dd2f5e7112436d7bb624f40ca2b33": "w",
    "e18e537d32f3c9fbbd5d15727989ccb45e6e9a7359bda18efcf565daaa586f59": "_",
    "41966872516dd7753f8da534bfc043db4e09bae48b29a67276aec2d3f1c23007": "t",
    "0c8e9327c48e26f8b1ad1ed5a30c7367864364e50a5fc265eb6f7200e92697e6": "h",
    "716943d9e26ac6b4acc8ebf99f8568d68b190fdc682706a7e9d2da5d9a752d80": "4",
    "d59d1a72d6843ece0e193a7fb3ef5855dc7d4b5a7124beee8ab63c122b2ace60": "s",
    "d636a0b6cb7f664513a7c8303b999a507ec6ee6cc3604f8e83c9268b42962bd0": "d",
    "060ab74341a64445cfa51919401e228ec681ccd31c6d94fa0fcbdc68f548db88": "y",
    "2a89c3e10076c5e8ec789cf82e684e872c116917408a5da8c6b6e76f4832953f": "m",
    "840541dbe53dfa522352914361fcf3dc765610ade144c2423681d05aed6237c1": "1",
    "700c91637baab9816b4c7ac8f659365bb2b55d0321cef4c2b7feb952c11f64a6": "}",
}


def probe_video(path: Path) -> tuple[int, int]:
    result = subprocess.run(
        [
            "ffprobe", "-v", "error", "-select_streams", "v:0",
            "-show_entries", "stream=width,height", "-of", "json", str(path),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    stream = json.loads(result.stdout)["streams"][0]
    return int(stream["width"]), int(stream["height"])


def extract_masks(path: Path, width: int, height: int) -> list[np.ndarray]:
    frame_size = width * height
    process = subprocess.Popen(
        [
            "ffmpeg", "-hide_banner", "-loglevel", "error", "-i", str(path),
            "-f", "rawvideo", "-pix_fmt", "gray", "-",
        ],
        stdout=subprocess.PIPE,
    )
    if process.stdout is None:
        raise RuntimeError("Gagal membuka output ffmpeg")

    triplet: list[np.ndarray] = []
    masks: list[np.ndarray] = []
    previous_active = False

    while True:
        raw = process.stdout.read(frame_size)
        if not raw:
            break
        if len(raw) != frame_size:
            process.kill()
            raise ValueError("Frame terpotong")

        frame = np.frombuffer(raw, dtype=np.uint8).reshape(height, width) >= 128
        triplet.append(frame)

        if len(triplet) == 3:
            mask = np.logical_xor(triplet[0], triplet[2])
            active = float(mask.mean()) > 0.01

            if active and not previous_active:
                masks.append(mask.copy())

            previous_active = active
            triplet.clear()

    if process.wait() != 0:
        raise RuntimeError("ffmpeg gagal mendecode video")

    return masks


def digest_mask(mask: np.ndarray) -> str:
    return hashlib.sha256(np.packbits(mask.reshape(-1)).tobytes()).hexdigest()


def decode(masks: list[np.ndarray]) -> str:
    chars: list[str] = []
    for index, mask in enumerate(masks):
        digest = digest_mask(mask)
        if digest not in GLYPH_HASHES:
            raise ValueError(f"Glyph {index} tidak dikenal: {digest}")
        chars.append(GLYPH_HASHES[digest])
    return "".join(chars)


def dump_sheet(masks: list[np.ndarray], output: Path) -> None:
    from PIL import Image, ImageDraw

    columns = 5
    height, width = masks[0].shape
    label_height = 24
    rows = (len(masks) + columns - 1) // columns
    sheet = Image.new("L", (columns * width, rows * (height + label_height)), 128)
    draw = ImageDraw.Draw(sheet)

    for index, mask in enumerate(masks):
        x = (index % columns) * width
        y = (index // columns) * (height + label_height)
        sheet.paste(Image.fromarray(mask.astype(np.uint8) * 255), (x, y))
        draw.text((x + 4, y + height + 4), str(index), fill=0)

    output.parent.mkdir(parents=True, exist_ok=True)
    sheet.save(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("video", nargs="?", default="static.mp4")
    parser.add_argument("--dump", type=Path)
    args = parser.parse_args()

    video = Path(args.video)
    width, height = probe_video(video)
    masks = extract_masks(video, width, height)

    if args.dump:
        dump_sheet(masks, args.dump)

    flag = decode(masks)
    if not re.fullmatch(r"bronco\{[a-z0-9_]+\}", flag):
        raise ValueError(f"Format flag tidak valid: {flag}")

    print(f"[+] Active glyph runs: {len(masks)}")
    print(f"[+] Flag: {flag}")


if __name__ == "__main__":
    main()
