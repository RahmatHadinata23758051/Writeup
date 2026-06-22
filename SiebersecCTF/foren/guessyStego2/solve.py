from __future__ import annotations

import re
import sys
import zipfile
from pathlib import Path

import numpy as np
from PIL import Image

FLAG_RE = re.compile(r"[A-Za-z0-9_]+CTF\{[^}]+\}|sctf\{[^}]+\}|flag\{[^}]+\}")


def load_image(path: Path) -> Image.Image:
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as zf:
            names = [n for n in zf.namelist() if not n.endswith("/")]
            pngs = [n for n in names if n.lower().endswith(".png")]
            if not pngs:
                raise SystemExit("no PNG inside zip")
            with zf.open(pngs[0]) as fp:
                return Image.open(fp).convert("RGBA")
    return Image.open(path).convert("RGBA")


def decode_qr(img: Image.Image) -> str | None:
    # pyzbar is fast when libzbar is available.
    try:
        from pyzbar.pyzbar import decode as zbar_decode

        hits = zbar_decode(img)
        if hits:
            return hits[0].data.decode("utf-8", "replace")
    except Exception:
        pass

    # OpenCV fallback.
    try:
        import cv2

        arr = np.array(img.convert("L"))
        detector = cv2.QRCodeDetector()
        for scale in (1, 2, 3, 4):
            cur = arr
            if scale != 1:
                cur = cv2.resize(arr, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
            data, _points, _straight = detector.detectAndDecode(cur)
            if data:
                return data
    except Exception:
        pass

    return None


def main() -> None:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("dist.zip")
    im = load_image(src)
    alpha = np.array(im)[:, :, 3]

    # The image is visually opaque, but alpha values are 254/255. The LSB stream
    # is a flattened QR image. Brute force the square side and decode each shape.
    bits = (alpha & 1).reshape(-1).astype(np.uint8)
    max_side = int(len(bits) ** 0.5)

    for side in range(21, max_side + 1):
        qr = (bits[: side * side].reshape(side, side) * 255).astype(np.uint8)
        for inverted in (False, True):
            cur = 255 - qr if inverted else qr
            pil = Image.fromarray(cur, mode="L")
            text = decode_qr(pil)
            if not text:
                continue
            m = FLAG_RE.search(text)
            if m:
                print(m.group(0))
                return
            print(text)
            return

    raise SystemExit("QR not decoded")


if __name__ == "__main__":
    main()
