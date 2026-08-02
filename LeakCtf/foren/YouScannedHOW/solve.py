#!/usr/bin/env python3
import json
import re
import sqlite3
import subprocess
from pathlib import Path

import numpy as np
from PIL import Image, ImageEnhance, ImageOps

ARCHIVE = Path("scan2.7z")
DB = Path("scan2.sqlite")
OUT = Path("scan2_angle0_projection.png")
FLAG = "L3AK{CT_Sc4Ns_R_jU57_L0t5_0F_Xr4y5!!}"


def ensure_db():
    if DB.exists():
        return
    if not ARCHIVE.exists():
        raise SystemExit("scan2.sqlite tidak ada, dan scan2.7z juga tidak ada")
    print("[+] extracting scan2.7z")
    subprocess.run(["7z", "x", "-y", str(ARCHIVE)], check=True)
    if not DB.exists():
        raise SystemExit("extract selesai, tapi scan2.sqlite tidak ditemukan")


def load_angle0_projection():
    con = sqlite3.connect(DB)
    cur = con.cursor()

    tables = [
        row[0]
        for row in cur.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name LIKE 'slice_%cm'"
        )
    ]

    if not tables:
        raise SystemExit("tidak ada table slice_*cm di database")

    def slice_pos(name):
        m = re.fullmatch(r"slice_(\d+)cm", name)
        if not m:
            return 10**18
        return int(m.group(1))

    tables.sort(key=slice_pos)

    rows = []
    for table in tables:
        row = cur.execute(
            f"SELECT detector_count, light_values FROM {table} "
            "WHERE angle_degrees = 0"
        ).fetchone()
        if row is None:
            continue
        _, raw = row
        rows.append(np.array(json.loads(raw), dtype=np.float32))

    con.close()

    if not rows:
        raise SystemExit("angle_degrees = 0 tidak ditemukan")

    width = max(len(r) for r in rows)
    mat = np.zeros((len(rows), width), dtype=np.float32)

    # Detector count antar angle/slice bisa beda. Centering menjaga posisi proyeksi.
    for y, values in enumerate(rows):
        start = (width - len(values)) // 2
        mat[y, start:start + len(values)] = values

    return mat


def save_projection_image(mat):
    lo, hi = np.percentile(mat, [1, 99.5])
    img = np.clip((mat - lo) / (hi - lo) * 255, 0, 255).astype(np.uint8)

    im = Image.fromarray(img)

    # Orientasi yang membuat flag terbaca dari kiri ke kanan.
    im = ImageOps.invert(im)
    im = ImageOps.mirror(im).transpose(Image.Transpose.ROTATE_90)

    # Buang border kosong/abu-abu, tambah kontras, lalu scale supaya gampang dibaca.
    im = im.crop((0, 70, im.width, min(730, im.height)))
    im = ImageEnhance.Contrast(im).enhance(2.5)
    im = im.point(lambda p: 0 if p < 150 else 255)
    im = im.resize((im.width * 3, im.height * 2), Image.Resampling.NEAREST)
    im.save(OUT)
    return OUT


def main():
    ensure_db()
    mat = load_angle0_projection()
    out = save_projection_image(mat)
    print(f"[+] angle-0 projection shape: {mat.shape[0]} slices x {mat.shape[1]} detectors")
    print(f"[+] evidence image written: {out}")
    print(f"[+] flag: {FLAG}")


if __name__ == "__main__":
    main()
