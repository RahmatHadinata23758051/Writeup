#!/usr/bin/env python3
"""
Ghost Layers - solve script
----------------------------
Ide vuln: beaver.svg punya <g id="s17"> berisi glyph path (huruf yang sudah
di-convert jadi outline path, bukan <text>), yang dipakai sebagai clip-path
("cp4") untuk layer "ghost-wash". Secara visual layer ini cuma kelihatan
sebagai glow tipis di belakang gambar beaver, jadi teksnya nggak pernah
"terbaca" langsung dari hasil render penuh -> makanya judulnya "Ghost Layers".

Script ini:
1. Ekstrak grup <g id="s17"> langsung dari SVG (raw string, tanpa parse XML
   supaya path data yang panjang gak keubah).
2. Bikin SVG baru cuma isi grup itu di atas background hitam solid.
3. Render ke PNG resolusi tinggi pakai cairosvg.
4. Crop area teksnya biar gampang dibaca -> simpan sebagai flag.png.
5. Print flag-nya ke stdout.

Requirement: pip install cairosvg --break-system-packages
"""

import re
import cairosvg
from PIL import Image

SVG_PATH = "beaver.svg"
OUT_FULL = "text_only.svg"
OUT_PNG_RAW = "text_render.png"
OUT_PNG_FINAL = "flag.png"

VIEWBOX_W = 577
VIEWBOX_H = 635
RENDER_SCALE = 6  # px per svg-unit -> render gede biar tajam

# area kira-kira tempat teks hidden itu duduk (hasil inspeksi manual):
# glyph group di-translate ke y=454 dengan scale -0.0094, jadi rentang
# vertikalnya ada di sekitar y=430-460 pada viewBox asli.
CROP_Y0 = 420
CROP_Y1 = 480


def extract_hidden_glyphs(svg_text: str) -> str:
    """Ambil grup <g id="s17">...</g></g> yang isinya path-path glyph flag."""
    m = re.search(r'(<g id="s17">.*?</g></g>)', svg_text, re.DOTALL)
    if not m:
        raise RuntimeError("Grup s17 (hidden glyph paths) tidak ketemu di SVG")
    return m.group(1)


def build_standalone_svg(glyph_group: str) -> str:
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {VIEWBOX_W} {VIEWBOX_H}"
     width="{VIEWBOX_W}" height="{VIEWBOX_H}">
  <rect x="0" y="0" width="{VIEWBOX_W}" height="{VIEWBOX_H}" fill="black"/>
  {glyph_group}
</svg>'''


def main():
    svg_text = open(SVG_PATH, encoding="utf-8").read()

    glyph_group = extract_hidden_glyphs(svg_text)
    standalone_svg = build_standalone_svg(glyph_group)
    open(OUT_FULL, "w", encoding="utf-8").write(standalone_svg)

    # render full canvas dulu
    cairosvg.svg2png(
        url=OUT_FULL,
        write_to=OUT_PNG_RAW,
        output_width=VIEWBOX_W * RENDER_SCALE,
        output_height=VIEWBOX_H * RENDER_SCALE,
    )

    # crop cuma bagian yang ada teksnya biar rapi jadi satu PNG kebaca jelas
    img = Image.open(OUT_PNG_RAW)
    y0 = int(CROP_Y0 * RENDER_SCALE)
    y1 = int(CROP_Y1 * RENDER_SCALE)
    cropped = img.crop((0, y0, img.width, y1))
    cropped.save(OUT_PNG_FINAL)

    print(f"[+] Rendered hidden glyph layer -> {OUT_PNG_FINAL}")
    print("[+] Baca manual teks pada gambar tsb untuk konfirmasi flag.")
    print("[+] Flag hasil ekstraksi:")
    print("grodno{h1dd3n_1n_pl41n_svg_l4y3r}")


if __name__ == "__main__":
    main()
