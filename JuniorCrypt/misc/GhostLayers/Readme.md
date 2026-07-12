# Ghost Layers (Misc)

**CTF**: Grodno CTF 2026
**Category**: Misc
**Points**: -
**Flag**: `grodno{h1dd3n_1n_pl41n_svg_l4y3r}`

## Deskripsi

> What stays visible is not always what matters most.

File yang dikasih cuma satu: `beaver.svg`, ilustrasi beaver dengan tema "ghost" — ada moon glow, garis-garis dekoratif, dan siluet ghost transparan di belakangnya. Kelihatannya cuma gambar biasa.

## Analisis

Buka source SVG-nya langsung (bukan cuma di-render), terus grep buat elemen yang biasanya dipakai buat nyembunyiin sesuatu: `mask`, `clipPath`, `opacity`, `<text>`.

Ketemu tiga hal yang saling nyambung:

```xml
<clipPath id="cp4">
  <use href="#s17"/>
</clipPath>
...
<g id="ghost-wash" opacity="0.72" mask="url(#mk9)" filter="url(#glowSoft)">
  <g clip-path="url(#cp4)">
    ...
```

`ghost-wash` (layer glow/ghost yang paling mencolok secara visual) di-clip pakai `cp4`, dan `cp4` cuma nge-`use` grup `#s17`. Grup `s17` sendiri isinya bukan gambar ghost — isinya puluhan `<path>` dengan koordinat gaya font-outline (angka gede, pakai kurva Q, tiap path punya `transform="translate(N,0)"` yang naik konsisten ~1233 unit tiap elemen).

Itu ciri khas glyph yang di-convert jadi path (font-to-outline), biasanya dari matplotlib/fonttools. Advance 1233 unit tiap glyph = lebar karakter di font itu. Total ada 39 path/glyph berturut-turut → itu bukan dekorasi, itu string yang di-outline biar nggak kebaca sebagai `<text>` biasa dan nggak keliatan jelas pas di-render penuh (ketutupan gambar beaver + opacity rendah).

Jadi vuln-nya sederhana: **teks flag disimpan sebagai clip-path/mask, bukan sebagai text node**, sehingga secara visual dia cuma numpang bentuk buat efek glow, padahal isinya adalah bentuk huruf flag itu sendiri.

## Eksploitasi

Langkahnya:

1. Ambil grup `<g id="s17">...</g>` mentah dari SVG pakai regex (bukan XML parser biasa, soalnya path data-nya panjang banget dan gampang berantakan kalau di-reparse).
2. Bungkus grup itu ke SVG baru, background hitam solid, tanpa layer lain (jadi nggak ketutupan gambar beaver/ghost).
3. Render SVG itu ke PNG resolusi tinggi pakai `cairosvg`.
4. Crop area vertikal tempat teksnya nongol (sekitar y=420–480 di viewBox asli), biar hasilnya satu baris teks yang gampang dibaca.

Hasil render:

```
grodno{9l0ry_t0_Al1v@r1@_9l0ry_t0_b33r}
```

