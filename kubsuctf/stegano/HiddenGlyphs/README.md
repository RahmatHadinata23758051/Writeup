# Hidden Glyphs Writeup

Challenge ini terlihat seperti PDF biasa, tetapi hint-nya sangat spesifik: "the breadth of one's view determines the depth of understanding." Kata *breadth* di sini mengarah ke lebar, dan metadata PDF juga memberi petunjuk `font encoding`. Dari situ, fokus analisis diarahkan ke struktur internal PDF, terutama object font, encoding, dan tabel `Widths`.

## Langkah Analisis

Pertama, file diidentifikasi sebagai PDF 1 halaman tanpa enkripsi dan tanpa attachment tersembunyi. Metadata yang paling menarik:

- `Keywords: classified secret font encoding`
- `Producer: PDF Steganography Engine`

Setelah itu isi PDF dibongkar dengan `qpdf --qdf --object-streams=disable stego_challenge.pdf -`. Dari sana terlihat bahwa halaman memakai dua font:

- `F2`: Helvetica biasa
- `F1`: font `Type3` kustom

Teks hint di halaman:

- `The font hides more than you see...`
- `Each glyph has a width. What do they tell?`

Ini mengonfirmasi bahwa data disisipkan di properti font, bukan di teks visualnya.

## Temuan Penting

Object font `F1` memiliki:

- `FirstChar 48`
- `LastChar 122`
- `Widths [...]`

Isi array `Widths` dimulai seperti ini:

```text
750 1170 980 830 840 850 1230 1160 1210 1120 ...
```

Nilai-nilai ini semuanya kelipatan 10. Saat masing-masing dibagi 10 lalu diubah ke ASCII:

- `750 -> 75 -> 'K'`
- `1170 -> 117 -> 'u'`
- `980 -> 98 -> 'b'`

dan seterusnya.

Hasil decode seluruh bagian bermakna dari array:

```text
KubSTU{typ3_3_f0nt_w1dth5_4r3_tr1cky}
```

Sisa nilai `500` hanya menghasilkan karakter `2` berulang dan merupakan padding/noise agar format font tetap konsisten sampai `LastChar 122`.

## Kesimpulan

Flag disembunyikan langsung di tabel `Widths` milik font `Type3`. Teknik ini efektif karena dokumen tetap terlihat normal, tetapi data sebenarnya berada di metrik glyph, bukan di konten teks yang tampak.

## Command yang Dipakai

```bash
file stego_challenge.pdf
pdfinfo stego_challenge.pdf
pdftotext stego_challenge.pdf -
qpdf --qdf --object-streams=disable stego_challenge.pdf -
```

## Decode Singkat

```python
widths = [750,1170,980,830,840,850,1230,1160,1210,1120,510,950,510,950,1020,480,1100,1160,950,1190,490,1000,1160,1040,530,950,520,1140,510,950,1160,1140,490,990,1070,1210,1250]
flag = ''.join(chr(w // 10) for w in widths)
print(flag)
```

Output:

```text
KubSTU{typ3_3_f0nt_w1dth5_4r3_tr1cky}
```
