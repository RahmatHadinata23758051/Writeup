# All night long...

## Ringkasan

`signal.wav` adalah WAV PCM 16-bit stereo 44.1 kHz. Payload tersembunyi bukan LSB/FSK; kedua channel menyimpan koordinat gambar oscilloscope/vector (X/Y).

## Temuan Penting

- Channel kiri memiliki silence panjang `4.500000–4.650000 s`.
- Channel kanan memiliki silence yang sama tetapi terlambat `1129` sample (`25.601 ms`).
- Setelah payload kedua channel disejajarkan, panjang payload aktif adalah `178260` sample.
- Payload tersebut terdiri dari `60` frame yang identik byte-for-byte.
- Panjang satu frame adalah `2971` sample.
- Plot `left[t]` sebagai X dan `right[t+1129]` sebagai Y menghasilkan tulisan vector.
- Rotasi sekitar `-20°` membuat dua baris tulisan horizontal.
- Garis perpindahan cepat dibuang dengan threshold kecepatan antar-titik agar glyph terbaca bersih.

## Detail yang Menyebabkan Salah Baca Awal

Karakter ketiga pada isi flag bukan ASCII `a`. Glyph memiliki acute accent `´` di atas huruf, sehingga karakter yang benar adalah `á` (U+00E1).

Tulisan yang direkonstruksi:

```
THJCC{
6pákos}
```

Jadi flag:

```
THJCC{δράκος}
```

## Flag

```
THJCC{δράκος}
```

