# 67

## Ringkasan

File `intercepted.enc` bukan binary mentah, melainkan teks hexdump. Proses penyelesaiannya terdiri dari dua layer utama:

1. Parsing hexdump untuk mengambil byte sebenarnya.
2. Decode Base92-style, kemudian decrypt menggunakan affine cipher.

Clue dari deskripsi membantu mengarahkan proses:

* **“Walking through the dumps”** → ambil byte dari hexdump.
* **“92nd street”** → gunakan Base92/Base92-style decoding.
* **“so fine”** → gunakan affine cipher.
* **“reflection”** → menjadi petunjuk untuk memeriksa hasil transformasi pada layer berikutnya.

**Flag final:**

```text id="6xq8xg"
Thryve{67_7h3_c0m3b4CK_417f4}
```

## Analisis Awal

Isi `intercepted.enc` berupa hexdump:

```text id="c1pn5n"
00000000  3d 78 31 7b 61 51  |=x1{aQ|
00000006  65 33 62 29 48 78  |e3b)Hx|
...
```

Jadi file tersebut perlu diperlakukan sebagai representasi hexadecimal, bukan sebagai binary langsung.

## Step 1 — Parse Hexdump

Kolom offset seperti:

```text id="l6n0i2"
00000000
00000006
```

dan preview ASCII yang berada di antara karakter `|` dibuang.

Byte hexadecimal yang tersisa kemudian digabung menjadi satu string:

```text id="q4a6c3"
=x1{aQe3b)HxkERECUQ.c|al:BV=k+RIHFTP
```

String inilah yang digunakan sebagai input untuk layer berikutnya.

## Step 2 — Decode Base92-style

Clue **“92nd street”** mengarah ke encoding Base92/Base92-style.

String tersebut menggunakan alphabet karakter printable ASCII, dengan pengecualian karakter `"` dan `\`.

Decoder kemudian menyusun ulang bitstream menggunakan blok 13-bit untuk setiap dua karakter.

Hasil decoding:

```text id="0sn2bh"
Oqklsx{67_7q3_t0n3e4TJ_417m4}
```

Hasilnya sudah memiliki struktur yang sangat mirip dengan flag:

```text id="y0y7pc"
Oqklsx{...}
```

Namun, prefix `Oqklsx` belum sesuai dengan format flag yang diharapkan.

## Step 3 — Affine Decrypt

Clue **“so fine”** mengarahkan ke affine cipher.

Cipher hanya diterapkan pada karakter alfabet. Angka, underscore, dan kurung kurawal dibiarkan apa adanya.

Parameter yang cocok adalah:

```text id="tr9i5x"
a = 15
b = 15
```

Rumus dekripsi affine:

```text id="t7h6o9"
P = a^-1 × (C - b) mod 26
```

Dengan parameter tersebut, ciphertext:

```text id="m0o1pw"
Oqklsx{67_7q3_t0n3e4TJ_417m4}
```

berubah menjadi:

```text id="l1t8ne"
Thryve{67_7h3_c0m3b4CK_417f4}
```

Angka, underscore, dan delimiter flag tetap tidak berubah selama proses affine.

## Solver

Proses solve dapat diotomatisasi dalam script dengan tahapan:

1. Membaca `intercepted.enc`.
2. Mengambil seluruh byte hexadecimal dari hexdump.
3. Menggabungkan byte menjadi ciphertext.
4. Melakukan Base92-style decoding.
5. Menerapkan affine decryption dengan `a = 15` dan `b = 15`.
6. Mencetak hasil akhir.

## Flag

```text id="c0m9za"
Thryve{67_7h3_c0m3b4CK_417f4}
```

