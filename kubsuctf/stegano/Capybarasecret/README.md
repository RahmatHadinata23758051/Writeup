# Capybara Secret

Challenge ini ternyata tidak butuh teknik steganografi yang rumit di level piksel. Kalimat deskripsinya, *"look beyond the surface"*, mengarah ke hal yang tidak langsung terlihat saat gambar dibuka biasa, yaitu metadata file.

## Langkah analisis

Pertama saya enumerasi file yang diberikan:

```bash
ls -la
file chall.jpg
```

Hasilnya hanya ada satu file `chall.jpg`, berupa JPEG biasa.

Lalu saya cek metadata:

```bash
exiftool chall.jpg
```

Di output `exiftool` ada field yang langsung mencurigakan:

```text
XP Comment : XhoFGH{J0J_1aperq1oyr_pnclon6n}
```

String ini tidak tampak seperti teks acak penuh, karena polanya sangat mirip format flag. Huruf-hurufnya terlihat seperti hasil substitusi sederhana. Saya coba ROT13:

```bash
python3 - <<'PY'
import codecs
s = 'XhoFGH{J0J_1aperq1oyr_pnclon6n}'
print(codecs.decode(s, 'rot_13'))
PY
```

Hasil decode:

```text
KubSTU{W0W_1ncred1ble_capyba6a}
```

Formatnya cocok dengan flag challenge lain di event yang sama, jadi ini adalah flag validnya.

## Kenapa ini works

Field `XP Comment` adalah bagian dari metadata EXIF. Isinya disimpan di dalam file JPEG, tetapi tidak terlihat saat gambar dibuka normal. Jadi "secret visible only to those who can look beyond the surface" maksudnya bukan membongkar warna atau LSB gambar, melainkan memeriksa informasi di balik tampilan visual file.

Setelah metadata ditemukan, lapisan obfuscation-nya cuma ROT13.

## Solver

Solver final ada di `solve.py`. Script itu:

1. Membuka `chall.jpg`
2. Mengambil tag EXIF `XP Comment`
3. Decode nilainya dari UTF-16LE
4. Menjalankan ROT13
5. Mencetak flag

Jalankan dengan:

```bash
python3 solve.py
```

## Flag

```text
KubSTU{W0W_1ncred1ble_capyba6a}
```
