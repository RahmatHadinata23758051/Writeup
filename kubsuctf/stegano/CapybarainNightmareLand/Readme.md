# Writeup: Capybara in Nightmare Land

## Informasi Challenge
- **Kategori**: Misc / Steganography
- **Judul**: Capybara in Nightmare Land
- **Deskripsi**: Mencari pesan rahasia yang ditinggalkan oleh seekor kapibara dalam mimpinya.

## Langkah Penyelesaian

### 1. Analisis Awal
Langkah pertama adalah melakukan enumerasi dasar pada file `capybara_nightmare.png`. Menggunakan tool `binwalk` dan `exiftool`, ditemukan bahwa terdapat data tambahan setelah chunk IEND (trailer data).
```bash
binwalk capybara_nightmare.png
```
Hasil menunjukkan adanya ZIP archive yang tersembunyi di akhir file PNG.

### 2. Ekstraksi Data Tersembunyi
Data ZIP tersebut diekstrak menggunakan `binwalk -e`. Di dalamnya terdapat dua file:
- `README.txt`
- `encrypted_flag.bin`

Isi dari `README.txt` memberikan informasi krusial:
- Flag dienkripsi menggunakan XOR.
- Key disembunyikan di dalam pixel gambar asli menggunakan teknik LSB (Least Significant Bit).
- Panjang key adalah 19 karakter.
- Diberikan juga hex dari encrypted flag: `0544053b20384f3a03333a6b3d49334b6f71573e482f09370605004e`.

### 3. Mencari XOR Key (LSB Extraction)
Dibuat skrip Python untuk mengekstrak bit LSB dari gambar. Eksperimen dilakukan dengan mencoba berbagai urutan (interleaved RGB vs per channel).
Ditemukan bahwa pada LSB yang di-interleave (R1, G1, B1, R2, G2, B2, ...), terdapat string yang terbaca di awal data:
`N1ghtm4r3_C4py_2026`

String ini memiliki panjang tepat 19 karakter, sesuai dengan petunjuk.

### 4. Dekripsi Flag
Dengan key `N1ghtm4r3_C4py_2026` dan data terenkripsi yang ada, proses dekripsi XOR dilakukan:
```python
key = "N1ghtm4r3_C4py_2026"
encrypted_hex = "0544053b20384f3a03333a6b3d49334b6f71573e482f09370605004e"
encrypted = bytes.fromhex(encrypted_hex)
flag = ''.join(chr(b ^ ord(key[i % len(key)])) for i, b in enumerate(encrypted))
print(flag)
```

## Hasil
Flag yang ditemukan: `KubSTU{H0ly_M0ly_CapyHaCk1r}`
