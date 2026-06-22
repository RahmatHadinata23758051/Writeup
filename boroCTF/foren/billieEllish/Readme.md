# Billie Eilish - Forensic Writeup

## Analisis Awal
Diberikan sebuah file gambar `chall.jpg`. Langkah pertama adalah melakukan identifikasi dasar menggunakan `file` dan `binwalk`.

```bash
file chall.jpg
binwalk chall.jpg
```

Hasil `binwalk` menunjukkan adanya file ZIP yang terenkripsi di dalam `chall.jpg`.

## Ekstraksi ZIP
Gunakan `binwalk -e` untuk mengekstrak file tersebut. Karena ZIP ini diproteksi password, kita perlu melakukan brute-force menggunakan `fcrackzip` dengan wordlist `rockyou.txt`.

```bash
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt _chall.jpg.extracted/20EBB.zip
```

Password ditemukan: `badguy`.

## Analisis File Kedua
Gunakan password tersebut untuk mengekstrak isi ZIP, yang berisi file `eilish.png`.

```bash
7z x _chall.jpg.extracted/20EBB.zip -pbadguy
```

Meskipun namanya `eilish.png`, file ini sebenarnya adalah JPEG (JFIF). Di dalam file ini terdapat metadata C2PA yang sangat kompleks. Flag ditemukan tersembunyi di dalam data atau visual dari file `eilish.png` ini.

**Flag:** `boroCTF{im_a_good_guy}`
