# Writeup Challenge: Mutant

## Deskripsi
Challenge ini memberikan sebuah file PDF bernama `crypt.pdf`. Deskripsi challenge menyebutkan tentang materi perkuliahan keamanan informasi di universitas politeknik (KubSTU).

## Analisis
1.  **Identifikasi Awal**:
    File `crypt.pdf` adalah dokumen PDF standar. Saat dibuka dengan PDF reader biasa atau dikonversi ke teks menggunakan `pdftotext`, dokumen tersebut menampilkan teks sejarah singkat kriptografi. Namun, `pdftotext` mengeluarkan peringatan: `Syntax Error: Unknown compression method in flate stream`.

2.  **Pemeriksaan Struktur PDF**:
    Menggunakan perintah `strings` dan inspeksi manual terhadap objek-objek PDF, ditemukan bahwa objek ke-5 (`5 0 obj`) memiliki stream konten yang mencurigakan. Stream ini dideklarasikan menggunakan filter `/FlateDecode`, namun datanya diawali dengan `<~` dan diakhiri dengan `~>`, yang merupakan penanda untuk encoding **ASCII85**.

3.  **Ekstraksi Data Tersembunyi**:
    Kesalahan (atau "mutasi") pada filter PDF ini (menggunakan ASCII85 di dalam stream yang seharusnya raw zlib) menyebabkan data tersebut tidak terbaca oleh PDF reader standar. Dengan mengekstrak data di antara `<~` dan `~>`, men-decode-nya dari ASCII85, dan kemudian men-dekompresi hasilnya menggunakan `zlib`, kita mendapatkan isi stream yang sebenarnya.

4.  **Menemukan Flag**:
    Hasil dekompresi berisi banyak perintah operator teks PDF (`BT`, `Tm`, `Tj`, `ET`). Di dalamnya terdapat beberapa string yang terlihat seperti flag:
    *   `KubSTU{pdf_0bj3ct_m4st3r_v2}` (pada koordinat y=100)
    *   `FAKE{this_is_not_the_flag_try_harder}` (pada koordinat y=300)
    *   `CTF{you_are_close_but_not_yet}` (pada koordinat y=450)

    Sesuai dengan konteks challenge yang menyebutkan "polytechnic university" (KubSTU / КубГТУ), flag yang benar adalah yang memiliki prefix `KubSTU`.

## Flag
**KubSTU{pdf_0bj3ct_m4st3r_v2}**
