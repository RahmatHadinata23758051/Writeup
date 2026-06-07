# Writeup Warmerer Up - DalCTF 2026

## Deskripsi Challenge
Challenge ini memberikan sebuah file PDF bernama `rules2.pdf`. Deskripsinya menyinggung tentang aturan yang diberikan berulang kali ("What, what, the rules again again?").

## Analisis Awal
1.  **Identifikasi File**: File `rules2.pdf` adalah dokumen PDF standar. Namun, ukurannya cukup besar (~5.1 MB) untuk sebuah dokumen yang hanya berisi 3 halaman teks.
2.  **Pengecekan Teks**: Menggunakan `pdftotext` menunjukkan isi aturan CTF biasa. Di akhir teks terdapat string mencurigakan: `teapot_2026`.
3.  **Struktur PDF**: Saat memeriksa struktur internal PDF menggunakan `strings` atau hex editor, ditemukan banyak objek stream yang diawali dengan label `@@0:`, `@@1:`, dst.
    *   Ada total 360 chunk (0-359).
    *   Isi chunk tersebut terlihat seperti data Base64.
    *   Decode awal pada chunk 0 (`@@0:`) menunjukkan header file ZIP (`PK\x03\x04`).

## Langkah Penyelesaian
1.  **Ekstraksi Data**: Dibuat script Python (`solve.py`) untuk mengambil semua data dari label `@@i:` di dalam file PDF, menggabungkannya, dan men-decode-nya dari Base64.
2.  **Reassemblasi ZIP**: Hasil decode Base64 disimpan sebagai `extracted.zip`.
3.  **Membuka ZIP**: File `extracted.zip` ternyata diproteksi password. Menggunakan petunjuk `teapot_2026` dari teks PDF sebagai password, file di dalamnya berhasil diekstrak. File tersebut bernama `image.sif`.
4.  **Analisis SIF**: File `image.sif` adalah *Singularity Image Format*. Di dalamnya terdapat sistem file terkompresi.
5.  **Ekstraksi SquashFS**: Menggunakan `binwalk`, ditemukan header SquashFS pada offset `36864`. File sistem ini kemudian diekstrak menggunakan `unsquashfs`.
6.  **Menemukan Flag**: Di dalam hasil ekstraksi SquashFS, ditemukan file `flag.txt` di direktori `/home/flag/flag.txt`.

## Flag
<FLAG>dalctf{n0w_y0u_r3ally_b3tt3r_kn0w_th3_rul3s}</FLAG>
