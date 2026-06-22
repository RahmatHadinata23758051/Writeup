# boroCTF 2026 - Next Challenge (Pwn)

## Analisis Masalah
Tantangan ini merupakan tipe *blind challenge* tanpa file binary yang disediakan. Berdasarkan interaksi awal dengan layanan netcat, program bertindak sebagai menu interaktif bernama `VULNBOT` dengan dua opsi utama: `cheese` dan `flag`.

Jika pengguna memilih `cheese`, program langsung keluar dan menampilkan pesan jebakan. 

## Langkah Eksploitasi
Eksploitasi hanya membutuhkan interaksi logika menu sederhana:
1. Jalankan koneksi netcat ke server target.
2. Masukkan perintah `flag` pada prompt utama.
3. Saat program memberikan konfirmasi pencegahan `Are you SURE you don't want to see what the Cheese option does? (y/n)`, jawab dengan `y` (yes).
4. Program akan langsung mencetak flag ke layar.
