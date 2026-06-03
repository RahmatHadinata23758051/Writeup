# Writeup: Easy Mode (Misc/Jail) - BYUCTF

## Deskripsi Challenge
Target memberikan akses ke sebuah shell Bash interaktif, namun dengan batasan yang sangat ketat:
1.  **Space Removal**: Semua spasi yang diinputkan dihapus oleh sistem backend sebelum dieksekusi.
2.  **Restricted PATH**: Perintah standar seperti `ls` atau `cat` tidak dapat ditemukan (kemungkinan `PATH` dikosongkan).
3.  **Kata Terlarang**: Ada indikasi filter terhadap kata-kata tertentu (seperti `flag`), meskipun akhirnya bisa diatasi dengan wildcard.

Tujuan kita adalah membaca isi file `flag.txt` di direktori `/app`.

## Langkah-langkah Penyelesaian

### 1. Menemukan Masalah Utama
Saat mencoba perintah normal seperti `ls` atau `echo *`, sistem memberikan pesan error:
- Input `ls` -> `bash: ls: command not found`
- Input `echo *` -> `bash: echo*: command not found` (Spasi hilang dan menjadi satu string `echo*`).

### 2. Bypass Filter Spasi
Untuk menjalankan perintah dengan argumen tanpa karakter spasi, kita bisa menggunakan **Brace Expansion** di Bash. Format `{perintah,argumen}` akan dievaluasi oleh Bash sebagai `perintah argumen`.

Contoh penemuan file:
```bash
$ {echo,*}
# Output: bash flag.txt run
