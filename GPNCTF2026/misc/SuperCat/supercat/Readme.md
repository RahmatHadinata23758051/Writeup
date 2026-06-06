# Writeup Challenge: superCAT

## Deskripsi Challenge
Challenge ini memberikan sebuah binary bernama `supercat` yang ditulis dalam bahasa Rust. Binary ini berfungsi sebagai pengganti `cat` yang "highly opinionated". Berdasarkan source code yang diberikan, binary ini melakukan pengecekan permission secara manual sebelum mengizinkan pembacaan file.

## Analisis Vulnerability
Setelah menganalisis `src/main.rs`, ditemukan kerentanan **TOCTOU (Time-of-Check Time-of-Use)** pada fungsi pengecekan permission.

Binary `supercat` memiliki bit SUID set (berjalan sebagai root). Namun, ia mencoba untuk membatasi pembacaan file berdasarkan UID/GID pengguna yang menjalankannya dengan langkah-langkah berikut:
1. Membaca metadata file target menggunakan `std::fs::metadata(file)`.
2. Mengecek apakah pengguna memiliki hak akses baca (berdasarkan UID, GID, atau group lain).
3. Jika pengecekan lolos, isi file dibaca menggunakan `fs::read_to_string(file)`.

Masalahnya adalah `std::fs::metadata` mengikuti symbolic link. Jika kita memberikan path ke sebuah symlink, `metadata()` akan mengecek file yang dituju oleh symlink tersebut pada saat itu. Kemudian, `read_to_string()` akan membuka file yang dituju oleh symlink tersebut pada saat dipanggil.

Terdapat jendela waktu (race window) antara pemanggilan `metadata()` dan `read_to_string()`. Jika kita bisa mengubah tujuan symlink di antara kedua pemanggilan tersebut, kita bisa melewati pengecekan permission.

## Eksploitasi
Langkah-langkah eksploitasi yang dilakukan:
1. Membuat file yang bisa kita baca (misal: `readable`).
2. Membuat loop yang terus menerus mengubah tujuan sebuah symlink (misal: `link`) antara file `readable` dan file `/flag`.
3. Menjalankan `supercat link` berulang kali.

Jika kita beruntung (memenangkan race condition), `supercat` akan memanggil `metadata()` saat `link` menunjuk ke `readable` (pengecekan lolos), namun memanggil `read_to_string()` saat `link` sudah diubah menunjuk ke `/flag` (flag terbaca karena binary berjalan sebagai root).

## Flag
Setelah menjalankan script race condition sederhana di server target, flag berhasil ditemukan:
**GPNCTF{ru5t_1S_Shit_cHAngE_mY_MInD}**

## Script Solve
Script `solve.py` telah disediakan untuk mengotomatisasi proses ini melalui koneksi ncat.
