# SiebersecCTF - littleBabyFirstRev (Reverse Engineering)

## Analisis
Diberikan sebuah script Python `chall.py`. Di dalamnya terdapat fungsi `check_flag()` yang menyimpan 7 buah array berisi data biner (`a` sampai `g`). 

Script ini melakukan rekonstruksi karakter flag dengan cara melakukan operasi *bit shifting* ke kiri (`<<`) pada setiap elemen array berdasarkan indeksnya, lalu menjumlahkannya (`+`). Hasil penjumlahan tersebut dikonversi menjadi karakter ASCII menggunakan fungsi `chr()`.

Vulnerability atau celah keamanan tidak ada karena ini adalah tantangan *Reverse Engineering* dasar. Logika pembuatan flag sudah tertanam langsung (hardcoded) di dalam source code, sehingga kita hanya perlu mengekstrak dan mengeksekusi logika rekonstruksi tersebut tanpa harus memberikan input yang valid ke program aslinya.

## Langkah Penyelesaian
1. Ambil seluruh array biner (`a` sampai `g`) beserta loop rekonstruksi dari `chall.py`.
2. Buat script baru `solve.py` untuk mengisolasi logika tersebut dan langsung mencetak variabel `flag`.
3. Jalankan script solver untuk mendapatkan flag.
