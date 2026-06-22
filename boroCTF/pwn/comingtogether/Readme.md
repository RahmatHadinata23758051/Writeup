# boroCTF 2026 - Coming Together (Pwn)

## Analisis Binary
Program menerima input string melalui `fgets()` maksimal 12 karakter, lalu dikonversi menjadi integer bertanda 32-bit (`int32_t`) menggunakan `atoi()`.

Alur logika pengecekan input:
1. Jika input $> 10000$, nilai diubah menjadi `1`.
2. Jika input $< 0$, program mencetak `"No negatives!"` dan melakukan instruksi `neg` (negasi tanda bilangan).
3. Nilai input ditambahkan dengan angka `2`.
4. Jika hasil akhir penjumlahan bernilai negatif ($< 0$), program akan membuka dan mencetak `flag.txt`.

## Kerentanan (Integer Overflow)
Fungsi `neg` pada arsitektur x86_64 bekerja dengan melakukan operasi Two's Complement (membalikkan semua bit dan menambah 1). 

Batas minimum integer bertanda 32-bit adalah `-2147483648` (`0x80000000`). Jika nilai ini di-negasi:
- `~0x80000000 = 0x7FFFFFFF`
- `0x7FFFFFFF + 1 = 0x80000000` (kembali menjadi `-2147483648`).

Karena nilai tidak berubah setelah operasi `neg`, proses kalkulasi berikutnya adalah `-2147483648 + 2 = -2147483646`. Hasil akhir ini tetap bernilai negatif, sehingga kondisi untuk mencetak flag berhasil dipicu.

## Langkah Eksploitasi
1. Hubungkan ke instance netcat target.
2. Kirim nilai batas minimum integer bertanda 32-bit: `-2147483648`.
3. Server mengeksekusi logika overflow dan mengembalikan flag.
