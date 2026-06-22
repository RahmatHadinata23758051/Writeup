# AlphaCode - CTF Writeup

Challenge ini meminta kita untuk memahami bahasa pemrograman kustom bernama "AlphaCode" dan menyelesaikan tugas di "Gauntlet" untuk mendapatkan flag.

## Analisis AlphaCode

Bahasa ini memiliki sistem encoding string yang unik. Setiap karakter direpresentasikan oleh 4 huruf (contoh: `awzz`, `atzz`). Rumusnya adalah:
`sum(huruf - 'a') + 32 = ASCII value`.

Beberapa instruksi utama yang berhasil diidentifikasi:
- `zm <nama>`: Mendeklarasikan variabel.
- `zz di <nama>`: Meload nilai variabel ke buffer saat ini.
- `zz fi`: Membaca input dari user dan menyimpannya di stack.
- `zz fr`: Mencetak isi buffer atau input yang sedang ditunjuk.
- `zz dp`: Memindahkan pointer ke buffer sebelumnya di stack dan mencetaknya.
- `zz fo`: Mencetak newline.
- `ex`: Mengakhiri program.

## Strategi Eksploitasi

Tugas Gauntlet adalah menerima 3 input dan mencetaknya dalam format:
```
Hello I am {input 3}, and I like {input 2}.
I hate {input 1}.
```

Tantangan terbesarnya adalah `zz di` (load variabel) menimpa buffer yang sedang aktif. Untuk mempertahankan input, kita harus melakukan interleaving antara membaca input (`zz fi`) dan memanggil variabel (`zz di`).

Melalui trial-and-error, ditemukan bahwa stack VM ini bertingkah laku cukup unik saat dicampur dengan deklarasi variabel. Strategi finalnya adalah:
1. Baca input 1 dan 2.
2. Load string "Hello I am " dan cetak.
3. Baca input 3 dan cetak.
4. Load string ", and I like " dan cetak.
5. Gunakan `zz dp` secara berulang untuk kembali ke posisi input 2 dan mencetaknya.
6. Lanjutkan pola ini untuk input 1 dan string sisanya.

Script solve lengkap ada di `solve.py`.

Flag: `boroCTF{r3verse_by_guessncheck}`
