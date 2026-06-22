# Lazing Around

File `chall` ternyata image ext4 10 MB.

Isi root cuma ratusan file kecil `entry_log_*.txt` dan `exit_log_*.txt`. Kontennya kelihatan random printable dan nggak ada flag langsung dari `strings`, jadi fokus pindah ke artefak filesystem.

Kunci solve-nya ada di file slack.

Setiap log cuma berukuran 10-100 byte, tapi masing-masing tetap pakai 1 blok ext4 (`4096` byte). Artinya ada sisa ribuan byte setelah EOF. Mayoritas slack berisi nol, tapi beberapa file punya 2 byte non-zero yang kalau diambil berurutan membentuk flag.

Langkah yang dipakai:

```bash
rtk file chall
rtk debugfs -R 'ls -l /' chall
```

Dump satu blok penuh buat verifikasi konsep:

```bash
rtk debugfs -R 'stat <12>' chall
rtk dd if=chall bs=4096 skip=2048 count=1 status=none | xxd -g 1 -l 128
```

Lalu scan semua file:

1. Ambil inode dan ukuran file dari `debugfs -R 'ls -l /' chall`
2. Ambil nomor blok data dari `debugfs -R 'stat <inode>' chall`
3. Baca 1 blok penuh pakai `dd`
4. Ambil byte setelah `size`
5. Simpan file yang slack-nya punya byte non-zero
6. Urutkan berdasarkan nomor log
7. Gabungkan fragmen slack

Fragmen yang muncul:

```text
(6, 'bo')
(10, 'ro')
(27, 'CT')
(40, 'F{')
(78, 'C0')
(82, 'u!')
(95, 'D_')
(109, 'yo')
(119, '8_')
(166, 'cu')
(234, 'T_')
(255, 'm3')
(277, '_S')
(346, 'om')
(351, '4_')
(367, 'sL')
(440, '@c')
(474, 'k}')
```

Hasil gabungannya:

```text
boroCTF{C0u!D_yo8_cuT_m3_Som4_sL@ck}
```

Automasi final ada di `solve.py`:

```bash
python3 solve.py
```
