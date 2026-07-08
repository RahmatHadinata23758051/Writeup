# World Cup 2 Writeup

## Analisis
File `worldcup2_challenge.png` dideteksi sebagai file JPEG oleh utilitas `file`.
Menggunakan `binwalk` untuk memeriksa file tersemat:
```bash
binwalk worldcup2_challenge.png
```
Ditemukan adanya arsip ZIP di offset `283620` (0x453E4) yang berisi file `flag_hidden.txt`.

## Solusi
Ekstraksi file menggunakan `unzip`:
```bash
unzip worldcup2_challenge.png
```
Membaca isi file `flag_hidden.txt` menghasilkan flag:
`LYKNCTF{RespectToCaboVerde}`
