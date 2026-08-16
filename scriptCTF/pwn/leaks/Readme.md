# Leaks

## Ringkasan

Service remote aktif pada `challs.scriptsorcerers.xyz:10003`. Direktori challenge tidak menyediakan binary, libc, loader, atau source lokal.

Primitive yang terbukti adalah format-string arbitrary read. Input diproses sebagai format string, dan slot argumen ke-7 dapat diisi dengan alamat yang ditempel setelah format string.

## Observasi service

Banner berbentuk:

```text
Here is a gift (stdin): 0x...
Enter input:
```

Input panjang dipotong menjadi sekitar 15 byte efektif. Karena itu alamat userspace ditempel setelah format string 8-byte; byte tinggi alamat bernilai nol dan tidak diperlukan.

## Analisis program

Leak code menunjukkan input dibaca ke `[rbp-0x30]` dengan ukuran `0x1d`, lalu dipakai oleh `printf`. Program juga memiliki branch tersembunyi:

```c
if (strstr(input, "FSOP")) {
    fp = fopen("flop.txt", "rb");
    fgets(global_data, 100, fp);
    printf("Data: %s", global_data);
}
```

Input `FSOP` biasa hanya menghasilkan decoy `Nothing to see here ;)`.

## Vulnerability

Input pengguna diteruskan ke fungsi printf sebagai format string. Contoh `%p` membocorkan isi argumen variadic. `%7$s` mendereference alamat pada slot argumen ke-7.

Payload leak yang terbukti:

```python
b"%7$sAAA".ljust(8, b"A") + p64(address)
```

Contoh `%7$p` menghasilkan byte input sendiri pada stack, sedangkan `%17$p` dan slot lain membocorkan alamat PIE, stack, serta libc.

## Leak GOT dan libc

Dari tabel relocation yang dibaca melalui primitive tersebut:

```text
gift - 0x98 = puts@GOT
gift - 0x90 = printf@GOT
gift - 0x88 = strcspn@GOT
gift - 0x80 = fgets@GOT
gift - 0x78 = setvbuf@GOT
gift - 0x70 = fopen@GOT
gift - 0x68 = exit@GOT
gift - 0x60 = strstr@GOT
```

Leak `puts@GOT` memberikan pointer libc yang valid. Pada percobaan, pengurangan offset `puts` dari libc lokal menghasilkan base yang ketika dibaca kembali diawali `\x7fELF`, sehingga offset libc cocok dengan service yang diuji.

String global `flop.txt` terbaca pada `gift - 0x20`.

## Strategi exploit

`gift = PIE + 0x4030`, sedangkan literal `flop.txt` berada pada `PIE + 0x4010`. Target `gift-0x1e` menunjuk ke byte ketiga filename.

Payload final:

```python
b"FSOP%26461c%8$hn" + p64(gift - 0x1e)
```

`FSOP` memicu branch pembacaan file. Empat karakter literal dihitung sebagai output, sehingga `%26461c` menghasilkan total `26465 == 0x6761`. `%8$hn` menulis bytes little-endian `61 67` ke `flop.txt+2`, mengubahnya menjadi `flag.txt`. Payload panjangnya 24 byte dan muat di input buffer.

## Exploit final

`solve.py` menghitung PIE base dan menjalankan payload final:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py REMOTE HOST=challs.scriptsorcerers.xyz PORT=10003
```

Mode lokal menolak dengan pesan jelas karena binary lokal memang tidak tersedia.

## Hasil

Output service:

```text
Data: scriptCTF{ju57_l34k_3v3ry7h1ng_4nd_r34d_fl4g_f7bbb94b1c33}
```

Flag berasal langsung dari output service setelah filename diubah menjadi `flag.txt`.
