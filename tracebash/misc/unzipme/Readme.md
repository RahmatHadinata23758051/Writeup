# Unzip Me

Flag: `TBCTF{br0_kn0w5_3v3ry_3nc0d1ng}`

## Ringkas

`secret.zip` hanya pembungkus awal. Di dalamnya ada pasangan file berulang: `secret.7z` dan `pass`. Isi `pass` bukan password mentah, tetapi encoding yang harus dibalik untuk membuka layer berikutnya.

Urutan decoding yang dipakai:

| Layer | Isi `pass` | Decoding | Password |
|---:|---|---|---|
| 0 | karakter printable aneh | ROT47 | `R0T47_p@SSw0Rdc81ae068` |
| 1 | byte hex `C5 C2 ...` | EBCDIC / cp037 | `EBCDIC_P@sSw0Rdd1c72fc4` |
| 2 | angka 0–63 | nilai + 32 ke ASCII | `6B1T_PASSW0RD28622B4D` |
| 3 | Motorola S-Record | ambil data record `S1` | `SR3C_PAsSw0rd1943f79c` |
| 4 | Intel HEX | ambil record data type `00` | `IH3X_PAssw0rd3db29edd` |
| 5 | Unicode symbols | Base32768 | `b@se32768_PAssw0rd91fa13ae` |
| 6 | string ASCII simbol | Base91 | `base91_P@ssw0rd1551de6c` |

Setelah layer terakhir dibuka, file `flag.txt` berisi flag.

## Cara jalanin

```bash
python3 -m pip install py7zr
python3 solve.py
```

Output utama:

```text
FLAG: TBCTF{br0_kn0w5_3v3ry_3nc0d1ng}
```

## Catatan eksploitasi

Tidak ada brute force password. Semua password diturunkan dari file `pass` di setiap layer. Script melakukan ekstraksi ZIP awal, decode password sesuai format layer, lalu membuka arsip 7z berikutnya secara otomatis sampai `flag.txt` terbaca.
                                     
