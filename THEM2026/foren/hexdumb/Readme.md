# HexDumb Writeup

## Informasi Challenge

- **Kategori:** Forensic
- **Judul:** HexDumb
- **Deskripsi:** Screenshot hex dump lama yang berisi sesuatu.
- **Goal:** Rekonstruksi artefak dari screenshot, lalu ekstrak `flag.txt`.

## Ringkasan

Challenge hanya memberikan screenshot berisi hex dump. Dari byte awal terlihat signature:

```text
50 4b 03 04
```

Signature tersebut adalah magic byte untuk file ZIP. Jadi langkah utama adalah menyalin kembali hex dari screenshot, mengubahnya menjadi byte asli, lalu menyimpan hasilnya sebagai file ZIP.

Setelah file ZIP berhasil direkonstruksi, diketahui bahwa archive berisi satu file bernama `flag.txt`, tetapi file tersebut terenkripsi. Password ZIP kemudian di-crack menggunakan wordlist `rockyou.txt`, dan password yang benar adalah:

```text
love@123
```

Setelah ZIP diekstrak dengan password tersebut, isi `flag.txt` menghasilkan flag:

```text
THEM?!CTF{XXD_0R_XD}
```

## 1. Rekonstruksi File dari Screenshot

Hex dump pada gambar ditranskrip menjadi byte. Bagian awal dump:

```text
50 4b 03 04 0a 00 09 00 00 00 01 75 98 5c 0f de
90 6f 20 00 00 00 14 00 00 00 08 00 1c 00 66 6c
61 67 2e 74 78 74 ...
```

Terlihat juga string nama file:

```text
66 6c 61 67 2e 74 78 74
```

Jika dikonversi ke ASCII:

```text
flag.txt
```

Script rekonstruksi sederhana:

```python
#!/usr/bin/env python3

hex_dump = '''
50 4b 03 04 0a 00 09 00 00 00 01 75 98 5c 0f de
90 6f 20 00 00 00 14 00 00 00 08 00 1c 00 66 6c
61 67 2e 74 78 74 55 54 09 00 03 02 b9 eb 69 02
b9 eb 69 75 78 0b 00 01 04 e8 03 00 00 04 e8 03
00 00 5d 81 87 1d 8c 4b 2f 2a 4d af f2 f0 3a 1b
95 84 f3 b7 a8 c9 be 77 cf 1d 92 4a de 9d eb e9
95 c3 50 4b 07 08 0f de 90 6f 20 00 00 00 14 00
00 00 50 4b 01 02 1e 03 0a 00 09 00 00 00 01 75
98 5c 0f de 90 6f 20 00 00 00 14 00 00 00 08 00
18 00 00 00 00 00 01 00 00 00 b4 81 00 00 00 00
66 6c 61 67 2e 74 78 74 55 54 05 00 03 02 b9 eb
69 75 78 0b 00 01 04 e8 03 00 00 04 e8 03 00 00
50 4b 05 06 00 00 00 00 01 00 01 00 4e 00 00 00
72 00 00 00 00 00
'''

zip_bytes = bytes.fromhex(hex_dump)
with open('recovered.zip', 'wb') as f:
    f.write(zip_bytes)

print('[+] recovered.zip written')
```

## 2. Recon ZIP

Setelah file dibuat, cek tipe file:

```bash
file recovered.zip
```

Hasilnya menunjukkan bahwa file tersebut adalah ZIP archive.

Cek isi archive:

```bash
unzip -l recovered.zip
```

Isi archive:

```text
flag.txt
```

Saat dicoba diekstrak, ZIP meminta password. Ini sesuai dengan flag bit pada header ZIP yang menunjukkan file terenkripsi.

Informasi penting dari struktur ZIP:

```text
filename           : flag.txt
encrypted          : yes
compression method : store / none
crc32              : 0x6f90de0f
compressed size    : 32 bytes
uncompressed size  : 20 bytes
```

Catatan penting: CRC32 memang bisa dipakai untuk validasi, tetapi tidak cukup aman untuk menebak plaintext karena collision sangat mungkin terjadi pada kandidat pendek. Jadi solusi yang benar adalah crack password ZIP, bukan hanya mencari string yang CRC-nya cocok.

## 3. Crack Password ZIP

Password dicrack menggunakan wordlist `rockyou.txt`. Contoh script `crack.py`:

```python
#!/usr/bin/env python3
import zipfile

zip_path = 'recovered.zip'
wordlist_path = '/usr/share/wordlists/rockyou.txt'

print(f'[*] Memuat wordlist dari {wordlist_path}...')

with zipfile.ZipFile(zip_path) as zf:
    with open(wordlist_path, 'rb') as wordlist:
        for i, password in enumerate(wordlist, 1):
            password = password.strip()
            try:
                zf.extractall(pwd=password)
                print(f'\n[+] PASSWORD KETEMU: {password.decode(errors="ignore")}')
                break
            except Exception:
                pass

            if i % 100000 == 0:
                print(f'[*] Tried {i} passwords...')
```

Jalankan:

```bash
python3 crack.py
```

Output penting:

```text
[*] Memuat wordlist dari /usr/share/wordlists/rockyou.txt...
[*] Memulai bruteforce dengan 499997 kombinasi password...

[+] PASSWORD KETEMU: love@123
```

Password ZIP:

```text
love@123
```

## 4. Ekstraksi Flag

Setelah password ditemukan, ekstrak ZIP:

```bash
unzip -P 'love@123' recovered.zip
```

Baca isi file:

```bash
cat flag.txt
```

Output:

```text
THEM?!CTF{XXD_0R_XD}
```

## Flag

```text
THEM?!CTF{XXD_0R_XD}
```

## Kesimpulan

Inti challenge ini adalah membaca screenshot hex dump sebagai data mentah, bukan sebagai gambar biasa. Byte awal `50 4b 03 04` mengarah ke format ZIP. Setelah ZIP direkonstruksi, file `flag.txt` ternyata terenkripsi, sehingga perlu dilakukan cracking password. Password ditemukan dari `rockyou.txt` sebagai `love@123`, lalu `flag.txt` berhasil dibuka dan menghasilkan flag final.
