# I HATE THIS APP REVENGE

- **CTF:** LYKNCTF 2026
- **Category:** Reverse
- **Binary:** `fuoverflow_learning.exe`
- **Encrypted file:** `challenge.enc.bin`
- **Flag:** `LYKNCTF{alolanvulpix}`

## Ringkasan

File `.enc.bin` memakai AES-256-CTR. Dua belas byte awal bukan ciphertext: 8 byte pertama adalah nonce dan 4 byte berikutnya adalah counter big-endian. Binary menyimpan fallback key 32 byte yang dipakai saat environment variable `FIXED_ENCRYPTION_KEY` tidak tersedia.

Setelah didekripsi, output memiliki header JPEG yang valid. Gambar menampilkan Alolan Vulpix, jadi nama karakter untuk flag adalah `alolanvulpix`.

## Ekstraksi binary

Arsip berisi satu aplikasi Windows x64 berbasis Tauri:

```bash
file fuoverflow_learning.exe
```

```text
fuoverflow_learning.exe: PE32+ executable for MS Windows 6.00 (GUI), x86-64, 6 sections
```

## Mencari bagian kriptografi

String yang relevan langsung mengarah ke command decrypt dan konfigurasi key:

```bash
strings -a -n 5 fuoverflow_learning.exe \
  | grep -iE 'decrypt|encrypted data too short|fixed_encryption_key|aes-0.8.4|stream_core'
```

Potongan penting:

```text
src\commands\decrypt.rs
Encrypted data too short
FIXED_ENCRYPTION_KEY
C:\Users\nguye\.cargo\registry\src\...\aes-0.8.4\src\soft\fixslice64.rs
C:\Users\nguye\.cargo\registry\src\...\cipher-0.4.4\src\stream_core.rs
```

`FIXED_ENCRYPTION_KEY` dibaca sebagai environment variable. Jika variabel tersebut tidak ada atau panjangnya bukan 32 byte, program memakai konstanta fallback dari `.rdata`:

```text
H}3t%^nDw5F?cWj-XAH!Dj8AakaD9y9M
```

## Format file terenkripsi

Dua belas byte pertama:

```text
00 11 22 33 44 55 66 77 00 00 00 07
```

Decrypt routine memprosesnya seperti ini:

```text
nonce   = data[0:8]                         # 0011223344556677
counter = int.from_bytes(data[8:12], "big") # 7
iv      = nonce || counter.to_bytes(8, "big")
```

IV AES akhirnya:

```text
00112233445566770000000000000007
```

Sisa file mulai offset `0x0c` adalah ciphertext. Mode yang dipakai adalah AES-256-CTR, jadi tidak ada padding atau authentication tag.

## Dekripsi

Implementasi minimalnya:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

blob = open("challenge.enc.bin", "rb").read()
key = b"H}3t%^nDw5F?cWj-XAH!Dj8AakaD9y9M"
nonce = blob[:8]
counter = int.from_bytes(blob[8:12], "big")
iv = nonce + counter.to_bytes(8, "big")

dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
plain = dec.update(blob[12:]) + dec.finalize()
open("recovered.jpg", "wb").write(plain)
```

Header hasil dekripsi:

```text
ff d8 ff e0 00 10 4a 46 49 46
```

Itu adalah JPEG/JFIF. `file` juga mengenalinya dengan benar:

```bash
file recovered.jpg
```

```text
recovered.jpg: JPEG image data, JFIF standard 1.01, 526x684
```

## Identifikasi karakter

Gambar memperlihatkan rubah putih dengan mata biru, jambul es, dan beberapa ekor melengkung. Ciri tersebut cocok dengan **Alolan Vulpix**.

Format flag meminta lowercase tanpa spasi:

```text
LYKNCTF{alolanvulpix}
```

## Solver

`solve.py` tidak sekadar hardcode offset key. Script mencari marker `FIXED_ENCRYPTION_KEY`, menguji kandidat string printable 32 byte di area `.rdata`, lalu memilih key yang menghasilkan signature gambar valid.

```bash
python3 solve.py challenge.enc.bin fuoverflow_learning.exe
```

```text
[+] Key offset : 0xc5ec10
[+] AES key    : H}3t%^nDw5F?cWj-XAH!Dj8AakaD9y9M
[+] Nonce      : 0011223344556677
[+] Counter    : 7
[+] IV         : 00112233445566770000000000000007
[+] Image      : recovered.jpg (33100 bytes)
[+] Character  : Alolan Vulpix
[+] Flag       : LYKNCTF{alolanvulpix}
```
