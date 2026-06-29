# impossible stego

**CTF:** SEKAI CTF 2026  
**Category:** Misc  
**Flag:** `SEKAI{th3y_d1dn7_4ctually_l3t_m3_us3_my7h0s_f0r_7h1s_0n3_s4dly_i_h4d_i7_r3r0ut3d_t0_0pus}`

## Files

```text
flag.png
messages.log
```

`flag.png` terlihat seperti PNG biasa berukuran 828×449. File yang lebih berguna justru `messages.log`: 60 baris NDJSON dengan ukuran sekitar 23 MB. Setiap baris menyimpan request dan response menuju gateway Anthropic, sedangkan body-nya dikodekan dengan Base64.

```bash
file flag.png messages.log
wc -lc messages.log
head -n 1 messages.log
```

Hasil penting:

```text
flag.png:     PNG image data, 828 x 449, 8-bit/color RGBA
messages.log: New Line Delimited JSON text data
60 23367221 messages.log
```

## Membaca log Claude

Struktur satu record kurang lebih seperti ini:

```json
{
  "path": "v1/messages",
  "method": "POST",
  "req_body": "...base64...",
  "resp_body": "...base64..."
}
```

Claude API bersifat stateless. Client mengirim ulang histori percakapan pada request berikutnya, jadi request terakhir menjadi salinan percakapan yang paling lengkap. Setelah `req_body` di-decode, field `messages` berisi semua percakapan, tool call, command, dan source code yang ditulis Claude.

Pemeriksaan singkat:

```python
import base64
import json

records = [json.loads(line) for line in open("messages.log")]
request = json.loads(base64.b64decode(records[-1]["req_body"]))
print(len(request["messages"]))
```

Output:

```text
114
```

## Source stego ikut bocor

Tool call Claude disimpan sebagai content block bertipe `tool_use`. Source program muncul melalui tool `Write`, kemudian beberapa bagian diperbarui melalui tool `Edit`.

Contoh bentuk tool call:

```json
{
  "type": "tool_use",
  "name": "Write",
  "input": {
    "file_path": "/home/claude/projects/impossible-stego/stego/pipeline.py",
    "content": "..."
  }
}
```

Source awal berupa satu file `stego.py`, tetapi versi itu kemudian dibuang dan diganti package `stego/`. Solver hanya memutar ulang `Write` dan `Edit` dengan path yang dimulai oleh:

```text
/home/claude/projects/impossible-stego/stego/
```

Package akhir yang pulih:

```text
stego/
├── __init__.py
├── __main__.py
├── bits.py
├── pipeline.py
├── secret.py
├── coding/
│   ├── frame.py
│   ├── sbox.py
│   └── whiten.py
├── crypto/
│   ├── chacha20.py
│   ├── csprng.py
│   ├── kdf.py
│   └── mac.py
└── image/
    ├── carrier.py
    ├── embed.py
    └── scatter.py
```

Tidak ada passphrase. Seluruh key material berada di `secret.py`, termasuk `ROOT_SECRET`, salt HKDF, label domain separation, magic frame, dan konfigurasi scatter.

## Pipeline ekstraksi

`pipeline.py` menunjukkan urutan yang perlu dibalik:

1. Ambil LSB RGB mengikuti multi-stage keyed scatter.
2. Baca encrypted header untuk memperoleh panjang payload.
3. Ambil seluruh blob sesuai panjang frame dan tag.
4. Verifikasi truncated HMAC-SHA256.
5. Lepas positional whitening.
6. Balik keyed S-box.
7. Dekripsi ChaCha20.
8. Validasi magic, version, panjang data, dan CRC32.

Scatter terakhir bukan Fisher–Yates tunggal. Claude mengubahnya menjadi komposisi empat permutasi:

```text
block interleave
keyed rotation
cycle-walking Feistel permutation
Fisher–Yates shuffle
```

Menebak pola dari piksel tidak diperlukan karena implementasi finalnya tersedia utuh di log.

## Solver

`solve.py` mengerjakan seluruh proses secara otomatis:

- mengekstrak arsip secara aman;
- mencari `messages.log` dan `flag.png`;
- mengambil request Claude dengan histori terpanjang;
- merekonstruksi package `stego` dari tool call `Write` dan `Edit`;
- menjalankan fungsi `stego.extract()` terhadap `flag.png`;
- memvalidasi hasil dengan pola flag SEKAI.

Jalankan dari folder challenge:

```bash
python3 solve.py misc_impossible-stego.tar.gz
```

Atau terhadap folder yang sudah diekstrak:

```bash
python3 solve.py misc_impossible-stego
```

Output:

```text
<FLAG>SEKAI{th3y_d1dn7_4ctually_l3t_m3_us3_my7h0s_f0r_7h1s_0n3_s4dly_i_h4d_i7_r3r0ut3d_t0_0pus}</FLAG>
```

## Flag

```text
SEKAI{th3y_d1dn7_4ctually_l3t_m3_us3_my7h0s_f0r_7h1s_0n3_s4dly_i_h4d_i7_r3r0ut3d_t0_0pus}
```
