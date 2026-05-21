# forensics/unfinished-file

Challenge ini ngasih satu artefak: `secret_archive.zip.crdownload`. Dari namanya kelihatan seperti file download Chrome yang belum selesai, jadi fokus awalnya adalah memastikan apakah ini benar-benar cuma file rusak atau ada data yang masih bisa diambil.

## Recon awal

File yang tersedia:

```bash
ls -la
```

Hasil pentingnya cuma satu file:

- `secret_archive.zip.crdownload`

Cek tipe file:

```bash
file secret_archive.zip.crdownload
```

Outputnya hanya `data`, jadi formatnya tidak dikenali langsung.

Lalu cek string yang kelihatan:

```bash
strings -a -n 4 secret_archive.zip.crdownload
```

Ada beberapa temuan menarik:

- Header `CRDL`
- URL `https://example.com/secret_archive.zip`
- `readme.txt`
- `hidden/.flagdata`
- Sebuah blob aneh:

```text
6(!6$9,q4q0
r6*'0
2qr2.'
6r7!*
70
!r/276'0?
```

Ini langsung memberi petunjuk bahwa file ini bukan sekadar unduhan gagal biasa. Ada struktur internal yang sengaja disisipkan.

## Menemukan ZIP di dalam file

Hex dump bagian awal:

```bash
xxd secret_archive.zip.crdownload | sed -n '1,40p'
```

Dari sini terlihat signature ZIP `PK\x03\x04` mulai di offset `0x100`. Jadi file `.crdownload` ini punya data tambahan di depan, lalu di dalamnya ada archive ZIP yang terpotong.

Cek dengan `binwalk`:

```bash
binwalk secret_archive.zip.crdownload
```

Terlihat dua file di dalam archive:

- `readme.txt`
- `hidden/.flagdata`

`7z l` juga masih bisa membaca local file header walaupun central directory ZIP-nya tidak lengkap.

## Ekstraksi manual

Karena archive-nya tidak utuh, saya parse local file header ZIP secara manual untuk mengambil isi file langsung dari offset-nya.

Intinya:

- ZIP mulai di offset `0x100`
- File pertama adalah `readme.txt`
- File kedua adalah `hidden/.flagdata`

Isi `readme.txt`:

```text
This file is incomplete. Keep looking...
```

Isi `hidden/.flagdata` berupa 47 byte data yang sama dengan blob aneh yang sebelumnya muncul di `strings`.

## Decode flag

Karena datanya pendek dan terlihat seperti teks yang diobfuscate, saya brute-force XOR 1 byte.

Contoh script cepat:

```python
from pathlib import Path

s = Path("extracted_manual/hidden/.flagdata").read_bytes()

for k in range(256):
    t = bytes(b ^ k for b in s)
    if all(32 <= c < 127 for c in t):
        txt = t.decode("latin1")
        if "flag" in txt.lower() or "tjc" in txt.lower() or "{" in txt:
            print(k, txt)
```

Hasil untuk key XOR `0x42`:

```text
tjctf{n3v3r_l3t_0ther_p30ple_t0uch_ur_c0mputer}
```

## Kesimpulan

Teman di deskripsi challenge kelihatannya sedang mencoba mengunduh archive rahasia, dan walaupun file ZIP-nya belum selesai, local file header serta isi file yang sudah terunduh masih cukup untuk mengekstrak data tersembunyi dan mendapatkan flag.

## Flag

```text
tjctf{n3v3r_l3t_0ther_p30ple_t0uch_ur_c0mputer}
```
