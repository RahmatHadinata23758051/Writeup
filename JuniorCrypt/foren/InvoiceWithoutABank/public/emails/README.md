# Invoice Without A Bank (Forensics)

**CTF**: JuniorCrypt
**Category**: Forensics
**Flag**: `grodno{Vl6s3kCIKaUvwaUAeY.pdf_6ZFYeMmltso}`

## Deskripsi

> Find the message where a PDF attachment is distributed under the guise of a banking notification.

Dikasih 10 file `.eml` di folder `emails/`. Tugasnya nyari satu email spesifik yang nyamar sebagai notifikasi bank, terus ambil nama attachment PDF-nya sama ID di subject.

## Analisis

Subject challenge-nya udah kasih clue: harus ada teks **"Fatura Emitida -"** (bahasa Portugis, artinya "Invoice Diterbitkan -"). Tinggal grep semua `.eml` buat nyari itu:

```bash
grep -liE "fatura emitida" *.eml
```

Ketemu satu file: `sample-717.eml`.

Sekalian cross-check tema banking di email lain (buat mastiin bukan salah sample, soalnya ada beberapa phishing email lain yang juga nyamar jadi bank: `[BB]`, `Banco do Brasil`, dll):

```bash
grep -liE "bank|banco|banking" *.eml
```

Cek header `From`/`Subject` file itu:

```
From: "Itaucard - Pague sua fatura | Cod. 2374614215181323" <watw96708@gmail.com>
Subject: Fatura Emitida - 6ZFYeMmltso
```

`From`-nya nyamarin diri jadi "Itaucard" (brand kartu kredit bank Itaú di Brasil) + kode fake, padahal domainnya cuma gmail biasa — pola khas phishing invoice/tagihan.

## Ekstraksi Detail

Attachment filename-nya nggak keliatan langsung dari `grep -iE "filename=.*\.pdf"` doang karena beberapa email nge-encode header (RFC 2047 `=?UTF-8?B?...?=`). Supaya nggak salah decode/salah baca, parse pakai modul `email` bawaan Python:

```python
import glob, email
from email.header import decode_header

def dec(s):
    if not s:
        return ""
    out = ""
    for val, enc in decode_header(s):
        out += val.decode(enc or "utf-8", errors="replace") if isinstance(val, bytes) else val
    return out

for fname in sorted(glob.glob("*.eml")):
    with open(fname, "rb") as f:
        msg = email.message_from_binary_file(f)
    subj = dec(msg["subject"])
    if "fatura emitida" in subj.lower():
        print("FILE:", fname)
        print("SUBJECT:", subj)
        for part in msg.walk():
            fn = part.get_filename()
            if fn:
                print("  ATTACHMENT:", dec(fn))
```

Output:

```
FILE: sample-717.eml
SUBJECT: Fatura Emitida - 6ZFYeMmltso
  ATTACHMENT: Vl6s3kCIKaUvwaUAeY.pdf
```

Dua data yang dibutuhin:

- **Filename attachment**: `Vl6s3kCIKaUvwaUAeY.pdf`
- **ID setelah "Fatura Emitida -"**: `6ZFYeMmltso`

## Flag

```
grodno{Vl6s3kCIKaUvwaUAeY.pdf_6ZFYeMmltso}
```

## Tools

- `grep` — cari keyword subject & tema banking
- Python `email` + `email.header.decode_header` — decode header RFC 2047 dengan benar (menghindari salah baca base64/quoted-printable manual)
