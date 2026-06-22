# Broken Promise — boroCTF 2026 / Misc

**Author:** ForeverFlames  
**Solved by:** rhnataiet23-art  
**Flag:** `boroCTF{s0rry_w1sh_w3_c0uld_g0_t0_th3_m00n_t0g3th3r}`

## TL;DR

File gambar cuma pengalih perhatian. Metadata JPEG bilang flag tidak ada di file, lalu hint `Two unseen anomalies hide. One is off and the other is on.` mengarah ke karakter Unicode invisible di postingan Reddit user `SandevastedMoonboy`. Karakter `U+200B` dan `U+200C` dipakai sebagai bit `0` dan `1`, lalu didecode per 8 bit menjadi flag.

## Deskripsi Challenge

> My friend David has been sobbing uncontrollably recently. He even changed his socials to "SandevastedMoonboy".

## Recon Awal

Challenge memberi gambar bulan dari Cyberpunk: Edgerunners. Dari clue nama sosial `SandevastedMoonboy`, pencarian diarahkan ke akun Reddit/Redlib dengan username yang sama.

Posting yang ditemukan:

```text
u/SandevastedMoonboy
Just finished Cyberpunk for the first time. This image broke me...
```

Di body komentar, bagian antara kata `Just` dan `finished` terlihat seperti spasi biasa. Setelah dicek, ternyata ada banyak karakter zero-width.

## Analisis File Gambar

Metadata gambar dicek dulu karena file-nya memang terlihat seperti stego bait.

```bash
exiftool moon.jpg
```

Output penting:

```text
Comment : The flag is not in this file. The image is a dead end. Everywhere you think you've looked, you really haven't. Two unseen anomalies hide. One is off and the other is on.
```

`binwalk` juga menemukan beberapa stream zlib, tapi metadata sudah cukup jelas: gambar adalah dead end.

```bash
binwalk moon.jpg
strings moon.jpg | grep boroCTF
```

Tidak ada flag plaintext dari file.

## Titik Temu

Kalimat `Two unseen anomalies hide. One is off and the other is on.` cocok dengan dua karakter invisible:

- `U+200B` / zero width space
- `U+200C` / zero width non-joiner

Dua karakter itu bisa dipakai sebagai bit biner. Mapping yang benar:

```text
U+200B = 0
U+200C = 1
```

Hidden payload berada di antara kata `Just` dan `finished` pada komentar Reddit/Redlib.

## Solver

Karena Reddit susah diakses langsung, page Redlib bisa disimpan manual sebagai `page.html`, lalu solver membaca HTML tersebut. Solver juga dibuat tahan terhadap escape HTML dan literal `\\u200b` / `\\u200c`.

```python
#!/usr/bin/env python3
import re
import sys
import html

ZW0 = "\u200b"  # zero width space
ZW1 = "\u200c"  # zero width non-joiner


def decode_bits(seq):
    for zero, one in [(ZW0, ZW1), (ZW1, ZW0)]:
        bits = seq.replace(zero, "0").replace(one, "1")

        for off in range(8):
            b = bits[off:]
            out = ""
            for i in range(0, len(b) - 7, 8):
                out += chr(int(b[i:i+8], 2))

            m = re.search(r"boroCTF\{[^}]+\}", out)
            if m:
                return m.group(0)

    return None


def extract_from_text(s):
    s = html.unescape(s)
    s = s.replace("\\u200b", ZW0).replace("\\u200c", ZW1)
    s = s.replace("&#8203;", ZW0).replace("&#8204;", ZW1)
    s = s.replace("&#x200b;", ZW0).replace("&#x200c;", ZW1)

    patterns = [
        rf"Just([{ZW0}{ZW1}]+)\s*finished",
        rf"Just\s*([{ZW0}{ZW1}]+)\s*finished",
    ]

    for pat in patterns:
        m = re.search(pat, s, flags=re.I)
        if m:
            flag = decode_bits(m.group(1))
            if flag:
                return flag

    seq = "".join(c for c in s if c in (ZW0, ZW1))
    if seq:
        return decode_bits(seq)

    return None


def main():
    if len(sys.argv) < 2:
        print("usage: python3 solve.py page.html")
        return

    data = open(sys.argv[1], "r", encoding="utf-8", errors="ignore").read()
    print(extract_from_text(data) or "flag not found")


if __name__ == "__main__":
    main()
```

Run:

```bash
python3 solve.py page.html
```

Output:

```text
boroCTF{s0rry_w1sh_w3_c0uld_g0_t0_th3_m00n_t0g3th3r}
```

## Flag

```text
boroCTF{s0rry_w1sh_w3_c0uld_g0_t0_th3_m00n_t0g3th3r}
```
