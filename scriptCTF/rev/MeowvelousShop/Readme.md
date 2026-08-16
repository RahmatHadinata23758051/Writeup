# MeowvelousShop — Writeup

## Challenge

**Name:** MeowvelousShop
**Category:** Reversing / Pwn-ish

Description:

> "to distrcat your enemy, you must first distrcat yourself" --⚞^. .^⚟

Binary menampilkan menu toko kucing dengan fitur browse katalog, membership ID, redeem reward, credits, earn credits, dan buy cat.

## TL;DR

Fitur shop, credits, dan plushie itu distraksi. Trigger sebenarnya ada di membership ID.

Valid membership ID:

```text
N0Fl4gY37
```

Payload:

```text
2
N0Fl4gY37
4
```

Flag:

```text
scriptCTF{bu5y_c47_unw1nd1ng_fr0m_h15_5h1f7_@_7h3_5h0p_4cab00f896b6}
```

## Analisis Awal

Pertama cek binary:

```bash
file chall
checksec --file=chall
strings -a chall | less
```

Program berjalan sebagai menu interaktif:

```text
[1] Browse the Cat-alog
[2] Set your membership ID
[3] View your membership ID
[4] Redeem membership rewards
[5] View credits
[6] Earn credits
[7] Buy a cat
[8] View current cat
[9] Exit
```

Sekilas program terlihat seperti challenge untuk mengumpulkan credits atau membeli item tertentu. Namun deskripsi challenge memberi hint bahwa kita sedang dibuat terdistraksi.

## Hidden Flag Function

Dari hasil reversing/decompile, ditemukan fungsi yang membaca `flag.txt` dan mencetak isinya. Fungsi ini tidak terlihat dipanggil langsung dari alur menu biasa.

Bagian yang paling menarik ada di fitur membership:

* option `2`: set membership ID
* option `4`: redeem membership rewards

Saat redeem reward, program memvalidasi membership ID.

## Membership Check

Setelah membongkar logic validasi, membership ID yang valid adalah:

```text
N0Fl4gY37
```

String ini terlihat seperti jebakan karena terbaca sebagai `NoFlagYet`. Saat redeem, program memang mencetak pesan palsu:

```text
gud try, but no flag for u ≽^╥⩊╥^≼
maybe buy some plushies?
```

Tetapi setelah pesan tersebut, flag asli tetap ikut tercetak.

## Exploit

Interaksi yang dibutuhkan sangat pendek:

```text
2
N0Fl4gY37
4
```

Artinya:

1. Pilih menu `2` untuk set membership ID.
2. Masukkan `N0Fl4gY37`.
3. Pilih menu `4` untuk redeem membership rewards.

Output remote:

```text
> enter new membership ID: updated ≽^•⩊•^≼

> gud try, but no flag for u ≽^╥⩊╥^≼
> maybe buy some plushies?
> scriptCTF{bu5y_c47_unw1nd1ng_fr0m_h15_5h1f7_@_7h3_5h0p_4cab00f896b6}
```

## Solver

```python
#!/usr/bin/env python3
from pwn import *
import re
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "challs.scriptsorcerers.xyz"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 10135

membership_id = b"N0Fl4gY37"

io = remote(HOST, PORT)

io.sendlineafter(b">", b"2")
io.sendlineafter(b"enter new membership ID:", membership_id)
io.sendlineafter(b">", b"4")

out = io.recvall(timeout=3).decode(errors="ignore")
print(out)

m = re.search(r"scriptCTF\{[^}]+\}", out)
if m:
    print("\n[+] flag:", m.group(0))
```

Jalankan:

```bash
python3 solve.py challs.scriptsorcerers.xyz 10135
```

## Flag

```text
scriptCTF{bu5y_c47_unw1nd1ng_fr0m_h15_5h1f7_@_7h3_5h0p_4cab00f896b6}
```

