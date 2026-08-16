# Single Byte - CTF Writeup

## Analysis

Diberikan file `secret.bin` berupa binary blob:

```bash
xxd secret.bin
```

Output:

```text
723a14720b06393a72301d29713b1d2472372c263f
```

Deskripsi challenge memberikan petunjuk:

> Single-byte operations are often reversible. Try all 256 possibilities.

Kemungkinan besar digunakan operasi **XOR dengan satu byte key**. Karena hanya terdapat 256 kemungkinan nilai byte (`0x00`–`0xff`), kita dapat melakukan brute force terhadap seluruh key.

Script yang digunakan:

```python
data = open("secret.bin", "rb").read()

for k in range(256):
    out = bytes([b ^ k for b in data])

    if b"0xV0ID{" in out:
        print(hex(k))
        print(out)
```

Hasil brute force menemukan:

```text
KEY: 0x42
```

Dengan key `0x42`, binary tersebut berhasil didekripsi menjadi plaintext:

```text
0xV0ID{x0r_k3y_f0und}
```

## Flag

```text
0xV0ID{x0r_k3y_f0und}
```
