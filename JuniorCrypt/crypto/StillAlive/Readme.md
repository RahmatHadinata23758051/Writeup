# Aperture Science: Still Alive

## Informasi Challenge

- **Kategori:** Crypto
- **Kesulitan:** Medium
- **Judul:** Aperture Science: Still Alive
- **Flag format:** `grodno{}`

## Deskripsi

Sebuah record internal Aperture Science yang berkaitan dengan GLaDOS berhasil dipulihkan dari storage yang selamat setelah fasilitas mati.

File yang diberikan:

```text
ciphertexts.json
public.pem
```

Tujuannya adalah memulihkan pesan asli yang dienkripsi.

---

## Isi File

`ciphertexts.json`:

```json
{
  "c1": "...",
  "c2": "...",
  "a": 1337,
  "b": "5577100914618608347433571795909361526455637706263378490"
}
```

`public.pem` berisi public key RSA.

Langkah pertama adalah membaca parameter public key:

```python
from cryptography.hazmat.primitives import serialization

pub = serialization.load_pem_public_key(
    open("public.pem", "rb").read()
).public_numbers()

print(pub.n)
print(pub.e)
```

Dari public key tersebut didapat:

```text
e = 3
```

Public exponent kecil belum tentu langsung berbahaya, tetapi menjadi masalah ketika plaintext memiliki hubungan matematis dan keduanya dienkripsi dengan modulus RSA yang sama.

---

## Identifikasi Relasi Plaintext

Adanya nilai:

```text
a = 1337
b = 5577100914618608347433571795909361526455637706263378490
```

menunjukkan bahwa dua plaintext kemungkinan berhubungan secara linear:

```text
m2 = a × m1 + b mod n
```

Ciphertext pertama:

```text
c1 = m1^3 mod n
```

Ciphertext kedua:

```text
c2 = m2^3 mod n
```

Karena:

```text
m2 = a × m1 + b
```

maka:

```text
c2 = (a × m1 + b)^3 mod n
```

Kondisi ini cocok dengan **Franklin–Reiter Related Message Attack**.

---

## Franklin–Reiter Related Message Attack

Franklin–Reiter attack dapat digunakan ketika:

- Dua plaintext dienkripsi menggunakan RSA modulus yang sama.
- Public exponent kecil.
- Kedua plaintext memiliki relasi polynomial yang diketahui.
- Relasi tersebut memiliki derajat rendah, seperti relasi linear.

Pada challenge ini, bentuk polynomial-nya adalah:

```text
f(x) = x^3 - c1
```

dan:

```text
g(x) = (a × x + b)^3 - c2
```

Plaintext `m1` adalah akar bersama dari kedua polynomial tersebut modulo `n`.

Artinya:

```text
f(m1) = 0 mod n
g(m1) = 0 mod n
```

Jika dihitung:

```text
gcd(f(x), g(x)) mod n
```

hasilnya akan menjadi polynomial linear:

```text
x - m1
```

Dari sana plaintext dapat langsung diambil.

---

## Bentuk Polynomial

Polynomial pertama:

```text
f(x) = x^3 - c1
```

Koefisien dari derajat terendah ke tertinggi:

```python
f = [
    -c1,
    0,
    0,
    1
]
```

Polynomial kedua:

```text
g(x) = (a × x + b)^3 - c2
```

Ekspansinya:

```text
(a × x + b)^3
=
a^3x^3 + 3a^2bx^2 + 3ab^2x + b^3
```

Sehingga:

```python
g = [
    b**3 - c2,
    3 * a * b**2,
    3 * a**2 * b,
    a**3
]
```

Semua operasi dilakukan modulo `n`.

---

## Solver Otomatis

Simpan script berikut sebagai `solve.py`:

```python
#!/usr/bin/env python3
import json
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization


def trim(poly, modulus):
    while len(poly) > 1 and poly[-1] % modulus == 0:
        poly.pop()

    return [value % modulus for value in poly]


def poly_sub(left, right, modulus):
    size = max(len(left), len(right))
    result = [0] * size

    for index in range(size):
        a = left[index] if index < len(left) else 0
        b = right[index] if index < len(right) else 0
        result[index] = (a - b) % modulus

    return trim(result, modulus)


def poly_mul_monomial(poly, coefficient, degree, modulus):
    return [0] * degree + [
        coefficient * value % modulus
        for value in poly
    ]


def poly_divmod(dividend, divisor, modulus):
    dividend = trim(dividend[:], modulus)
    divisor = trim(divisor[:], modulus)

    if len(divisor) == 1 and divisor[0] == 0:
        raise ZeroDivisionError("Polynomial division by zero")

    quotient = [0] * max(
        1,
        len(dividend) - len(divisor) + 1
    )

    inverse_lead = pow(
        divisor[-1],
        -1,
        modulus
    )

    while len(dividend) >= len(divisor):
        if len(dividend) == 1 and dividend[0] == 0:
            break

        degree = len(dividend) - len(divisor)

        coefficient = (
            dividend[-1] * inverse_lead
        ) % modulus

        quotient[degree] = coefficient

        dividend = poly_sub(
            dividend,
            poly_mul_monomial(
                divisor,
                coefficient,
                degree,
                modulus,
            ),
            modulus,
        )

    return trim(quotient, modulus), trim(dividend, modulus)


def poly_gcd(left, right, modulus):
    left = trim(left, modulus)
    right = trim(right, modulus)

    while not (
        len(right) == 1
        and right[0] == 0
    ):
        _, remainder = poly_divmod(
            left,
            right,
            modulus
        )

        left, right = right, remainder

    inverse_lead = pow(
        left[-1],
        -1,
        modulus
    )

    return [
        coefficient * inverse_lead % modulus
        for coefficient in left
    ]


def int_to_bytes(value):
    length = max(
        1,
        (value.bit_length() + 7) // 8
    )

    return value.to_bytes(length, "big")


def main():
    data = json.loads(
        Path("ciphertexts.json").read_text(
            encoding="utf-8"
        )
    )

    public_key = serialization.load_pem_public_key(
        Path("public.pem").read_bytes()
    ).public_numbers()

    n = public_key.n
    e = public_key.e

    c1 = int(data["c1"])
    c2 = int(data["c2"])
    a = int(data["a"])
    b = int(data["b"])

    if e != 3:
        raise RuntimeError(
            f"Expected e=3, got e={e}"
        )

    f = [
        -c1,
        0,
        0,
        1,
    ]

    g = [
        pow(b, 3, n) - c2,
        3 * a * pow(b, 2, n),
        3 * pow(a, 2, n) * b,
        pow(a, 3, n),
    ]

    common = poly_gcd(
        f,
        g,
        n
    )

    if len(common) != 2 or common[1] != 1:
        raise RuntimeError(
            f"Unexpected polynomial GCD: {common}"
        )

    message_integer = (-common[0]) % n
    message = int_to_bytes(message_integer)

    if pow(message_integer, e, n) != c1:
        raise RuntimeError(
            "Recovered message does not match c1"
        )

    related_message = (
        a * message_integer + b
    ) % n

    if pow(related_message, e, n) != c2:
        raise RuntimeError(
            "Recovered message does not match c2"
        )

    decoded = message.decode("utf-8")

    print(f"[+] RSA modulus bits : {n.bit_length()}")
    print(f"[+] Public exponent  : {e}")
    print(f"[+] Recovered message: {decoded}")

    match = re.search(
        r"grodno\{[^}\r\n]+\}",
        decoded
    )

    if not match:
        raise RuntimeError("Flag not found")

    print(f"[+] FLAG: {match.group(0)}")


if __name__ == "__main__":
    main()
```

Install dependency jika belum tersedia:

```bash
pip install cryptography
```

Jalankan solver:

```bash
python3 solve.py
```

---

## Hasil

Output solver:

```text
[+] RSA modulus bits : 2048
[+] Public exponent  : 3
[+] Recovered message: grodno{571ll_4l1v3_bu7_g14d05_k3375_r3w5171ng_m35s4g35}
[+] FLAG: grodno{571ll_4l1v3_bu7_g14d05_k3375_r3w5171ng_m35s4g35}
```

Flag:

```text
grodno{571ll_4l1v3_bu7_g14d05_k3375_r3w5171ng_m35s4g35}
```
