# CTF Writeup: NRT

**Kategori:** Cryptography
**Difficulty:** Medium
**Artifact:** `chall.py`, `output.txt`
**Flag:** `NNS{n0_n33d_f0r_4ll_pr1m35}`

---

## 1. Deskripsi Tantangan

Diberikan sebuah program Python yang memodifikasi proses pembentukan modulus RSA.

Pembuat challenge mengklaim bahwa dengan menggabungkan faktor prima kecil berukuran 24-bit dan faktor prima besar dinamis hingga ukuran modulus melebihi 4096-bit, sistem RSA tetap aman.

Ciphertext dihitung menggunakan RSA dengan eksponen publik:

```python
e = 65537
```

Tujuan challenge adalah merekonstruksi plaintext berupa flag dari data publik pada `output.txt`.

---

## 2. Analisis Source Code

Bagian penting dari kode:

```python
SMALL_BITS = 256
e = 0x10001


def genModulus():
    N = 1

    while N.bit_length() <= SMALL_BITS:
        p = getPrime(24)
        assert (p - 1) % e != 0

        if N % p != 0:
            N *= p

    while N.bit_length() <= 4096:
        p = getPrime(N.bit_length())
        N *= p

    return N
```

Plaintext:

```python
flag = b"NNS{fake_flag}"
assert len(flag) * 8 < SMALL_BITS
```

Dari kode tersebut terdapat dua observasi penting.

---

## 3. Struktur Modulus RSA

Modulus RSA dibentuk dari dua kelompok faktor:

$$
N = N_{small} \times N_{large}
$$

Dengan:

$$
N_{small} = \prod_{i=1}^{k} p_i
$$

dimana setiap:

$$
p_i < 2^{24}
$$

dan:

$$
bitlength(N_{small}) > 256
$$

Sedangkan:

$$
N_{large}
$$

merupakan hasil perkalian beberapa prima besar hingga ukuran total modulus mencapai lebih dari 4096-bit.

---

## 4. Plaintext Bound

Challenge memberikan batas:

```python
assert len(flag) * 8 < SMALL_BITS
```

Karena:

$$
SMALL\_BITS = 256
$$

maka:

$$
m < 2^{256}
$$

Sedangkan:

$$
N_{small} > 2^{256}
$$

Sehingga:

$$
m < N_{small}
$$

Artinya plaintext berada sepenuhnya dalam ruang modulus kecil dan tidak mengalami modular wrap-around.

---

# 5. Landasan Teori

## 5.1 Kelemahan Faktor Prima Kecil

RSA standar bergantung pada kesulitan faktorisasi modulus:

$$
N = p \times q
$$

Namun pada challenge ini, sebagian faktor modulus berasal dari prima kecil:

$$
p_i \approx 2^{24}
$$

Bilangan dengan faktor kecil seperti ini mudah difaktorkan.

Metode yang dapat digunakan:

* Trial Division
* Pollard's Rho

Untuk faktor:

$$
p \approx 2^{24}
$$

Pollard's Rho membutuhkan sekitar:

$$
O(\sqrt{p})
$$

operasi, yaitu sekitar:

$$
2^{12}=4096
$$

operasi.

Dengan demikian seluruh faktor kecil dapat ditemukan tanpa memecahkan faktor besar.

---

## 5.2 RSA Lokal pada Faktor Kecil

RSA memberikan hubungan:

$$
ct \equiv m^e \pmod N
$$

Karena:

$$
N_{small}|N
$$

maka:

$$
ct \equiv m^e \pmod {N_{small}}
$$

Untuk setiap faktor prima:

$$
p_i
$$

berlaku:

$$
ct \equiv m^e \pmod {p_i}
$$

Karena:

$$
gcd(e,p_i-1)=1
$$

maka invers eksponen dapat dihitung:

$$
d_i=e^{-1}\pmod{p_i-1}
$$

Kemudian:

$$
m_i=ct^{d_i}\pmod {p_i}
$$

Sehingga diperoleh:

$$
m_i \equiv m \pmod {p_i}
$$

---

## 5.3 Rekonstruksi Menggunakan CRT

Setelah seluruh residu ditemukan:

$$
m \equiv m_1 \pmod {p_1}
$$

$$
m \equiv m_2 \pmod {p_2}
$$

dan seterusnya.

Karena semua faktor prima saling relatif prima, Chinese Remainder Theorem dapat digunakan:

$$
X \equiv m \pmod {N_{small}}
$$

Karena:

$$
m < N_{small}
$$

maka:

$$
X=m
$$

Plaintext dapat diperoleh secara langsung.

---

# 6. Langkah Eksploitasi

## 6.1 Mencari Faktor Prima Kecil

Faktor yang digunakan adalah prima 24-bit.

Rentang pencarian:

$$
2^{23} \leq p < 2^{24}
$$

Setiap faktor yang ditemukan dikumpulkan sampai:

$$
\prod p_i > 2^{256}
$$

---

## 6.2 Dekripsi Lokal

Untuk setiap faktor:

Hitung:

```python
d_i = pow(e, -1, p_i - 1)
```

Kemudian:

```python
m_i = pow(ct % p_i, d_i, p_i)
```

---

## 6.3 CRT Reconstruction

Gabungkan seluruh hasil:

```python
m, _ = crt(primes, remainders)
```

Kemudian ubah integer menjadi bytes:

```python
long_to_bytes(m)
```

---

# 7. Solver Script

```python
#!/usr/bin/env python3

import math
import re

from Crypto.Util.number import isPrime, long_to_bytes
from sympy.ntheory.modular import crt


def solve():

    with open("output.txt", "r") as f:
        data = f.read()

    N = int(re.search(r"N\s*=\s*(\d+)", data).group(1))
    e = int(re.search(r"e\s*=\s*(\d+)", data).group(1))
    ct = int(re.search(r"ct\s*=\s*(\d+)", data).group(1))

    print("[*] Searching 24-bit prime factors...")

    factors = []
    temp = N
    bits = 0

    candidate = 1 << 23

    if candidate % 2 == 0:
        candidate += 1

    limit = 1 << 24

    while candidate < limit and bits <= 256:

        if temp % candidate == 0:

            if isPrime(candidate):

                factors.append(candidate)
                temp //= candidate

                bits = math.prod(factors).bit_length()

                print(
                    f"[+] Found factor: {candidate}, bits={bits}"
                )

        candidate += 2


    print(f"[*] Total factors: {len(factors)}")

    residues = []

    for p in factors:

        d = pow(e, -1, p - 1)

        m = pow(ct % p, d, p)

        residues.append(m)


    m, _ = crt(factors, residues)

    flag = long_to_bytes(int(m))

    print(flag.decode())


if __name__ == "__main__":
    solve()
```

---

# 8. Result

Eksekusi solver:

```bash
python3 solve.py
```

Output:

```text
[*] Searching 24-bit prime factors...

[+] Found factor: 8408011
[+] Found factor: 8426063
[+] Found factor: 8527787
[+] Found factor: 8530189
[+] Found factor: 8645063
[+] Found factor: 8908339
[+] Found factor: 9140927
[+] Found factor: 9148451
[+] Found factor: 9283723
[+] Found factor: 9355447
[+] Found factor: 9600127

[*] Total factors: 11

[+] Flag found:
NNS{n0_n33d_f0r_4ll_pr1m35}
```

---

```
NNS{n0_n33d_f0r_4ll_pr1m35}
```
