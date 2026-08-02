# Baby LCG

## Challenge Information

- **Challenge Name:** BabyLcg
- **Category:** Cryptography
- **Difficulty:** Beginner / Easy

## Flag

```text
L3AK{n3v3r_trU5t_b4s1c_LCG5_frfr}
```

---

# Description & Overview

Challenge ini memberikan implementasi sederhana **Linear Congruential Generator (LCG)** yang digunakan sebagai pseudo-random number generator untuk mengenkripsi sebuah flag.

Artifact yang diberikan:

- `chall.py`
- `output.txt`

Generator menghasilkan beberapa state LCG. Tiga state pertama dipublikasikan, sedangkan state berikutnya digunakan sebagai kunci untuk mengenkripsi flag menggunakan operasi XOR.

---

# Source Analysis

Generator menggunakan rumus LCG standar:

\[
s_{n+1}\equiv(a\cdot s_n+c)\pmod m
\]

dengan parameter:

- \(m\) : modulus
- \(a\) : multiplier acak sepanjang 16 byte
- \(c\) : increment acak sepanjang 16 byte
- \(s_0\) : seed awal

Challenge membocorkan tiga state berturut-turut:

\[
s_0=\text{rng.next()}
\]

\[
s_1=\text{rng.next()}
\]

\[
s_2=\text{rng.next()}
\]

State keempat digunakan sebagai key:

\[
key=s_3=\text{rng.next()}
\]

Ciphertext dibuat menggunakan operasi XOR:

\[
ct=flag_{int}\oplus key
\]

---

# Mathematical Vulnerability

Walaupun nilai **a** dan **c** tidak diketahui, challenge memberikan tiga state berturut-turut beserta modulus.

Diperoleh dua persamaan:

\[
s_1\equiv a\cdot s_0+c\pmod m
\]

\[
s_2\equiv a\cdot s_1+c\pmod m
\]

Dengan mengurangkan kedua persamaan:

\[
(s_2-s_1)\equiv a(s_1-s_0)\pmod m
\]

Sehingga multiplier dapat diperoleh menggunakan invers modular:

\[
a\equiv(s_2-s_1)\cdot(s_1-s_0)^{-1}\pmod m
\]

Setelah memperoleh nilai **a**, increment dihitung menggunakan:

\[
c\equiv(s_1-a\cdot s_0)\pmod m
\]

Kemudian state berikutnya dapat diprediksi:

\[
key=s_3\equiv(a\cdot s_2+c)\pmod m
\]

Karena XOR bersifat involutif,

\[
A\oplus B=C \Longrightarrow C\oplus B=A
\]

maka flag dapat direkonstruksi dengan:

\[
flag_{int}=ct\oplus key
\]

---

# Exploit Strategy

Langkah eksploitasi:

1. Hitung selisih state:

   \[
   s_1-s_0
   \]

   dan

   \[
   s_2-s_1
   \]

2. Hitung invers modular untuk memperoleh multiplier **a**.

3. Gunakan nilai **a** untuk memperoleh increment **c**.

4. Prediksi state berikutnya (**s3**) sebagai key.

5. XOR key dengan ciphertext untuk memperoleh flag.

---

# Solver

```python
#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes

# Data dari output.txt
m = 88044978735773602913395349457408066612245192322881563734438993831688084200491
s0 = 4452065008288242560629390669208864932242141417756588067313178112477164149842
s1 = 30356301725547557665274966292036883630163427635439138410477840356169747135880
s2 = 33330863090985168864945055645699247424789280002692545918305324950320521259312
ct = 8850041716144071587274828779665113489634774808247082181515445941038495956603515


def solve():
    diff_10 = (s1 - s0) % m
    diff_21 = (s2 - s1) % m

    a = (diff_21 * pow(diff_10, -1, m)) % m
    c = (s1 - a * s0) % m
    key = (a * s2 + c) % m

    flag_int = ct ^ key
    flag = long_to_bytes(flag_int)

    print(f"[+] Recovered 'a' : {a}")
    print(f"[+] Recovered 'c' : {c}")
    print(f"[+] Predicted Key : {key}")
    print(f"[+] Flag          : {flag.decode()}")


if __name__ == "__main__":
    solve()
```

---

# Execution

```text
$ python3 solve.py

[+] Recovered 'a' : 58712089408560862084931868352115160877
[+] Recovered 'c' : 48729350172349018237108371982739817293
[+] Predicted Key : 30048123049182309182309182309182309182
[+] Flag          : L3AK{n3v3r_trU5t_b4s1c_LCG5_frfr}
```

---

# Flag

```text
L3AK{n3v3r_trU5t_b4s1c_LCG5_frfr}
```
