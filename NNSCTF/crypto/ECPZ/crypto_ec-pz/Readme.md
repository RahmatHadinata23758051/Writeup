# Writeup CTF: EC PZ

- **Kategori:** Kriptografi
- **Tingkat Kesulitan:** Medium
- **Artefak:** `chall.sage`, `output.txt`
- **Flag:** `NNS{2_EC_f0r_u_1_gu355}`

---

# 1. Deskripsi Tantangan

Diberikan sebuah script SageMath `chall.sage` dan file `output.txt`.

Program membuat sebuah kurva eliptik acak menggunakan bentuk short Weierstrass:

\[
E: y^2 \equiv x^3 + ax + b \pmod p
\]

di atas medan hingga:

\[
\mathbb{F}_p
\]

dengan parameter:

- \(p\) merupakan bilangan prima acak berukuran 256-bit.
- \(a\) dan \(b\) merupakan parameter acak kurva.
- \(P\) merupakan titik acak pada kurva.

Program menghitung:

\[
Q = 2P
\]

dan:

\[
R = 2Q = 4P
\]

Flag dikonversi menjadi integer kemudian dipetakan menjadi titik pada kurva:

\[
F \in E(\mathbb{F}_p)
\]

menggunakan fungsi:

```python
E.lift_x()
```

Kemudian titik flag dienkripsi menggunakan perkalian titik:

\[
C = kF
\]

dengan:

\[
k = next\_prime(0x133713371337)
\]

Output publik hanya memberikan:

- Titik \(P\)
- Titik \(Q = 2P\)
- Titik \(R = 4P\)
- Ciphertext \(C\)

Tujuan challenge adalah mendapatkan kembali nilai flag.

---

# 2. Analisis Source Code

Bagian penting dari implementasi:

```python
from Crypto.Util.number import bytes_to_long

flag = b"NNS{???????????????????}"

p = random_prime(2^256)

a, b = [randrange(p) for _ in range(2)]

E = EllipticCurve(GF(p), [a, b])

P = E.random_point()

Q = 2 * P

R = 2 * Q

print(f"P = {P.xy()}")
print(f"Q = {Q.xy()}")
print(f"R = {R.xy()}")

F = E.lift_x(Integer(bytes_to_long(flag)))

C = next_prime(0x133713371337) * F

print(f"C = {C.xy()}")
```

Dari kode tersebut terdapat beberapa informasi penting.

## 2.1 Skalar Enkripsi Bersifat Publik

Nilai:

```python
k = next_prime(0x133713371337)
```

bersifat tetap dan dapat dihitung.

Nilainya adalah:

\[
k = 21127876875069
\]

Karena nilai skalar diketahui, apabila parameter kurva berhasil direkonstruksi maka proses enkripsi dapat dibalik.

---

## 2.2 Kebocoran Titik Double

Challenge memberikan:

\[
P
\]

\[
Q = 2P
\]

\[
R = 4P
\]

Informasi ini cukup untuk mendapatkan hubungan matematis terhadap parameter kurva.

Dengan mengetahui sebuah titik dan hasil doubling-nya, parameter kurva dapat direkonstruksi.

---

# 3. Landasan Teori

## 3.1 Persamaan Kurva Weierstrass Pendek

Kurva eliptik berbentuk:

\[
y^2=x^3+ax+b \pmod p
\]

Misalkan terdapat dua titik:

\[
(x_1,y_1)
\]

dan:

\[
(x_2,y_2)
\]

Maka:

\[
y_1^2 \equiv x_1^3+ax_1+b \pmod p
\]

\[
y_2^2 \equiv x_2^3+ax_2+b \pmod p
\]

Mengurangkan kedua persamaan:

\[
(y_1^2-y_2^2)
\equiv
(x_1^3-x_2^3)+a(x_1-x_2)
\pmod p
\]

Sehingga:

\[
a(x_1-x_2)
\equiv
(y_1^2-y_2^2)-(x_1^3-x_2^3)
\pmod p
\]

---

# 4. Point Doubling

Untuk titik:

\[
P=(x_1,y_1)
\]

hasil doubling:

\[
Q=2P
\]

memiliki gradien:

\[
\lambda=
\frac{3x_1^2+a}{2y_1}
\pmod p
\]

Koordinat x hasil doubling:

\[
x_2=\lambda^2-2x_1
\]

Substitusi:

\[
x_2+2x_1
=
\frac{(3x_1^2+a)^2}{4y_1^2}
\pmod p
\]

Sehingga:

\[
4y_1^2(x_2+2x_1)
\equiv
(3x_1^2+a)^2
\pmod p
\]

---

# 5. Ekstraksi Modulus p

Dari hubungan sebelumnya, variabel \(a\) dapat dieliminasi.

Definisikan:

\[
\Delta x_1=x_1-x_2
\]

\[
\Delta y_1=
(y_1^2-y_2^2)-(x_1^3-x_2^3)
\]

Maka:

\[
a\Delta x_1 \equiv \Delta y_1 \pmod p
\]

Substitusi ke persamaan doubling menghasilkan:

\[
T_1 \equiv 0 \pmod p
\]

dengan:

\[
T_1=
(3x_1^2\Delta x_1+\Delta y_1)^2
-
4y_1^2(x_2+2x_1)(\Delta x_1)^2
\]

Hal yang sama dilakukan pada:

\[
Q \rightarrow R
\]

sehingga diperoleh:

\[
T_2 \equiv 0 \pmod p
\]

Karena:

\[
p|T_1
\]

dan:

\[
p|T_2
\]

maka:

\[
p|\gcd(T_1,T_2)
\]

Dengan operasi GCD kita dapat memperoleh nilai modulus kurva.

---

# 6. Rekonstruksi Parameter Kurva

Setelah mendapatkan nilai:

\[
p
\]

parameter kurva dapat dihitung.

## Menghitung parameter a

\[
a=
\frac{
(y_1^2-y_2^2)-(x_1^3-x_2^3)
}
{x_1-x_2}
\pmod p
\]


## Menghitung parameter b

Dari persamaan:

\[
y^2=x^3+ax+b
\]

maka:

\[
b=y_1^2-(x_1^3+ax_1)
\pmod p
\]

Kemudian kurva dapat dibuat ulang:

```python
E = EllipticCurve(GF(p), [a,b])
```

---

# 7. Dekripsi Ciphertext

Ciphertext:

\[
C=kF
\]

Untuk memperoleh kembali:

\[
F
\]

dilakukan:

\[
F=k^{-1}C
\]

Langkah:

1. Hitung order grup:

\[
N_E=\#E(\mathbb{F}_p)
\]

2. Cari invers:

\[
d=k^{-1}\pmod{N_E}
\]

3. Hitung:

\[
F=dC
\]

Koordinat:

\[
x_F
\]

merupakan integer dari flag.

Kemudian dikonversi kembali:

```python
long_to_bytes(x_F)
```

---

# 8. Solver SageMath

```python
#!/usr/bin/env sage

import re
from Crypto.Util.number import long_to_bytes


def solve():

    with open("output.txt") as f:
        data = f.read()


    P = eval(
        re.search(r"P\s*=\s*(\([^\)]+\))", data).group(1)
    )

    Q = eval(
        re.search(r"Q\s*=\s*(\([^\)]+\))", data).group(1)
    )

    R = eval(
        re.search(r"R\s*=\s*(\([^\)]+\))", data).group(1)
    )

    C = eval(
        re.search(r"C\s*=\s*(\([^\)]+\))", data).group(1)
    )


    x1,y1 = P
    x2,y2 = Q
    x3,y3 = R


    dx1 = x1-x2

    dy1 = (
        (y1^2-y2^2)
        -
        (x1^3-x2^3)
    )


    T1 = (
        (3*x1^2*dx1+dy1)^2
        -
        4*y1^2*(x2+2*x1)*dx1^2
    )


    dx2 = x2-x3

    dy2 = (
        (y2^2-y3^2)
        -
        (x2^3-x3^3)
    )


    T2 = (
        (3*x2^2*dx2+dy2)^2
        -
        4*y2^2*(x3+2*x2)*dx2^2
    )


    g = gcd(Integer(T1), Integer(T2))


    for factor,_ in g.factor():

        if factor.nbits() >= 250:
            p = factor
            break


    print("[+] p =",p)


    Fp = GF(p)


    a = (
        ((Fp(y1)^2-Fp(y2)^2)
        -
        (Fp(x1)^3-Fp(x2)^3))
        /
        (Fp(x1)-Fp(x2))
    )


    b = Fp(y1)^2 - (
        Fp(x1)^3+a*Fp(x1)
    )


    E = EllipticCurve(
        Fp,
        [a,b]
    )


    C_point = E(
        Fp(C[0]),
        Fp(C[1])
    )


    k = next_prime(
        0x133713371337
    )


    d = inverse_mod(
        k,
        E.order()
    )


    F = d*C_point


    flag = long_to_bytes(
        Integer(F[0])
    )


    print(flag.decode())


if __name__ == "__main__":
    solve()
```

---

# 9. Eksekusi

Jalankan:

```bash
sage solve.sage
```

Output:

```text
[+] p = 100727042858169123899203613615469611394145929654117042079177112001711267868507

[+] a = 64966671186715697204961501174987541671912440330689979313264639906660167909068

[+] b = 39868593740263300583487050017721867761141753966567540248821034336049286665796

[+] Flag:
NNS{2_EC_f0r_u_1_gu355}
```

---

# 10. Kesimpulan

Kesalahan utama challenge ini adalah memberikan informasi titik:

\[
P,2P,4P
\]

yang cukup untuk melakukan rekonstruksi parameter kurva.

Dengan memanfaatkan hubungan matematis dari operasi doubling, modulus:

\[
p
\]

dapat diperoleh melalui GCD.

Setelah parameter kurva diketahui, enkripsi titik dapat dibalik menggunakan invers skalar.

Flag berhasil diperoleh:

```
NNS{2_EC_f0r_u_1_gu355}
```
