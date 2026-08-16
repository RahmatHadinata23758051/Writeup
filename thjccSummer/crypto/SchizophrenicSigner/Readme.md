# CTF Writeup: Schizophrenic Signer

## Deskripsi Tantangan

Pada tantangan kriptografi **"Schizophrenic Signer"**, kita diberikan akses ke sebuah layanan yang menghasilkan tanda tangan digital ECDSA menggunakan kurva eliptik. Kita diberikan parameter *public key*, *generator params* (nilai `a` dan `b`), serta sejumlah besar tanda tangan digital (`h`, `r`, `s`). Tujuan akhirnya adalah menemukan *Private Key* (`d`).

Petunjuk utama dari tantangan ini adalah kalimat:

> "讓隨機數在兩個不同的世界中反覆跳躍"

yang kurang lebih berarti *"Biarkan angka acak melompat berulang kali di antara dua dunia berbeda"*.

String flag yang akhirnya ditemukan adalah:

```text
THJCC{w0w_y0u_f0und_th3_h1dd3n_d3lt4_b3tw33n_p_4nd_q!}
```

---

## Analisis Teori "Dua Dunia"

Dalam sistem ECDSA, setiap tanda tangan menggunakan sebuah *nonce* (`k`). Pada implementasi yang aman, `k` seharusnya dihasilkan menggunakan sumber randomness kriptografis yang kuat.

Pada challenge ini, `k` justru dihasilkan menggunakan **Linear Congruential Generator (LCG)**.

Cacat utama muncul karena state LCG berjalan pada modulus prime kurva `p`, sedangkan ECDSA bekerja pada modulus order grup `n`.

### Dunia 1 — Prime Field, Modulo `p`

State PRNG diperbarui menggunakan:

$$
k_{i+1} \equiv a \cdot k_i + b \pmod p
$$

### Dunia 2 — Scalar Field, Modulo `n`

ECDSA menggunakan hubungan:

$$
s_i \equiv k_i^{-1}(h_i+r_i d)\pmod n
$$

Sehingga:

$$
k_i \equiv s_i^{-1}h_i+s_i^{-1}r_i d\pmod n
$$

Karena nilai `k` yang sama digunakan oleh kedua sistem, kita dapat menghubungkan kedua dunia tersebut.

---

## 1. Eliminasi Private Key dari Modulo `n`

Definisikan:

$$
A_i=s_i^{-1}h_i\pmod n
$$

dan:

$$
B_i=s_i^{-1}r_i\pmod n
$$

Maka persamaan ECDSA menjadi:

$$
k_i\equiv A_i+B_i d\pmod n
$$

Untuk signature pertama:

$$
d\equiv B_0^{-1}(k_0-A_0)\pmod n
$$

Substitusikan persamaan tersebut ke signature lainnya:

$$
k_i\equiv A_i+B_iB_0^{-1}(k_0-A_0)\pmod n
$$

Dengan:

$$
u_i=B_iB_0^{-1}\pmod n
$$

dan:

$$
v_i=A_i-u_iA_0\pmod n
$$

kita memperoleh:

$$
k_i\equiv u_i k_0+v_i\pmod n
$$

Dengan demikian, seluruh nonce `k_i` dapat direpresentasikan berdasarkan satu variabel, yaitu `k_0`.

---

## 2. Ekspansi LCG pada Modulo `p`

LCG memiliki bentuk:

$$
k_{i+1}\equiv ak_i+b\pmod p
$$

Beberapa iterasi pertama:

$$
k_1\equiv ak_0+b\pmod p
$$

$$
k_2\equiv a^2k_0+ab+b\pmod p
$$

Secara umum:

$$
k_i\equiv U_i k_0+V_i\pmod p
$$

dengan:

$$
U_i=a^i\pmod p
$$

dan:

$$
V_i=\sum_{j=0}^{i-1}a^jb\pmod p
$$

Jadi, dari sisi LCG, `k_i` juga dapat ditulis sebagai fungsi linear terhadap `k_0`.

---

## 3. Menggabungkan Kedua Dunia dengan CRT

Sekarang kita memiliki dua persamaan untuk nonce yang sama:

$$
k_i\equiv u_i k_0+v_i\pmod n
$$

dan:

$$
k_i\equiv U_i k_0+V_i\pmod p
$$

Karena:

$$
\gcd(n,p)=1
$$

kedua persamaan tersebut dapat digabungkan menggunakan **Chinese Remainder Theorem (CRT)**.

Kita mencari `C_i` dan `D_i` sehingga:

$$
C_i\equiv u_i\pmod n
$$

$$
C_i\equiv U_i\pmod p
$$

serta:

$$
D_i\equiv v_i\pmod n
$$

$$
D_i\equiv V_i\pmod p
$$

Dengan modulus gabungan:

$$
M=n\cdot p
$$

maka diperoleh:

$$
k_i\equiv C_i k_0+D_i\pmod M
$$

atau:

$$
k_i-C_i k_0-D_i\equiv0\pmod M
$$

Persamaan inilah yang kemudian dimanfaatkan untuk membangun lattice.

---

## 4. Lattice Reduction dengan LLL

Nilai nonce `k_i` berada pada rentang yang jauh lebih kecil dibandingkan modulus gabungan:

$$
M=n\cdot p
$$

Hal tersebut memungkinkan kita memanfaatkan **Lenstra–Lenstra–Lovász (LLL) lattice reduction** untuk mencari solusi dengan koefisien kecil.

Basis lattice yang digunakan berbentuk:

$$
\begin{bmatrix}
M&0&\cdots&0&0&0\
0&M&\cdots&0&0&0\
\vdots&\vdots&\ddots&\vdots&\vdots&\vdots\
0&0&\cdots&M&0&0\
C_1&C_2&\cdots&C_N&1&0\
D_1&D_2&\cdots&D_N&0&n
\end{bmatrix}
$$

Setelah basis direduksi menggunakan LLL, salah satu vektor pendek akan mengandung informasi mengenai nonce yang dicari.

Dari `k_0`, private key dapat dihitung langsung:

$$
d\equiv B_0^{-1}(k_0-A_0)\pmod n
$$

---

## Skrip Solusi

Berikut solver lengkap menggunakan **pwntools** untuk berkomunikasi dengan server dan **SageMath** untuk perhitungan CRT serta LLL.

```python
from pwn import *
import re
import subprocess

def solve():
    io = remote('chal.thjcc.org', 11451)
    
    io.recvuntil(b"Generator params: ")
    params = io.recvline().decode().strip()

    a = int(
        re.search(r'a = (0x[0-9a-f]+)', params).group(1),
        16
    )
    b = int(
        re.search(r'b = (0x[0-9a-f]+)', params).group(1),
        16
    )
    
    io.recvuntil(b"Here are your signatures:\n")

    sigs = []

    while True:
        line = io.recvline().decode().strip()

        if "Can you find the private key?" in line:
            break

        if line.startswith('h ='):
            h = int(line.split('=')[1].strip(), 16)
            r = int(io.recvline().decode().split('=')[1].strip(), 16)
            s = int(io.recvline().decode().split('=')[1].strip(), 16)

            sigs.append((h, r, s))

    sage_script = f'''
import sys

a = {a}
b = {b}
sigs = {sigs}

curves = [
    (
        "secp256k1",
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
        0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    ),
    (
        "secp256r1",
        0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    )
]

def solve():
    N = min(len(sigs), 15)

    for name, p, n in curves:
        A = []
        B = []

        for i in range(N):
            h, r, s = sigs[i]

            s_inv = inverse_mod(s, n)

            A.append((h * s_inv) % n)
            B.append((r * s_inv) % n)

        B1_inv = inverse_mod(B[0], n)

        C = []
        D = []

        U = 1
        V = 0

        M = n * p

        for i in range(N):
            # Dunia 1: modulo n
            u_i = (B[i] * B1_inv) % n
            v_i = (A[i] - u_i * A[0]) % n

            # Gabungkan kedua dunia menggunakan CRT
            c_i = crt(
                [ZZ(u_i), ZZ(U)],
                [ZZ(n), ZZ(p)]
            )

            d_i = crt(
                [ZZ(v_i), ZZ(V)],
                [ZZ(n), ZZ(p)]
            )

            C.append(c_i)
            D.append(d_i)

            # Dunia 2: LCG modulo p
            U = (U * a) % p
            V = (V * a + b) % p

        mat = matrix(ZZ, N + 2, N + 2)

        for i in range(N):
            mat[i, i] = M
            mat[N, i] = C[i]
            mat[N + 1, i] = D[i]

        mat[N, N] = 1
        mat[N + 1, N + 1] = n

        # LLL reduction
        L = mat.LLL()

        for row in L:
            if abs(row[N + 1]) == n:
                sign = 1 if row[N + 1] > 0 else -1
                k1 = row[N] * sign

                if 0 < k1 < n:
                    d = (B1_inv * (k1 - A[0])) % n
                    print(d)
                    return

solve()
'''

    with open('solver.sage', 'w') as f:
        f.write(sage_script)

    output = subprocess.check_output(
        ['sage', 'solver.sage'],
        stderr=subprocess.STDOUT
    ).decode().strip()

    d = int(output.strip().split('\n')[-1])

    io.recvuntil(b"Private Key (d) in hex: ")
    io.sendline(hex(d).encode())

    io.interactive()


if __name__ == '__main__':
    solve()
```

---

## Hasil Eksekusi

Solver berhasil menemukan private key:

```text
0xd082afce549f0086dbb987d353f8eef32c9ee32cb300cf288ce337b61536c590
```

Private key tersebut kemudian dikirim kembali ke server:

```text
Private Key (d) in hex: 0xd082afce549f0086dbb987d353f8eef32c9ee32cb300cf288ce337b61536c590
```

Server menerima private key yang benar dan memberikan akses ke shell.

---

## Flag

```text
THJCC{w0w_y0u_f0und_th3_h1dd3n_d3lt4_b3tw33n_p_4nd_q!}
```

