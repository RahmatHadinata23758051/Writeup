# Writeup: From Nothing

## Informasi Tantangan

- **Kategori:** Cryptography
- **Judul:** From Nothing
- **Kurva:** Hyperelliptic Curve genus 5

$$
y^2 + y = x^{11}
$$

- **Field:** $\mathbb{F}_p$, dengan $p$ berukuran sekitar 512-bit dan memenuhi:

$$
p \equiv 1 \pmod{11}
$$

- **Tujuan:** Mengembalikan pesan asli dari ciphertext pada Jacobian kurva.
- **Flag:** `NNS{4nd_th3_g1ft3d_c4n_m4k3_s0m3th1ng_fr0m_n0th1ng}`

Challenge ini memberikan data berupa prima $p$, polinomial $u_D(x)$ dari sebuah divisor acak $D$, serta ciphertext dalam bentuk divisor pada Jacobian.

Pesan asli diubah menjadi sebuah titik $P$ pada kurva, lalu titik tersebut dipetakan ke Jacobian menjadi $J(P)$. Ciphertext dibentuk sebagai:

$$
ct = e \cdot J(P)
$$

Masalahnya ada di dua tempat:

1. Scalar $e$ bisa direkonstruksi dari $u_D(x)$ walaupun $v_D(x)$ tidak diberikan.
2. Order Jacobian bisa dihitung karena kurvanya punya struktur khusus.

Nama challenge “From Nothing” cukup pas, karena yang dieksploitasi justru data yang tidak diberikan: $v_D(x)$.

---

## Analisis Kerentanan

### 1. Kebocoran Scalar dari $u_D(x)$

Divisor pada Jacobian hyperelliptic curve biasanya direpresentasikan dalam bentuk Mumford:

$$
D = (u_D(x), v_D(x))
$$

Tetapi challenge hanya memberikan $u_D(x)$, sedangkan $v_D(x)$ disembunyikan.

Sekilas ini terlihat aman, tapi untuk kurva:

$$
y^2 + y = x^{11}
$$

polinomial $v_D(x)$ tidak bebas. Ia harus memenuhi relasi:

$$
v_D(x)^2 + v_D(x) \equiv x^{11} \pmod{u_D(x)}
$$

Relasi ini bisa diubah menjadi bentuk kuadrat sempurna:

$$
(2v_D(x) + 1)^2 \equiv 1 + 4x^{11} \pmod{u_D(x)}
$$

Artinya, untuk mendapatkan $v_D(x)$, cukup cari akar kuadrat dari:

$$
1 + 4x^{11}
$$

modulo $u_D(x)$.

Karena $u_D(x)$ bisa difaktorkan di $\mathbb{F}_p$, akar kuadrat bisa dicari per faktor. Untuk setiap faktor, akar kuadrat punya dua kemungkinan, yaitu $+s$ dan $-s$. Semua kombinasi akar kemudian digabung lagi menggunakan CRT polynomial.

Dari hasil rekonstruksi $v_D(x)$, scalar enkripsi $e$ diambil dari koefisien konstannya:

$$
e = v_D(0)
$$

Karena ada beberapa pilihan tanda akar, kita tidak langsung dapat satu nilai $e$, tetapi daftar kandidat $e$.

---

### 2. Order Jacobian Bisa Direkonstruksi

Untuk membalik ciphertext:

$$
ct = e \cdot J(P)
$$

kita butuh inverse dari $e$ modulo order grup Jacobian:

$$
d \equiv e^{-1} \pmod{N}
$$

Setelah itu plaintext bisa dipulihkan dengan:

$$
J(P) = d \cdot ct
$$

Masalah normalnya: menghitung order Jacobian genus 5 bukan hal ringan.

Namun kurva yang dipakai punya bentuk spesial:

$$
y^2 + y = x^{11}
$$

Karena $p \equiv 1 \pmod{11}$, field mengandung akar ke-11 dari satuan. Ini membuat kurva punya struktur automorphism kuat dan berkaitan dengan cyclotomic field:

$$
K = \mathbb{Q}(\zeta_{11})
$$

Dengan sifat Complex Multiplication, Weil root dari Frobenius bisa dicari melalui ideal di field cyclotomic tersebut.

Script menggunakan pendekatan berbasis Stickelberger dan LLL:

1. Bangun relasi akar ke-11 modulo $p$.
2. Cari kernel sebagai representasi ideal.
3. Bentuk lattice integer.
4. Jalankan LLL.
5. Ambil vektor pendek sebagai kandidat Jacobi sum.
6. Hitung kandidat order Jacobian dari norm.

Order kandidat dihitung dari:

$$
N = Norm(1 - \alpha)
$$

dengan:

$$
\alpha = \pm \zeta_{11}^{k} g
$$

untuk $k = 0,1,\dots,10$.

Karena ada faktor unit $\pm \zeta_{11}^k$, didapat 22 kandidat order.

---

## Walkthrough Eksploitasi

### Langkah 1 — Setup Kurva dan Ciphertext

Field dan polynomial ring dibuat dari prima $p$:

```sage
F = GF(p)
R_p.<x> = PolynomialRing(F)
```

Kurva didefinisikan sebagai:

```sage
H = HyperellipticCurve(x^11, 1, "u,v")
J = H.jacobian()
J = J(J.base_ring())
```

Ciphertext dibentuk dari pasangan polinomial Mumford:

```sage
ct = J([R_p(ct_u_coeffs), R_p(ct_v_coeffs)])
```

---

### Langkah 2 — Rekonstruksi Kandidat Scalar `e`

Faktorkan $u_D(x)$:

```sage
factors = D_u.factor()
```

Untuk setiap faktor $f_i(x)$, hitung akar kuadrat dari diskriminan:

```sage
delta = 1 + 4 * root^11
s = delta.sqrt()
```

Jika faktornya berderajat lebih dari 1, perhitungan dilakukan pada extension field:

```sage
F_ext.<a> = GF(p^f.degree(), modulus=f)
delta = 1 + 4 * a^11
s = delta.sqrt()
```

Setiap faktor memberikan dua kandidat:

```sage
[S_poly, -S_poly]
```

Semua kombinasi tanda digabung menggunakan CRT polynomial:

```sage
S_x = poly_crt(list(r_comb), mods)
```

Lalu $v_D(x)$ direkonstruksi:

```sage
v_D = (S_x - 1) * inverse_mod(2, p) % D_u
```

Scalar kandidat diambil dari koefisien konstannya:

```sage
e_cands.append(int(v_D[0]))
```

Pada titik ini, kita punya beberapa kandidat scalar `e`.

---

### Langkah 3 — Menghitung Kandidat Order Jacobian

Cyclotomic field dibuat:

```sage
K.<z> = CyclotomicField(11)
```

Lalu dicari elemen akar ke-11 modulo $p$:

```sage
r = F(2)^((p - 1) // 11)

while r == 1:
    r = F.random_element()^((p - 1) // 11)
```

Matriks relasi dibangun dari pangkat-pangkat $r$:

```sage
M = Matrix(GF(p), 5, 10)

for j, x_pow in enumerate([1, 2, 3, 4, 5]):
    rx = r^x_pow
    for i in range(10):
        M[j, i] = rx^i
```

Kernel dari matriks ini menjadi bagian awal basis lattice:

```sage
B = M.right_kernel().basis_matrix().change_ring(ZZ)
```

Lattice dibuat dengan tambahan batas prima $p$:

```sage
L = Matrix(ZZ, 15, 10)

for i in range(5):
    for j in range(10):
        L[i, j] = B[i, j]

for i in range(10):
    L[5 + i, i] = p
```

LLL digunakan untuk mencari vektor pendek:

```sage
g_coeffs = next(row for row in L.LLL() if not row.is_zero())
```

Vektor tersebut diubah menjadi elemen pada cyclotomic field:

```sage
g = sum(c * z^i for i, c in enumerate(g_coeffs))
```

Validasi norm:

```sage
assert g * sum(c * z^(-i) for i, c in enumerate(g_coeffs)) == p
```

Dari elemen ini, semua kandidat order dihitung:

```sage
Ns = set()

for sign in [1, -1]:
    for k in range(11):
        alpha = sign * (z^k) * g
        Ns.add(Integer((1 - alpha).norm()))
```

---

### Langkah 4 — Filter Order yang Benar

Tidak semua kandidat `N` benar untuk ciphertext. Order yang benar harus membuat ciphertext menjadi identity saat dikalikan:

```sage
if (N * ct) == J(0):
    valid_Ns.append(N)
```

Secara matematis:

$$
N \cdot ct = \mathcal{O}
$$

dengan $\mathcal{O}$ sebagai elemen identitas Jacobian.

Kandidat yang lolos filter ini dipakai untuk proses dekripsi.

---

### Langkah 5 — Dekripsi Ciphertext

Untuk setiap kandidat order valid dan kandidat scalar `e`, cek apakah inverse modular ada:

```sage
if gcd(e, valid_N) != 1:
    continue
```

Kalau `gcd(e, N) = 1`, hitung inverse:

```sage
d = inverse_mod(e, valid_N)
```

Kemudian balik ciphertext:

```sage
P_cand = d * ct
```

Karena:

$$
ct = e \cdot J(P)
$$

maka:

$$
d \cdot ct = d \cdot e \cdot J(P)
$$

dan karena:

$$
d \cdot e \equiv 1 \pmod{N}
$$

hasilnya adalah:

$$
J(P)
$$

---

### Langkah 6 — Ambil Pesan dari Titik

Plaintext asli dibuat sebagai titik berbobot 1. Pada representasi Mumford, divisor bobot 1 punya bentuk:

$$
u_P(x) = x - x_m
$$

Jadi jika derajat $u_P(x)$ adalah 1, nilai pesan bisa diambil dari koefisien konstannya:

```sage
u_cand = P_cand[0]

if u_cand.degree() == 1:
    x_m = int(-u_cand[0])
```

Nilai $x_m$ adalah integer hasil encoding flag. Konversi ke bytes big-endian:

```sage
flag = x_m.to_bytes((x_m.bit_length() + 7) // 8, "big")
```

Validasi dilakukan dengan marker flag:

```sage
if b"NNS{" in flag:
    print(f"<FLAG>{flag.decode()}</FLAG>")
```

---

## Kenapa Eksploit Ini Berhasil

Eksploit ini berhasil karena challenge membocorkan cukup informasi dari divisor acak.

Walaupun $v_D(x)$ tidak diberikan, $u_D(x)$ sudah cukup untuk membatasi kemungkinan $v_D(x)$ melalui persamaan kurva. Dari sana, scalar `e` bisa ditebak dalam ruang kandidat kecil.

Bagian kedua memanfaatkan struktur kurva yang terlalu spesial. Kurva genus 5 biasa sulit dihitung order Jacobian-nya, tetapi bentuk $x^{11}$ membuat kurva punya automorphism dan Complex Multiplication. Akibatnya, point counting bisa direduksi menjadi pencarian vektor pendek pada lattice, lalu diselesaikan dengan LLL.

Begitu `e` dan `N` diketahui, ciphertext hanya scalar multiplication biasa pada grup berhingga. Dekripsinya tinggal menghitung inverse scalar.

---

## Solver

Simpan script sebagai `solve.sage`, lalu jalankan dengan SageMath.

```bash
sage solve.sage
```

Output:

```text
<FLAG>NNS{4nd_th3_g1ft3d_c4n_m4k3_s0m3th1ng_fr0m_n0th1ng}</FLAG>
```

---

## Flag

```text
NNS{4nd_th3_g1ft3d_c4n_m4k3_s0m3th1ng_fr0m_n0th1ng}
```
