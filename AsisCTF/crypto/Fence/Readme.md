# Fence Writeup

## Ringkasan

Skema kriptografi pada challenge Fence memiliki struktur yang mirip dengan NTRU.

Public key $h$ dibentuk dari dua polinom kecil $a$ dan $b$:

$$
h = b \cdot a^{-1} \pmod{x^{128}+1,\ q}
$$

Secret $a$ dan $b$ bukan polinom random berkoefisien besar. Keduanya merupakan polinom ternary, sehingga setiap koefisien hanya bernilai:

$$
-1,\ 0,\ 1
$$

dengan weight:

$$
w = 80
$$

Karena:

$$
h = \frac{b}{a}
$$

maka berlaku relasi:

$$
a \cdot h = b \pmod q
$$

Relasi ini dapat diubah menjadi persoalan pencarian shortest vector pada lattice NTRU.

Challenge juga tidak mengenkripsi flag secara langsung. Terdapat 5 ciphertext. Empat plaintext pertama merupakan random share, sedangkan plaintext kelima merupakan hasil XOR antara seluruh random share dan flag.

Setelah seluruh ciphertext berhasil didekripsi, flag diperoleh melalui:

$$
\text{flag} = pt_0 \oplus pt_1 \oplus pt_2 \oplus pt_3 \oplus pt_4
$$

## Parameter

Parameter yang digunakan challenge:

```
n = 128
q = 268435361
w = 80
r = 5
```

Untuk setiap public key `H[i]`, secret $(a,b)$ memiliki norm yang sangat kecil.

Karena masing-masing polinom memiliki weight 80 dan koefisien non-zero hanya bernilai $\pm 1$:

$$
|a|^2 = 80
$$

$$
|b|^2 = 80
$$

Sehingga:

$$
|(b,a)|^2 = 160
$$

Nilai ini sangat kecil dibandingkan skala modulus $q$.

## Kelemahan

Dari persamaan:

$$
a \cdot h = b \pmod q
$$

vector:

$$
(b \parallel a)
$$

berada di dalam lattice NTRU yang dibangun dari public key $h$.

Basis lattice yang digunakan:

$$
\begin{bmatrix}
qI & 0 \\
H  & I
\end{bmatrix}
$$

dengan:

- $I$ adalah identity matrix berukuran $n \times n$
- $H$ adalah matriks konvolusi negacyclic dari public key $h$

Karena secret $a$ dan $b$ sangat kecil, vector:

$$
(b \parallel a)
$$

menjadi vector yang sangat pendek di dalam lattice.

Setelah basis direduksi menggunakan LLL atau BKZ, vector dengan squared norm sekitar:

$$
160
$$

dapat ditemukan.

Vector tersebut merupakan:

$$
(b \parallel a)
$$

atau versi sign-flip:

$$
(-b \parallel -a)
$$

Keduanya ekuivalen untuk proses recovery key.

## Eksploitasi

Alur solver:

1. Parse file `flag.enc`.
2. Ambil setiap public key `H[i]`.
3. Bangun lattice NTRU dari public key tersebut.
4. Recover shortest vector $(b \parallel a)$ menggunakan LLL/BKZ.
5. Pisahkan vector hasil recovery menjadi secret $b$ dan $a$.
6. Gunakan $(a,b)$ untuk merekonstruksi key yang sama dengan server.
7. Validasi candidate key menggunakan HMAC tag pada ciphertext.
8. Jika HMAC valid, decrypt plaintext share.
9. Ulangi sampai seluruh 5 ciphertext berhasil didekripsi.
10. XOR seluruh plaintext:

$$
\text{flag} = pt_0 \oplus pt_1 \oplus pt_2 \oplus pt_3 \oplus pt_4
$$

Di folder challenge ini, `solve.py` sudah berisi vector pendek hasil recovery lattice.
Script tetap melakukan validasi menggunakan HMAC sebelum menerima plaintext, sehingga hasil akhir bukan sekadar XOR langsung terhadap ciphertext.

## Menjalankan Solver

Aktifkan environment:

```
source /home/nata/ctf_env/bin/activate
```

Kemudian jalankan:

```
python3 solve.py
```

Output:

```
<FLAG>ASIS{qu4ntum_c0h3r3nc3_1n_0v3r5tr3tch3d_h4rm0n1c_f13ld5!}</FLAG>
```

## Flag

```
ASIS{qu4ntum_c0h3r3nc3_1n_0v3r5tr3tch3d_h4rm0n1c_f13ld5!}
```
