# Inside

- **CTF:** R3CTF 2026
- **Category:** Crypto
- **Challenge:** Inside
- **Description:** `Crashed PoLwE`
- **Flag:** `r3ctf{to_eNd-UP-wherE-WE_4r3-m34NT_to-638a109}`

## Ringkasan

Service meminta proof of knowledge untuk sebuah sampel RLWE:

\[
b = a \cdot s + e \pmod{x^{256}+1,\ 3329}
\]

Witness aslinya berisi tiga polinomial:

- \(s_i \in \{-1,0,1\}\)
- \(e_i \in \{-1,0,1\}\)
- \(k\), yaitu quotient dari reduksi modulo \(3329\)

Relasi tersebut tidak diverifikasi sebagai persamaan polinomial integer. Seluruh pengecekan dipindahkan ke grup secp256k1, sehingga koefisien dihitung modulo orde kurva. Karena `3329` memiliki invers modulo orde secp256k1, nilai `k_i` bisa dipilih bebas untuk menutup persamaan verifier.

## Audit Source

`rlwe_gen()` membuat statement dan witness secara jujur:

```python
b = (a*s + e) % f % qq
k = ((a*s + e) % f - b) // qq
```

dengan:

```python
qq = 3329
n = 256
f = x**n + 1
```

Server hanya mengirim `st = (a, b)`. Client harus mengirim `aux` dan tiga sigma proof:

1. proof bit decomposition untuk `s`
2. proof bit decomposition untuk `e`
3. proof discrete log untuk `k`

CRS dibuat sebagai:

```python
crs[i] = tau**i * G
```

di atas secp256k1.

## Bentuk Proof

`MaurerProof` memakai Fiat–Shamir:

\[
R = \phi(r)
\]

\[
c = H(R \parallel Y \parallel \phi)
\]

\[
z = r + cx \pmod Q
\]

Verifier mengecek:

\[
\phi(z) = R + cY
\]

dengan \(Q\) sebagai orde secp256k1.

Proof ini hanya membuktikan bahwa client mengetahui skalar yang menghasilkan titik-titik pada `aux`. Proof tersebut tidak membatasi besar nilai `k`, dan tidak membuktikan bahwa `k` merupakan quotient integer kecil dari operasi RLWE.

## Memilih Witness Sederhana

Pilih semua koefisien:

\[
s_i = -1,\qquad e_i = -1
\]

Encoding bit memakai `si + 1` dan `ei + 1`. Nilai tersebut menjadi nol:

\[
s_i + 1 = e_i + 1 = 0
\]

Maka semua bit adalah `00`, sehingga:

```python
aux_s[i] = [O, O]
aux_e[i] = [O, O]
```

Untuk dua proof bit, witness, nonce, commitment, dan response dapat dibuat nol:

```python
R = [O, O, ...]
z = [0, 0, ...]
```

Karena semua statement point pada bagian tersebut juga nol:

\[
\phi(0)=0=R+cY
\]

untuk challenge Fiat–Shamir berapa pun.

## Menurunkan Nilai `k`

Verifier membentuk:

```python
Ax[i] = sum(a[j] * crs[(i+j) % n] for j in range(n))
Bx = sum(b[i] * crs[i] for i in range(n))
Ex = sum(bits_e_i * crs[i] - crs[i])
Kx = sum(aux_k[i])
```

Karena semua bit `e` nol:

\[
E_x = -\sum_i CRS_i
\]

Definisikan:

\[
A = \sum_j a_j
\]

Penjumlahan seluruh `Ax[i]` memberi:

\[
\sum_i A_{x,i}
  = A\sum_i CRS_i
\]

Dengan witness bit `s` seluruhnya nol, output pertama dari homomorphism harus menjadi titik identitas. Statement verifier berubah menjadi:

\[
3329K_x + B_x - E_x + \sum_i A_{x,i} = O
\]

Substitusi definisinya:

\[
\sum_i
\left(
3329k_i+b_i+1+A
\right) CRS_i = O
\]

Cukup buat setiap koefisien nol modulo orde kurva \(Q\):

\[
3329k_i+b_i+1+A \equiv 0 \pmod Q
\]

Karena:

\[
\gcd(3329,Q)=1
\]

maka invers modular tersedia:

\[
k_i =
(-A-b_i-1)\cdot3329^{-1}
\pmod Q
\]

Nilai ini bukan quotient RLWE yang jujur. Biasanya ukurannya mendekati orde secp256k1, tetapi verifier tidak melakukan range check.

Auxiliary commitment untuk `k` dibuat sebagai:

\[
Y_i = k_i CRS_i
\]

atau:

```python
aux_k[i] = k[i] * crs[i]
```

## Memalsukan Proof `k`

Homomorphism ketiga bersifat diagonal:

\[
\phi(k)_i = k_i CRS_i
\]

Pilih nonce nol:

\[
r_i=0,\qquad R_i=O
\]

Hitung challenge sesuai implementasi server:

\[
c=H(R\parallel Y\parallel\phi)
\]

Response:

\[
z_i=ck_i\pmod Q
\]

Verifier memperoleh:

\[
\phi(z)_i
  = ck_i CRS_i
  = cY_i
  = R_i+cY_i
\]

Proof lolos tanpa mengetahui witness RLWE asli.

## Alur Solver

Solver melakukan langkah berikut:

1. brute-force PoW empat karakter dengan multiprocessing
2. meminta CRS melalui menu `C`
3. meminta statement `(a, b)` melalui menu `R`
4. menetapkan seluruh `s_i=e_i=-1`
5. menghitung `k_i` modulo orde secp256k1
6. membangun `aux`
7. membuat dua zero proof dan satu forged discrete-log proof
8. mengirim payload melalui menu `P`
9. mengekstrak flag dari respons server

Jalankan dengan Sage:

```bash
conda activate sage
sage -python solve.py HOST PORT
```

Jumlah worker PoW dapat diatur:

```bash
sage -python solve.py HOST PORT --workers 12
```

## Hasil

```text
Congratulations!
r3ctf{to_eNd-UP-wherE-WE_4r3-m34NT_to-638a109}
Hope you enjoy!

<FLAG>r3ctf{to_eNd-UP-wherE-WE_4r3-m34NT_to-638a109}</FLAG>
```

## Akar Masalah

Kegagalan desain ada pada perbedaan domain aritmetika:

- relasi asli membutuhkan quotient polinomial di bilangan bulat
- verifier hanya mengecek persamaan skalar modulo orde secp256k1
- konstanta `3329` menjadi elemen invertibel
- `k` tidak memiliki range proof
- proof of knowledge tetap valid untuk `k` palsu yang sangat besar

Perbaikan minimalnya adalah memberi range proof untuk koefisien `k` dan memastikan relasi yang dibuktikan merepresentasikan operasi ring RLWE secara benar, bukan sekadar kesetaraan modulo orde grup kurva.
