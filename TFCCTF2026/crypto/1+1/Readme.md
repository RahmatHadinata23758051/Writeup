# Writeup: 1+1 (Tantangan Kriptografi CTF)

## 1. Analisis Permasalahan (Problem Analysis)

Diberikan sebuah skrip tantangan dalam bahasa SageMath (`chall.sage`) yang menghasilkan sepuluh nilai integer `xs`. Berdasarkan kode sumber:

$$x_i = p \cdot q_i + r_i \quad \text{untuk} \ i = 0, 1, \dots, 9$$

Dengan parameter yang diketahui:

- **$p$**: Integer rahasia yang merepresentasikan nilai byte dari flag (`bytes_to_long(open('flag','rb').read())`).
- **$q_i$**: Bilangan prima acak berukuran 512-bit (`getPrime(pbit)` dengan `pbit = 512`).
- **$r_i$**: Nilai sisa atau noise acak berukuran 444-bit ($1 \le r_i < 2^{444}$).

Ukuran nilai $x_i$ berada pada kisaran 1024-bit (hasil perkalian 512-bit prima dan 512-bit $p$). Karena batas atas noise $r_i$ (444-bit) jauh lebih kecil daripada ukuran modulus utama, permasalahan ini dapat direduksi secara matematis menjadi **Approximate Common Divisor (ACD) Problem**.

## 2. Landasan Teori (Theoretical Foundation)

Masalah ACD bertujuan mencari pembagi persekutuan dari sekumpulan bilangan yang tercemar oleh galat (noise). Persamaan di atas dapat disusun ulang menjadi:

$$x_i - r_i = p \cdot q_i$$

Artinya, rasio antara dua elemen apa pun dalam himpunan `xs` mendekati rasio dari faktor pengalinya:

$$\frac{x_i}{x_0} \approx \frac{q_i}{q_0}$$

Pendekatan rasional ini menunjukkan bahwa $q_i$ dan $q_0$ membentuk suatu hubungan linier berbobot kecil. Dalam kriptografi, struktur linier seperti ini diselesaikan menggunakan **Lattice Reduction** melalui algoritma **LLL** (Lenstra–Lenstra–Lovász) atau **BKZ** (Block Korkin-Zolotarev).

Dengan menyusun matriks kisi yang merepresentasikan selisih kelipatan elemen-elemen $x_i$ terhadap batas noise $W = 2^{444}$, vektor terpendek di dalam kisi tersebut akan mengeliminasi faktor prima acak $q_i$ dan menyisakan hubungan proporsional yang mengarah pada nilai $p$.

## 3. Tahapan Penyelesaian (Step-by-Step Solution)

1. **Konstruksi Matriks Kisi (Lattice Matrix):**
   Dibentuk sebuah matriks berukuran $N \times N$ (dengan $N$ adalah jumlah elemen `xs`). Baris pertama matriks diisi oleh batas noise $W = 2^{444}$ pada diagonal utama dan elemen $x_i$ pada kolom berikutnya. Baris-baris selanjutnya diisi oleh $-x_0$ pada posisi diagonal yang bersesuaian untuk mengeliminasi komponen pengali.

2. **Reduksi Kisi (BKZ Reduction):**
   Algoritma reduksi BKZ diterapkan pada matriks tersebut untuk menemukan basis vektor terpendek (Shortest Vector Problem / SVP).

3. **Ekstraksi dan Validasi Kandidat:**
   Dari vektor hasil reduksi, nilai estimasi pengali $q_0$ diekstraksi. Nilai $p$ kandidat dihitung melalui pembagian bilangan bulat:

   $$p_{\text{cand}} = \left\lfloor \frac{x_0}{q_0} \right\rfloor$$

   Kandidat tersebut divalidasi dengan memastikan bahwa sisa pembagian ($x_i \pmod{p_{\text{cand}}}$) untuk setiap elemen benar-benar berada di bawah batas maksimum noise ($2^{445}$).

## 4. Skrip Otomatis Penyelesaian (SageMath Script)

```python
from Crypto.Util.number import long_to_bytes
import output

xs = output.xs
N = len(xs)
rbit = 444
W = 2**rbit

# Konstruksi matriks kisi untuk Approximate Common Divisor
M = Matrix(ZZ, N, N)
M[0, 0] = W
for i in range(1, N):
    M[0, i] = xs[i]
    M[i, i] = -xs[0]

# Melakukan reduksi kisi menggunakan BKZ
L = M.BKZ(block_size=10)

p_found = None
for row in L:
    q0 = abs(row[0]) // W
    if q0 > 0:
        p_cand = xs[0] // q0
        valid = True
        for x in xs:
            if x % p_cand >= 2**445:
                valid = False
                break
        if valid:
            p_found = p_cand
            break

if p_found:
    flag = long_to_bytes(int(p_found))
    print(flag.decode())
```

## 5. Hasil Akhir (Flag)

Setelah menjalankan skrip otomatis di atas, nilai integer $p$ berhasil diekstraksi secara akurat dan dikonversi kembali menjadi representasi biner teks terang (plaintext):

```
TFCCTF{nice_crypto_skillz_kid_you_will_be_great_one_day_af56c3}
```
