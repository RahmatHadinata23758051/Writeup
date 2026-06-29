# Iihash — SEKAI CTF 2026

## Informasi Challenge

- **Kategori:** Crypto
- **Judul:** Iihash
- **Deskripsi:** `Fast hash is good hash. A secret seed makes it even better, right?`
- **Target:** membuat input lebih dari 256 byte dengan digest XXH3-128 tepat `b"Give me the flag"`

```python
self.seed = random.getrandbits(64)

h = xxhash.xxh3_128(data, seed=self.seed).hexdigest()

if xxhash.xxh3_128(data, seed=self.seed).digest() == b"Give me the flag":
    print(open("flag.txt").read())
```

Flag yang didapat:

```text
SEKAI{Im4g1n3_U5iNg_LLL_!n_d1ff3rEn7IAL_Cryp7aN@lySis}
```

---

## Ringkasan Serangan

Ada dua tahap utama:

1. **Memulihkan seed 64-bit** menggunakan collision terpilih pada accumulator XXH3 long-input.
2. **Membuat preimage 320 byte** setelah seed diketahui. State target dihitung dengan membalik avalanche, nilai accumulator target dicari menggunakan LLL/BKZ, lalu word payload dirakit secara algebraic.

Alur lengkapnya:

```text
chosen-input hash oracle
        ↓
exact accumulator collision
        ↓
recover seed_low dengan x+y dan x XOR y
        ↓
recover seed_high dengan carry/borrow yang sudah diketahui
        ↓
invert avalanche target digest
        ↓
invert fold128 memakai lattice 66 dimensi
        ↓
rakit payload 320 byte
        ↓
xxh3_128(payload, seed) = b"Give me the flag"
```

---

# Bagian I — Struktur XXH3 yang Diserang

## 1. Custom Secret dari Seed

Pada long-input mode, XXH3 tidak memasukkan seed sebagai key ke primitive kriptografis. Seed hanya dipakai untuk memodifikasi default secret per word 64-bit.

Untuk pasangan word ke-`i`:

\[
S_{2i}=C_{2i}+s \pmod{2^{64}}
\]

\[
S_{2i+1}=C_{2i+1}-s \pmod{2^{64}}
\]

`C_i` adalah word dari default secret dan `s` adalah seed 64-bit.

Tuliskan seed sebagai dua half 32-bit:

\[
s=s_H 2^{32}+s_L
\]

Untuk word bertanda tambah, jika:

\[
C=C_H2^{32}+C_L
\]

maka:

\[
L_+ = C_L+s_L \pmod{2^{32}}
\]

\[
H_+ = C_H+s_H+\kappa \pmod{2^{32}}
\]

 dengan carry:

\[
\kappa=[C_L+s_L\ge 2^{32}]
\]

Untuk word bertanda kurang:

\[
L_- = C_L-s_L \pmod{2^{32}}
\]

\[
H_- = C_H-s_H-\beta \pmod{2^{32}}
\]

 dengan borrow:

\[
\beta=[C_L<s_L]
\]

Struktur `+s` dan `-s` ini membuat seed hilang ketika dua word dengan parity berbeda dijumlahkan.

---

## 2. Update Accumulator

Satu stripe berisi delapan word data 64-bit. Untuk lane `l`, definisikan:

\[
d=d_H2^{32}+d_L
\]

\[
k=k_H2^{32}+k_L
\]

\[
q=d\oplus k
\]

XXH3 memperbarui accumulator dengan:

\[
A_{l\oplus1}\leftarrow A_{l\oplus1}+d \pmod{2^{64}}
\]

\[
A_l\leftarrow A_l+
\operatorname{lo}_{32}(q)\cdot
\operatorname{hi}_{32}(q)
\pmod{2^{64}}
\]

atau:

\[
A_l\leftarrow A_l+(d_L\oplus k_L)(d_H\oplus k_H)
\pmod{2^{64}}
\]

Ada dua properti penting:

- accumulator pasangan menerima **penjumlahan linear** word data;
- accumulator lane sendiri menerima **perkalian dua nilai 32-bit**.

Collision gadget dibuat agar penjumlahan data sama dan selisih perkalian tepat nol.

---

# Bagian II — Exact Collision Gadget

## 3. Memulihkan XOR Low-Half Dua Secret Word

Ambil dua secret word yang digunakan pada lane sama tetapi stripe berbeda:

\[
S_i=H_i2^{32}+L_i
\]

\[
S_j=H_j2^{32}+L_j
\]

Kita ingin menguji tebakan:

\[
R=L_i\oplus L_j
\]

Pilih:

\[
\delta=2^b
\]

lalu buat dua pesan yang hanya berbeda pada dua posisi tersebut.

### Pesan A

\[
d_i=0
\]

\[
d_j=\delta 2^{32}+R
\]

### Pesan B

\[
d_i=\delta 2^{32}
\]

\[
d_j=R
\]

Jumlah data pada kedua pesan sama:

\[
d_i^{(A)}+d_j^{(A)}=
\delta2^{32}+R
\]

\[
d_i^{(B)}+d_j^{(B)}=
\delta2^{32}+R
\]

Maka accumulator silang `A[lane XOR 1]` identik.

Sekarang hitung kontribusi perkalian pada accumulator lane.

Definisikan:

\[
X=R\oplus L_j
\]

Kontribusi Pesan A:

\[
P_A=L_iH_i+X(H_j\oplus\delta)
\]

Kontribusi Pesan B:

\[
P_B=L_i(H_i\oplus\delta)+XH_j
\]

Selisihnya:

\[
P_A-P_B=
X[(H_j\oplus\delta)-H_j]
-L_i[(H_i\oplus\delta)-H_i]
\]

Jika bit ke-`b` dari `H_i` dan `H_j` sama, toggle bit tersebut memiliki tanda yang sama. Ada `\sigma\in\{-1,+1\}` sehingga:

\[
(H_j\oplus\delta)-H_j=\sigma\delta
\]

\[
(H_i\oplus\delta)-H_i=\sigma\delta
\]

Jadi:

\[
P_A-P_B=
\sigma\delta(X-L_i)
\]

Collision terjadi tepat ketika:

\[
X=L_i
\]

Karena `X=R XOR L_j`:

\[
R\oplus L_j=L_i
\]

sehingga:

\[
\boxed{R=L_i\oplus L_j}
\]

Jika tebakan `R` benar, seluruh delapan accumulator kedua pesan identik. Finalizer juga menerima state identik, sehingga digest 128-bit pasti sama.

Collision ini bukan birthday collision dan bukan collision probabilistik. Ini collision internal yang dibangun secara algebraic.

---

## 4. Mengapa Ada Bit High yang Pasti Sama

Gadget low-half membutuhkan satu bit `b` dengan:

\[
(H_i)_b=(H_j)_b
\]

Untuk pasangan parity berbeda, jumlah high-half diketahui sampai carry/borrow dari low-half:

\[
H_i+H_j=Q_H\pmod{2^{32}}
\]

Ambil bit nol pertama dari `Q_H`, dihitung dari LSB.

Semua bit lebih rendah adalah `1`. Mulai dari carry awal nol, bit hasil `1` memaksa operand berbeda dan carry tetap nol. Ketika mencapai bit nol pertama, carry masuk masih nol. Agar bit hasil nol, kedua operand harus sama:

\[
0+0+0=0
\]

atau:

\[
1+1+0=2
\]

Keduanya memiliki bit operand yang sama. Karena itu bit nol pertama dari jumlah dapat dipakai sebagai toggle `b`.

Saat low-half belum diketahui, ada beberapa kemungkinan carry akhir. Solver menghitung semua carry yang konsisten dengan sistem `x+y=Q` dan `x XOR y=R`, lalu mencoba bit aman yang dihasilkan.

---

## 5. Gadget untuk XOR High-Half

Setelah kandidat low-half tersedia, kita dapat mencari bit low yang sama dan menukar peran high/low.

Kita ingin menguji:

\[
R=H_i\oplus H_j
\]

Pilih `delta=2^b` pada low-half.

### Pesan A

\[
d_i=0
\]

\[
d_j=R2^{32}+\delta
\]

### Pesan B

\[
d_i=\delta
\]

\[
d_j=R2^{32}
\]

Jumlah data tetap sama. Jika bit ke-`b` dari `L_i` dan `L_j` sama, selisih perkalian menjadi:

\[
P_A-P_B=
\sigma\delta[(R\oplus H_j)-H_i]
\]

Collision terjadi tepat saat:

\[
\boxed{R=H_i\oplus H_j}
\]

Pada tahap ini solver sudah memiliki sekumpulan kandidat `s_L`. Ia memilih bit `b` yang memenuhi:

\[
(L_i\oplus L_j)_b=0
\]

untuk semua kandidat yang masih hidup.

---

# Bagian III — Mengubah Collision Menjadi Seed Recovery

## 6. Persamaan Low-Half

Pilih satu secret word parity genap dan satu parity ganjil:

\[
x=C_{+,L}+s_L\pmod{2^{32}}
\]

\[
y=C_{-,L}-s_L\pmod{2^{32}}
\]

Jumlahnya tidak mengandung seed:

\[
x+y=C_{+,L}+C_{-,L}\pmod{2^{32}}
\]

Definisikan:

\[
Q=(C_{+,L}+C_{-,L})\bmod 2^{32}
\]

Collision oracle memberikan:

\[
R=x\oplus y
\]

Jadi kita memperoleh sistem:

\[
\boxed{x+y=Q\pmod{2^{32}}}
\]

\[
\boxed{x\oplus y=R}
\]

Setelah menemukan `x`, low-half seed langsung:

\[
\boxed{s_L=x-C_{+,L}\pmod{2^{32}}}
\]

### Contoh dari sesi solve

Pasangan awal `(2,7)` memiliki:

\[
C_{2,L}=\texttt{0xe96dd4de}
\]

\[
C_{7,L}=\texttt{0xe69035e0}
\]

Maka:

\[
Q=\texttt{0xe96dd4de}+
\texttt{0xe69035e0}
\pmod{2^{32}}
\]

\[
Q=\texttt{0xcffe0abe}
\]

Oracle menemukan:

\[
R=\texttt{0x2ff9caa0}
\]

Untuk seed sesi:

\[
s_L=\texttt{0x702d0db1}
\]

word aktualnya:

\[
x=\texttt{0x599ae28f}
\]

\[
y=\texttt{0x7663282f}
\]

Verifikasi:

\[
x+y=\texttt{0xcffe0abe}=Q
\]

\[
x\oplus y=\texttt{0x2ff9caa0}=R
\]

---

## 7. Menyelesaikan `x+y=Q` dan `x XOR y=R`

Persamaan diselesaikan bit per bit dengan dynamic programming carry.

Untuk bit ke-`k`, tulis:

\[
x_k,y_k,q_k,r_k\in\{0,1\}
\]

Dari XOR:

\[
y_k=x_k\oplus r_k
\]

Jika carry masuk adalah `c_k`, maka:

\[
x_k+y_k+c_k=q_k+2c_{k+1}
\]

Untuk setiap `c_k`, solver mencoba `x_k=0` dan `x_k=1`, menghitung `y_k`, lalu hanya menyimpan transisi yang menghasilkan bit `q_k` benar.

Pseudo-formula transisinya:

\[
t=x_k+(x_k\oplus r_k)+c_k
\]

valid jika:

\[
t\bmod 2=q_k
\]

lalu:

\[
c_{k+1}=\lfloor t/2\rfloor
\]

Setelah 32 bit, seluruh kemungkinan `x` diperoleh. Banyaknya solusi untuk suatu `R` juga dihitung dengan DP yang sama.

Nilai `R` tidak memiliki peluang yang seragam. Solver mengurutkan tebakan berdasarkan:

\[
N(Q,R)=\#\{x:x+(x\oplus R)=Q\}
\]

Semakin besar `N(Q,R)`, semakin besar peluang relasi tersebut menjadi relasi seed acak. Ini menurunkan expected query count.

Pada sesi final:

```text
[+] low relation (2, 7): 0x2ff9caa0
[+] candidates=262144
```

Artinya sistem sum/XOR tersebut memiliki 262.144 kandidat `x`, yang dipetakan menjadi 262.144 kandidat `s_L`.

---

## 8. Filter Kandidat Low-Half

Setelah relasi pertama, kita tidak lagi perlu menghitung distribusi dari seluruh `2^32` seed.

Untuk setiap kandidat `s_L`, hitung relasi prediksi pada pasangan baru:

\[
R_{i,j}(s_L)=L_i(s_L)\oplus L_j(s_L)
\]

Relasi ini membagi kandidat ke beberapa bucket. Collision oracle menentukan bucket yang benar.

Output sesi final:

```text
[+] low filter (0, 1): remain=2560
[+] low filter (6, 9): remain=64
[+] low filter (8, 11): remain=8
[+] low filter (1, 4): remain=4
[+] low filter (8, 9): remain=2
```

Setiap filter bukan brute force ulang terhadap `2^32`; filter hanya menguji nilai relasi unik dari kandidat yang masih hidup.

---

## 9. Persamaan High-Half

Setelah `s_L` diketahui atau tinggal sedikit kandidat, carry dan borrow dapat dihitung:

\[
\kappa=[C_{+,L}+s_L\ge2^{32}]
\]

\[
\beta=[C_{-,L}<s_L]
\]

High-half dua word adalah:

\[
X=C_{+,H}+s_H+\kappa\pmod{2^{32}}
\]

\[
Y=C_{-,H}-s_H-\beta\pmod{2^{32}}
\]

Seed high kembali hilang dari jumlah:

\[
X+Y=
C_{+,H}+C_{-,H}+\kappa-\beta
\pmod{2^{32}}
\]

Definisikan:

\[
Q_H=C_{+,H}+C_{-,H}+\kappa-\beta
\pmod{2^{32}}
\]

High collision gadget memberikan:

\[
R_H=X\oplus Y
\]

Kita menyelesaikan sistem yang sama:

\[
X+Y=Q_H\pmod{2^{32}}
\]

\[
X\oplus Y=R_H
\]

Setelah `X` ditemukan:

\[
\boxed{s_H=X-C_{+,H}-\kappa\pmod{2^{32}}}
\]

Contoh relasi remote:

```text
[+] high relation (0, 5): 0x9fbd5bcf
[+] high relation (7, 14): 0x7d7fee4e
[+] high relation (9, 12): 0x9a590ffe
```

Untuk seed final:

\[
s_H=\texttt{0xeed153b3}
\]

Setelah intersection dan filter, kandidat terakhir diverifikasi memakai hash satu payload nol 320 byte.

Seed lengkap:

\[
\boxed{s=\texttt{0xeed153b3702d0db1}}
\]

Seed berubah pada setiap koneksi, jadi nilai ini hanya berlaku pada sesi tersebut.

---

# Bagian IV — Membalik Target Digest

## 10. Inverse Avalanche

Final avalanche XXH3 yang dipakai adalah:

\[
f(x)=x\oplus(x\gg37)
\]

\[
f(x)=f(x)\cdot m\pmod{2^{64}}
\]

\[
f(x)=f(x)\oplus(f(x)\gg32)
\]

 dengan:

\[
m=\texttt{0x165667919E3779F9}
\]

`m` ganjil, sehingga memiliki inverse modulo `2^64`:

\[
m^{-1}\equiv m^{ -1}\pmod{2^{64}}
\]

Untuk xor-shift `y=x XOR (x >> r)` dengan `r>=32`, inversenya cukup satu langkah:

\[
x=y\oplus(y\gg r)
\]

Karena shift kedua akan melewati 64 bit.

Maka inverse avalanche:

1. batalkan `xor >> 32`;
2. kalikan dengan `m^{-1} mod 2^64`;
3. batalkan `xor >> 37`.

Digest target adalah:

```text
47 69 76 65 20 6d 65 20 74 68 65 20 66 6c 61 67
 G  i  v  e     m  e     t  h  e     f  l  a  g
```

Setelah memperhatikan urutan output high/low XXH3, state sebelum avalanche adalah:

\[
\boxed{T_L=\texttt{0x26d73906e5b3b9f7}}
\]

\[
\boxed{T_H=\texttt{0x00b0c1155830d0a5}}
\]

---

## 11. Merge Accumulator untuk Payload 320 Byte

Panjang 320 dipilih karena:

- tetap masuk long-input mode;
- terdiri dari empat regular stripe dan satu final stripe;
- belum mencapai satu block penuh, sehingga tidak ada tahap scramble accumulator;
- dua stripe pertama cukup untuk mengontrol semua delapan accumulator.

Definisikan:

\[
F(a,b)=\operatorname{lo}_{64}(ab)\oplus
\operatorname{hi}_{64}(ab)
\]

Untuk empat pasangan accumulator:

\[
M_L=320P_1+
\sum_{i=0}^{3}
F(A_{2i}\oplus K^{L}_{i,0},
  A_{2i+1}\oplus K^{L}_{i,1})
\pmod{2^{64}}
\]

\[
M_H=\neg(320P_2)+
\sum_{i=0}^{3}
F(A_{2i}\oplus K^{H}_{i,0},
  A_{2i+1}\oplus K^{H}_{i,1})
\pmod{2^{64}}
\]

Kita membutuhkan:

\[
M_L=T_L
\]

\[
M_H=T_H
\]

Sehingga residual target:

\[
N_L=T_L-320P_1\pmod{2^{64}}
\]

\[
N_H=T_H-\neg(320P_2)\pmod{2^{64}}
\]

---

## 12. Memisahkan Persamaan Low dan High

Untuk pasangan accumulator `i=0,1`, pilih:

\[
A_{2i}=K^{H}_{i,0}
\]

Maka operand pertama pada merge high menjadi nol:

\[
A_{2i}\oplus K^{H}_{i,0}=0
\]

Karena `F(0,x)=0`, pasangan tersebut tidak berkontribusi ke high merge.

Pilih accumulator ganjil:

\[
A_{2i+1}=K^{L}_{i,1}\oplus y_i
\]

Kontribusi low-nya menjadi:

\[
F(K^{H}_{i,0}\oplus K^{L}_{i,0},y_i)
\]

Definisikan:

\[
c_i=K^{H}_{i,0}\oplus K^{L}_{i,0}
\]

Maka dua pasangan pertama harus memenuhi:

\[
\boxed{F(c_0,y_0)+F(c_1,y_1)=N_L\pmod{2^{64}}}
\]

Untuk pasangan `i=2,3`, lakukan kebalikannya:

\[
A_{2i}=K^{L}_{i,0}
\]

sehingga kontribusi low nol, dan:

\[
A_{2i+1}=K^{H}_{i,1}\oplus y_i
\]

memberikan:

\[
\boxed{F(c_2,y_2)+F(c_3,y_3)=N_H\pmod{2^{64}}}
\]

Masalah preimage 128-bit telah dipecah menjadi dua persamaan 64-bit yang independen.

---

# Bagian V — Inverting `fold128` dengan Lattice

## 13. Persamaan Dasar

Kita ingin menyelesaikan:

\[
F(c,y)=t
\]

Definisikan produk 128-bit:

\[
p=cy=p_L+2^{64}p_H
\]

Syarat fold:

\[
p_L\oplus p_H=t
\]

Maka:

\[
p_L=t\oplus p_H
\]

sehingga:

\[
cy=(t\oplus p_H)+2^{64}p_H
\]

Tuliskan bit `p_H` sebagai:

\[
p_H=\sum_{j=0}^{63}h_j2^j,
\qquad h_j\in\{0,1\}
\]

Untuk bit target `t_j`:

\[
t\oplus p_H
=t+
\sum_{j=0}^{63}
h_j2^j(1-2t_j)
\]

Gabungkan dengan `2^64 p_H`:

\[
cy=t+
\sum_{j=0}^{63}
h_j2^j(2^{64}+1-2t_j)
\]

Definisikan:

\[
a_j=2^j(2^{64}+1-2t_j)
\]

Kita mencari bit `h_j` sehingga:

\[
\boxed{t+\sum_{j=0}^{63}h_ja_j\equiv0\pmod c}
\]

Jika kongruensi terpenuhi:

\[
y=\frac{t+\sum h_ja_j}{c}
\]

lalu diverifikasi bahwa:

\[
0\le y<2^{64}
\]

 dan:

\[
F(c,y)=t
\]

Ini adalah modular subset-sum 64 variabel biner.

---

## 14. Embedding Lattice 66 Dimensi

Gunakan embedding berikut secara konseptual.

Untuk `j=0..63`, buat basis row:

\[
b_j=(2e_j,\;0,\;Ma_j)
\]

Tambahkan target row:

\[
b_T=(-1,-1,\ldots,-1,\;T,\;Mt)
\]

serta modulus row:

\[
b_c=(0,\ldots,0,\;0,\;Mc)
\]

Untuk pilihan bit `h_j` dan suatu integer `k`, kombinasi:

\[
v=b_T+
\sum_{j=0}^{63}h_jb_j+kb_c
\]

memiliki 64 koordinat awal:

\[
2h_j-1\in\{-1,+1\}
\]

Koordinat terakhir:

\[
M\left(t+
\sum h_ja_j+kc\right)
\]

Jika kongruensi terpenuhi, pilih `k` sehingga koordinat terakhir nol. Vektor solusi kemudian berbentuk:

\[
(\pm1,\pm1,\ldots,\pm1,T,0)
\]

Vektor seperti ini sangat pendek dibanding kombinasi acak. LLL lalu BKZ dipakai untuk menemukannya.

Implementasi menambahkan beberapa stabilisasi:

- permutasi random pada 64 bit;
- kelipatan acak dari `c` pada kolom embedding;
- variasi scale `M`;
- variasi marker `T`;
- block size BKZ bertahap.

Setelah vektor ditemukan, tanda `±1` dikonversi kembali menjadi bit `h_j`, lalu `y` direkonstruksi dan diverifikasi secara eksak.

---

## 15. Mengapa Memakai Dua `fold128`

Tidak semua target `t` mudah ditemukan sebagai image langsung dari `F(c,y)` untuk satu `c` tertentu.

Solver memilih `y_0` acak dan menghitung:

\[
t'=N_L-F(c_0,y_0)\pmod{2^{64}}
\]

Kemudian lattice hanya perlu menyelesaikan:

\[
F(c_1,y_1)=t'
\]

Jika gagal, pilih `y_0` baru. Cara sama dipakai untuk high target.

Hasil akhirnya:

\[
F(c_0,y_0)+F(c_1,y_1)=N_L
\]

\[
F(c_2,y_2)+F(c_3,y_3)=N_H
\]

---

# Bagian VI — Merakit Payload 320 Byte

## 16. Menonaktifkan Kontribusi Perkalian

Setelah delapan accumulator target `A_i` diketahui, payload dibuat menggunakan dua stripe pertama.

Untuk satu source lane, secret word pada stripe pertama adalah:

\[
k_0=k_{0,H}2^{32}+k_{0,L}
\]

secret word stripe kedua:

\[
k_1=k_{1,H}2^{32}+k_{1,L}
\]

Pilih word data:

\[
d_0=a2^{32}+k_{0,L}
\]

\[
d_1=k_{1,H}2^{32}+b
\]

Pada stripe pertama:

\[
\operatorname{lo}_{32}(d_0\oplus k_0)=0
\]

maka produk 32×32 adalah nol.

Pada stripe kedua:

\[
\operatorname{hi}_{32}(d_1\oplus k_1)=0
\]

maka produknya juga nol.

Jadi dua word ini hanya mengubah accumulator silang melalui:

\[
d_0+d_1\pmod{2^{64}}
\]

---

## 17. Menyelesaikan Word Data Secara Eksak

Misalkan correction yang dibutuhkan untuk accumulator silang adalah:

\[
S=S_H2^{32}+S_L
\]

Kita butuh:

\[
d_0+d_1=S\pmod{2^{64}}
\]

Dengan bentuk pilihan di atas:

\[
d_0+d_1=
(a+k_{1,H}+c)2^{32}
+(k_{0,L}+b\bmod2^{32})
\]

Pilih low-half:

\[
\boxed{b=S_L-k_{0,L}\pmod{2^{32}}}
\]

Carry dari penjumlahan low-half:

\[
c=\left\lfloor
\frac{k_{0,L}+b}{2^{32}}
\right\rfloor
\]

Lalu high-half:

\[
\boxed{a=S_H-k_{1,H}-c\pmod{2^{32}}}
\]

Ini langsung menghasilkan dua word yang:

- memberikan penambahan tepat `S` ke accumulator pasangan;
- memberikan kontribusi perkalian nol ke accumulator lane sendiri.

Stripe 2, stripe 3, dan final stripe diisi nol. Kontribusi tetap dari zero word sudah dihitung terlebih dahulu dalam `fixed accumulator`.

Setelah semua lane dirakit:

```python
assert model_accumulators(payload, seed) == desired_accumulators
assert xxhash.xxh3_128(payload, seed=seed).digest() == b"Give me the flag"
```

---

# Hasil Eksekusi

```text
[+] low relation (2, 7): 0x2ff9caa0; candidates=262144; queries=7990
[+] low filter (0, 1): remain=2560; queries=8246
[+] low filter (6, 9): remain=64; queries=8374
[+] low filter (8, 11): remain=8; queries=8398
[+] low filter (1, 4): remain=4; queries=8406
[+] low filter (8, 9): remain=2; queries=8414

[+] high relation (0, 5): 0x9fbd5bcf; queries=8542
[+] high relation (7, 14): 0x7d7fee4e; queries=8670
[+] high relation (9, 12): 0x9a590ffe; queries=12382
[+] intersected seed candidates: 1280

[+] high filter (5, 9): remain=80; queries=12400
[+] high filter (4, 5): remain=8; queries=12412

[+] Recovered seed: 0xeed153b3702d0db1
[+] Preimage ready: 320 bytes
[+] Local digest: b'Give me the flag'

<FLAG>SEKAI{Im4g1n3_U5iNg_LLL_!n_d1ff3rEn7IAL_Cryp7aN@lySis}</FLAG>
```

---

# Kesimpulan

Seeded XXH3 bukan MAC kriptografis. Pada long-input mode, seed hanya menggeser word default secret dengan `+seed` dan `-seed`. Update accumulator mempertahankan struktur bilinear 32-bit yang dapat dimanipulasi dengan chosen input.

Inti matematis serangannya:

1. Buat dua payload dengan jumlah data sama.
2. Paksa selisih produk menjadi:

   \[
   \pm2^b[(R\oplus S_1)-S_0]
   \]

3. Collision memberi XOR dua half secret.
4. Gunakan pembatalan `+seed` dan `-seed` untuk mendapatkan:

   \[
   x+y=Q,
   \qquad x\oplus y=R
   \]

5. Selesaikan sistem tersebut bit per bit untuk memperoleh seed.
6. Balik avalanche target.
7. Ubah inverse `fold128` menjadi modular subset-sum.
8. Gunakan LLL/BKZ pada lattice 66 dimensi.
9. Rakit payload agar kontribusi perkalian stripe kontrol bernilai nol.

Flag:

```text
SEKAI{Im4g1n3_U5iNg_LLL_!n_d1ff3rEn7IAL_Cryp7aN@lySis}
```
