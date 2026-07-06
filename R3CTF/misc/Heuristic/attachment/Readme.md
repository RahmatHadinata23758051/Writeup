# HEuristic — Crypto

**CTF:** R3CTF 2026  
**Category:** Crypto  
**Flag:** `r3ctf{H3uRI5TIc_dELT4-i5_HlDDeN-1n_FuILY-h0m0MoRphIC_encryption_schemes0}`

## Ringkasan

Service memakai Microsoft SEAL dengan parameter CKKS, tetapi plaintext tidak melalui encoder CKKS. Setiap koefisien pilihan user dikalikan dengan secret scalar `delta` di modulo ciphertext `q`, lalu dimasukkan langsung ke bentuk RNS/NTT sebelum dienkripsi.

Menu decrypt mengembalikan 96 koefisien pertama setelah ditambah noise acak sekitar 188 bit:

```text
y_i = m_i · delta + e_i mod q
```

Satu sampel memang tidak cukup karena `e_i` besar. Celahnya muncul karena seluruh `m_i` dapat dipilih sendiri. Koefisien disusun sebagai rantai:

```text
m_i = 2^g_i · m_(i-1) mod q
```

Output noisy kemudian diangkat dari modulo `q` agar setiap sampel sedekat mungkin dengan hasil doubling sampel sebelumnya. Error antarlangkah saling menghapus. Setelah 95 langkah, nilai akhir berbentuk:

```text
U_95 = 2^S · Z + e_95
```

`S` minimal sekitar 285 bit, sedangkan noise hanya sekitar 188 bit. Pembagian dengan `2^S` dan pembulatan terdekat mengembalikan `Z = m_0·delta mod q` secara exact. Karena `m_0` invertible modulo `q`, `delta` langsung didapat.

## Membaca source

Parameter yang dipakai server:

```cpp
parms.set_poly_modulus_degree(4096);
parms.set_coeff_modulus(CoeffModulus::Create(4096, {48, 48, 48, 48, 48}));
```

Modulus total adalah hasil kali lima prime 48-bit:

```text
q = q_0 q_1 q_2 q_3 q_4
```

Nilainya dicetak langsung saat koneksi dibuka. Secret `delta` dipilih uniform pada rentang `[1, q-1]`.

Bagian enkripsi melakukan ini untuk setiap koefisien input `m_i`:

```cpp
plain[i] = m_i * delta mod q
```

Nilai tersebut dikonversi ke RNS, ditransformasikan ke NTT, lalu dienkripsi dengan public key SEAL.

Server juga menolak plaintext yang terlalu dekat dengan nol modulo `q`:

```cpp
abs_coeff = min(m_i mod q, q - (m_i mod q));
if (abs_coeff < q / 8)
    throw invalid_argument("bad plaintext");
```

Jadi koefisien kecil seperti `1` tidak dapat dipakai langsung.

## Oracle decrypt

Ciphertext dari menu encrypt dapat dikirim kembali ke menu decrypt. Setelah dekripsi dan inverse NTT, server membocorkan 96 koefisien pertama dengan noise tambahan:

```cpp
noise_bound = 5 << 185;
value = coeffs[i] ± noise mod q;
```

Untuk koefisien pilihan `m_i`, observasi yang terlihat adalah:

```text
y_i ≡ m_i·delta + e_i (mod q)
|e_i| < B
B = 5·2^185 < 2^188.4
```

Koefisien ke-96 dan seterusnya diganti `*`, tetapi 96 sampel sudah lebih dari cukup.

## Chosen plaintext

Ambil nilai awal:

```text
m_0 = floor(q/3)
```

Nilai ini jauh dari nol modulo `q`, sehingga lolos pemeriksaan `q/8`. Solver juga memastikan `gcd(m_0, q)=1` agar inverse modular tersedia.

Untuk setiap indeks berikutnya, cari exponent kecil `g_i` pada rentang 3 sampai 32:

```text
m_i = 2^g_i · m_(i-1) mod q
```

Kandidat hanya dipakai jika tetap memenuhi:

```text
min(m_i, q-m_i) ≥ q/8
```

Sebanyak 96 multiplier ditempatkan pada 96 koefisien pertama. Sisa koefisien sampai panjang 4096 diisi `m_0`, karena semuanya tetap harus lolos validasi server.

Minimal setiap gap bernilai 3, sehingga total shift memenuhi:

```text
S = g_1 + g_2 + ... + g_95 ≥ 285
```

## Mengangkat observasi dari modulo q

Definisikan faktor lokal:

```text
r_i = 2^g_i
```

Karena `m_i ≡ r_i m_(i-1) mod q`, maka bagian tanpa noise memenuhi relasi doubling yang sama. Observasi `y_i` masih berada pada representasi modulo `q`, jadi kita pilih integer `k_i` agar:

```text
U_i = y_i + k_i q
```

sedekat mungkin dengan:

```text
r_i U_(i-1)
```

Nilai `k_i` dihitung dengan pembulatan:

```text
k_i = round((r_i U_(i-1) - y_i) / q)
```

atau dalam kode:

```python
quotient = nearest_div(factor * lifted - y, q)
lifted = y + quotient * q
```

Pemilihan lift ini unik. Selisih akibat noise dibatasi oleh:

```text
|e_i - r_i e_(i-1)| ≤ (r_i + 1)B
```

Bahkan untuk `g_i = 32`, nilainya masih jauh di bawah `q/2`, karena `q` sekitar 240 bit sedangkan noise sekitar 188 bit.

## Kenapa noise menghilang

Misalkan `Z` adalah lift integer dari:

```text
Z ≡ m_0·delta (mod q)
```

Pada langkah awal:

```text
U_0 = Z + e_0
```

Lift berikutnya dipilih sehingga:

```text
U_1 = r_1 Z + e_1
```

Bukan `r_1 Z + r_1 e_0 + e_1`. Kontribusi `r_1 e_0` dibatalkan saat memilih kelipatan `q` yang membuat hasil paling dekat dengan `r_1 U_0`.

Induksi memberi:

```text
U_i = 2^(g_1+...+g_i) Z + e_i
```

Pada sampel terakhir:

```text
U_95 = 2^S Z + e_95
```

Jadi hanya noise terakhir yang tersisa. Seluruh noise sebelumnya men-telescope.

Karena:

```text
S ≥ 285
|e_95| < 2^189
```

maka:

```text
|e_95 / 2^S| < 2^-96
```

Pembulatan menghasilkan `Z` secara exact:

```python
recovered_product = round(U_95 / 2**S) % q
```

Lalu secret scalar diperoleh dengan inverse modular:

```text
delta = Z · m_0^(-1) mod q
```

## Validasi kandidat

Sebelum submit, solver menghitung residual centered untuk semua 96 sampel:

```text
r_i = centered(y_i - m_i·delta mod q)
```

Recovery benar menghasilkan residual sekitar batas noise server. Recovery salah menghasilkan angka acak modulo `q`, umumnya berukuran mendekati `q/4`.

Solver menolak kandidat jika residual maksimum mencapai `2^205`, memberi margin cukup besar di atas noise yang diharapkan tetapi masih jauh di bawah ukuran `q`.

## Urutan interaksi

Service hanya memberikan tiga ronde menu. Semuanya dipakai tepat satu kali:

1. **encrypt** — kirim 4096 chosen coefficients;
2. **decrypt** — kirim kembali ciphertext yang baru diterima;
3. **submit** — kirim `delta` hasil recovery.

Ciphertext adalah data biner mentah, jadi parser harus membaca panjang yang diumumkan server, bukan memakai pembacaan berbasis newline.

## Menjalankan solver

Tidak ada dependency Python tambahan:

```bash
python3 solve.py HOST PORT
```

Contoh format output:

```text
[*] connecting to HOST:PORT (attempt 1/3)
[+] q bits = 240
[+] chosen chain: 96 coefficients, total shift = ...
[+] ciphertext length = ...
[+] recovered delta = ...
[+] max residual bits = ...
r3ctf{H3uRI5TIc_dELT4-i5_HlDDeN-1n_FuILY-h0m0MoRphIC_encryption_schemes0}
<FLAG>r3ctf{H3uRI5TIc_dELT4-i5_HlDDeN-1n_FuILY-h0m0MoRphIC_encryption_schemes0}</FLAG>
```

## Flag

```text
r3ctf{H3uRI5TIc_dELT4-i5_HlDDeN-1n_FuILY-h0m0MoRphIC_encryption_schemes0}
```
