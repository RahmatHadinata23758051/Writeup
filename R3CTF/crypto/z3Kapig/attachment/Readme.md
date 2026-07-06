# z3kapig — R3CTF 2026 Crypto Writeup

**Category:** Crypto  
**Difficulty:** Hard  
**Flag:** `r3ctf{P30PIE_sHou1d_m0ve_to_BETteR-ONE_ThAN-CGGMPZl....c0}`

## Challenge

> Not sure this challenge is focus on ZKP or not, but i think the challenge name is cool!

Service menjalankan protokol two-party ECDSA yang terdiri dari:

1. Distributed key generation
2. Auxiliary Paillier setup
3. Presigning
4. Signing
5. Tebak private share milik Party 1

Flag hanya diberikan jika private scalar `xi` milik server berhasil ditebak setelah minimal satu signing round valid.

Targetnya bukan memecahkan ECDLP dari `Xi = xi·G`. Implementasi proof membolehkan kita memasukkan modulus Paillier multiprime, lalu mengubah proses MtA menjadi oracle yang membocorkan `xi mod p` untuk prime kecil pilihan kita.

Attack chain:

```text
malicious Paillier modulus
→ forge ProofMod + valid ProofFac
→ inject plaintext q + N/p
→ grind Fiat–Shamir challenge e ≡ 0 mod p
→ leak xi mod p
→ ulangi untuk 15 prime
→ CRT
→ recover xi
```

---

## 1. Protokol dan Kondisi Menang

Endpoint `guess_key` membandingkan tebakan dengan private share Party 1:

```python
secret_key = self.party.get_secret_key_xi()

if guessed_key == secret_key:
    flag = open("flag.txt").read().strip()
```

Service juga memaksa kita menyelesaikan setidaknya satu signature:

```python
if not self.signing_completed:
    return {
        "correct": False,
        "message": "You must complete at least one successful signing round before guessing.",
    }
```

Jadi solver harus:

- mengikuti keygen;
- menyelesaikan auxiliary setup;
- menjalankan presigning dan signing valid;
- memulihkan scalar `xi`;
- mengirim `guess_key`.

---

## 2. Keygen dengan Share Nol

Pada keygen, client memilih public share:

```python
X = Point.infinity()
```

Ini setara dengan private share client sebesar nol. Proof Schnorr tetap dapat dibuat karena infinity adalah `0·G`.

Public key gabungan menjadi:

```text
X = Xi + 0·G = Xi
```

Artinya public point yang diterima dari server adalah langsung:

```text
Xi = xi·G
```

Kita tetap tidak bisa mengambil `xi` lewat ECDLP, tetapi point ini nanti dipakai untuk memvalidasi hasil CRT.

---

## 3. Bug pada Auxiliary Paillier Setup

Party harus mengirim modulus Paillier 2048-bit dan beberapa proof:

- `ProofPrm`
- `ProofMod`
- `ProofFac`

Modulus normal seharusnya berbentuk semiprime:

```text
N = P·Q
```

Solver membuat modulus multiprime:

```text
N = p1·p2·...·p15·Pmedium·R
```

Dengan:

- `p1 ... p15` prime kecil sekitar 18 bit;
- hasil kali 15 prime kecil memiliki ukuran 271 bit;
- `Pmedium` prime 753 bit;
- `R` prime besar agar total panjang `N` tepat 2048 bit.

Definisikan:

```text
Wbase = p1·p2·...·p15·Pmedium
N     = Wbase·R
```

Product seluruh prime kecil lebih besar dari order secp256k1:

```text
p1·p2·...·p15 > q
```

Ini memastikan hasil CRT nanti unik untuk scalar `0 < xi < q`.

### 3.1 ProofFac Tidak Memastikan Kedua Faktor Prime

`ProofFac` membuktikan relasi perkalian, tetapi verifier tidak melakukan primality test pada witness faktor.

Kita cukup memakai:

```text
N0p = Wbase
N0q = R
```

Walaupun `Wbase` komposit, proof tetap valid karena:

```text
N = Wbase·R
```

### 3.2 ProofMod Tidak Memastikan W Invertibel

Verifier `ProofMod` melakukan pengecekan:

```python
if is_quadratic_residue(W, N) == 1:
    return False
```

Tetapi tidak ada:

```python
gcd(W, N) == 1
```

Kita memilih:

```text
W = Wbase·c
```

Akibatnya:

```text
W ≡ 0 mod Wbase
```

Untuk setiap challenge `Y_i`, verifier meminta:

```text
X_i^4 = (-1)^a · W^b · Y_i mod N
Z_i^N = Y_i mod N
```

Construction proof:

- set `X_i ≡ 0 mod Wbase`;
- pilih tanda `a` agar `±W·Y_i` menjadi quadratic residue modulo `R`;
- hitung fourth root modulo `R`;
- gabungkan dengan CRT;
- hitung `Z_i` karena seluruh faktorisasi `N` diketahui.

Dengan construction ini, modulus multiprime diterima sebagai modulus Paillier valid.

---

## 4. Ciphertext Beracun

Misalkan satu prime leakage yang sedang dipakai adalah `p`, lalu:

```text
M = N / p
```

Ciphertext Paillier normal untuk plaintext `q`:

```text
K0 = Enc(q; ρ)
```

Solver mengalikan ciphertext dengan:

```text
(N + 1)^M
```

Karena generator Paillier adalah `γ = N + 1`, hasilnya mengenkripsi:

```text
Kmal = Enc(q + M; ρ)
```

Secara kode:

```python
K0, rho_k = mal.pub.encrypt_and_return_randomness(Q)
hsmall = pow(mal.pub.gamma, M, mal.pub.n_square)
Kmal = K0 * hsmall % mal.pub.n_square
```

Server percaya ciphertext tersebut memiliki witness `q`, padahal plaintext sebenarnya `q + M`.

---

## 5. Forging ProofEnc dengan Fiat–Shamir Grinding

`ProofEnc` memeriksa:

```text
γ^z1 · z2^N = A · K^e mod N²
```

Proof dibuat seolah witness plaintext adalah `q`:

```text
z1 = e·q + α
```

Tetapi `K` mengenkripsi `q + M`. Ada faktor ekstra:

```text
γ^(eM)
```

Untuk `γ = 1 + N`:

```text
γ^(eM) = (1 + N)^(eM)
       = 1 + eMN mod N²
```

Karena:

```text
M = N/p
```

maka faktor tersebut menjadi satu modulo `N²` saat:

```text
p | e
```

Jadi proof palsu akan lolos jika challenge Fiat–Shamir memenuhi:

```text
e ≡ 0 mod p
```

Challenge berasal dari hash commitment:

```python
e = H(..., C) mod q
```

Commitment memiliki komponen:

```text
C = s^α · t^γ mod Ncap
```

Nilai `γ` bisa divariasikan tanpa mengubah witness utama. Solver menaikkan `γ`, menghitung ulang `C`, lalu hash ulang sampai:

```text
e mod p == 0
```

Prime hanya sekitar 18 bit, jadi rata-rata perlu sekitar `p` hash. Grinding diparalelkan dengan multiprocessing.

Teknik yang sama dipakai untuk memalsukan `ProofLogstar`.

---

## 6. Leakage `gamma_i mod p`

Pada MtA milik server, ciphertext beracun dikalikan dengan secret `gamma_i`.

Plaintext yang kita decrypt menjadi:

```text
dγ = ((q + M)·gamma_i + beta_neg) mod N
```

Tulis hasil reduksi sebagai:

```text
dγ = (q + M)·gamma_i + beta_neg - zγ·N
```

Karena `N = pM`, setelah seluruh komponen normal protokol dibatalkan, solver membentuk point:

```text
Tγ = (delta_i + dγ - 1)·G - vdelta_i
```

Dari persamaan presigning:

```text
Tγ = M·(gamma_i - zγ·p)·G
```

Nilai:

```text
gamma_i - zγ·p
```

berukuran kecil dan sama dengan residue bertanda modulo `p`.

Jadi kita menyelesaikan bounded discrete log:

```text
Tγ = rγ · (M·G)
```

dengan:

```text
-p < rγ < p
```

Karena `p` hanya sekitar 262 ribu, Baby-Step Giant-Step sangat murah.

Residue gamma dipakai untuk menyusun `delta` peer yang membuat presigning selesai dan menghasilkan point nonce `R`.

---

## 7. Membuat `R = k_i⁻¹·G`

Client mengirim share `Gamma = ∞` dan MtA zero-share yang dirancang agar bagian client dapat dikontrol.

Setelah residue gamma ditemukan, solver mengirim peer delta:

```python
peer_delta = beta_g - 1
```

Total delta server menjadi:

```text
delta = gamma_i·k_i
```

Sementara total Gamma hanya:

```text
Gamma = gamma_i·G
```

Maka output presigning:

```text
R = delta⁻¹·Gamma
  = (gamma_i·k_i)⁻¹ · gamma_i·G
  = k_i⁻¹·G
```

Relasi pentingnya:

```text
k_i·R = G
```

Relasi ini membuat share secret key bisa dipisahkan pada signing phase.

---

## 8. Leakage `xi mod p`

Server menghitung MtA kedua menggunakan secret share `xi`. Ciphertext yang kita decrypt:

```text
dx = ((q + M)·xi + beta_neg_x) mod N
```

Tulis:

```text
dx = (q + M)·xi + beta_neg_x - zx·N
```

Server mengirim:

```text
R_chi = chi_i·R
```

dengan:

```text
chi_i = xi·k_i + 1 - beta_neg_x mod q
```

Solver membentuk:

```text
Tx = R_chi - Xi - (1 - dx)·R
```

Substitusi `Xi = xi·G` dan `k_i·R = G`:

```text
Tx
= (xi·k_i + 1 - beta_neg_x)·R
  - xi·G
  - (1 - dx)·R

= (xi·k_i - beta_neg_x + dx)·R - xi·G

= (xi·k_i + M·xi - zx·N)·R - xi·G

= xi·G + M·(xi - zx·p)·R - xi·G

= M·(xi - zx·p)·R
```

Jadi:

```text
Tx = rx · (M·R)
```

dengan `rx` adalah residue bertanda `xi mod p`.

Sekali lagi, bounded BSGS memulihkan:

```text
xi mod p
```

---

## 9. Ulangi 15 Kali dan CRT

Solver memakai 15 prime:

```text
262147, 262151, 262153, 262187, 262193,
262217, 262231, 262237, 262253, 262261,
262271, 262303, 262313, 262321, 262331
```

Setiap signing round membocorkan satu congruence:

```text
xi ≡ ri mod pi
```

Setelah 15 round:

```text
P = p1·p2·...·p15
```

memiliki panjang 271 bit, sedangkan private scalar secp256k1 kurang dari 256 bit.

CRT menghasilkan satu-satunya kandidat:

```text
0 < xi < q
```

Validation:

```python
EC.scalar_mult(xi) == Xi
```

Jika point cocok, scalar hasil CRT pasti benar.

---

## 10. Menyelesaikan Signing Requirement

Server tidak menerima `guess_key` sebelum ada signature valid.

Solver membuat peer signing message dengan:

```text
R_k_peer   = ∞
R_chi_peer = (beta_x - 1)·R
sigma_peer = r·(beta_x - 1)
```

Persamaan share point tetap terpenuhi:

```text
sigma_peer·R
= h·R_k_peer + r·R_chi_peer
```

karena `R_k_peer = ∞`.

`ProofST` dibuat normal, sedangkan proof nonce `ProofLogstar` diforge lagi dengan grinding `e ≡ 0 mod p`.

Setelah satu atau beberapa signing round diterima, `signing_completed` menjadi `True`.

---

## 11. Solver

Arsip challenge tidak memiliki `__init__.py` pada beberapa direktori dan dapat bertabrakan dengan package Python bernama `crypto`. Tambahkan file package marker saat menjalankan solver.

```bash
find crypto ecdsa -type d -exec touch {}/__init__.py \; && \
source /home/nata/ctf_env/bin/activate && \
python3 solve.py HOST PORT --workers 8
```

Alur solver:

```text
solve PoW
→ keygen dengan share nol
→ buat malicious multiprime Paillier
→ forge auxiliary proofs
→ lakukan 15 leakage rounds
→ recover residue dengan bounded BSGS
→ CRT
→ validasi xi·G == Xi
→ guess_key
```

Output akhir:

```text
<FLAG>r3ctf{P30PIE_sHou1d_m0ve_to_BETteR-ONE_ThAN-CGGMPZl....c0}</FLAG>
```

---

## Flag

```text
r3ctf{P30PIE_sHou1d_m0ve_to_BETteR-ONE_ThAN-CGGMPZl....c0}
```

## Root Cause

Bug-nya bukan satu check yang hilang, tetapi kombinasi beberapa asumsi proof:

1. `ProofFac` tidak memastikan faktor yang dibuktikan benar-benar prime.
2. `ProofMod` tidak memastikan `W` invertibel modulo `N`.
3. Fiat–Shamir challenge dapat digrind terhadap prime kecil yang sengaja ditanam di modulus.
4. Proof ciphertext tidak aman ketika modulus witness dibuat malicious dan ciphertext memiliki komponen berorde kecil.
5. Service mengizinkan presigning/signing diulang berkali-kali dengan long-term key share yang sama.

Perbaikan yang dibutuhkan:

- validasi modulus Paillier sebagai produk tepat dua strong/safe primes;
- pastikan seluruh elemen proof berada di grup unit yang benar;
- tambahkan `gcd(W, N) == 1`;
- gunakan proof setup yang sesuai spesifikasi threshold ECDSA yang diaudit;
- batasi reuse sesi dan abort permanen setelah proof gagal;
- jangan menerima auxiliary modulus arbitrary tanpa parameter validation yang ketat.
