# CTF Writeup — That Steel Really Is Secure

**Event:** RAM CTF  
**Category:** Crypto  
**Difficulty:** Medium / Hard  
**Flag:** `RAM{1_10V3_M47r1C35_P13453_D0N7_F1r3_M3}`

---

## Challenge Description

> Threatened with termination over continued failures, the overburdened hero Junior Dev 1 has tried one last time to invoke gibson to create a scheme that is truly secure (And under the terms of the steelsecure licence!) They're so confident, that they have even open sourced the signature scheme.
>
> You know what to do.

Diberikan dua file utama:

```bash
output.txt
chall.py
```

`chall.py` berisi implementasi custom signature scheme, sedangkan `output.txt` berisi public key, beberapa pasangan message-signature, ciphertext, dan IV.

---

## Reconnaissance

### Step 1 — Identify Crypto Primitive

Dari source code:

```python
p = 148982911401264734500617017580518449923542719532318121475997727602675813514863
g = 2
assert isPrime(p // 2)

x = randrange(p)
y = pow(g, x, p)
```

Terlihat bahwa skema ini bekerja pada grup modulo prime `p`.

Private key:

```python
x
```

Public key:

```python
y = g^x mod p
```

Signature scheme-nya mirip **Schnorr signature**:

```python
def sign(msg, k):
    r = pow(g, k, p)
    e = bytes_to_long(sha224(long_to_bytes(r) + msg).digest()) % p
    s = (k - x * e) % (p - 1)
    return (s, e)
```

Verification:

```python
def verify(s, e, msg):
    r_v = (pow(g, s, p) * pow(y, e, p)) % p
    return bytes_to_long(sha224(long_to_bytes(r_v) + msg).digest()) == e
```

Karena:

```text
y = g^x
s = k - x e
```

maka:

```text
g^s y^e = g^(k - xe) g^(xe) = g^k = r
```

Jadi secara konsep, signature valid.

Target akhirnya adalah mendapatkan `x`, karena flag dienkripsi menggunakan AES key turunan dari `x`:

```python
key = sha224(long_to_bytes(x)).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(pad(flag, 16)).hex()
```

---

## Vulnerability Analysis

### Step 2 — Check Nonce Generation

Bagian paling penting ada di nonce `k`:

```python
otp = os.urandom(32)

for message in messages:
    k = bytes_to_long(xor(pad(message, 32)[::-1], otp))
    s, e = sign(message, k % p)
```

Fungsi XOR:

```python
def xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])
```

Masalahnya:

1. `otp` hanya dibuat sekali.
2. `otp` dipakai ulang untuk semua message.
3. Nonce `k` bukan random murni, tetapi:

```text
k_i = known_mask_i XOR otp
```

dengan:

```text
known_mask_i = pad(message_i, 32)[::-1][:32]
```

Karena `otp` sama untuk semua signature, semua nonce saling berhubungan.

Ini fatal untuk Schnorr-like signature.

---

## Mathematical Model

Dari signature:

```python
s = (k - x * e) % (p - 1)
```

Misalkan:

```text
N = p - 1
```

Maka untuk setiap signature:

```text
s_i ≡ k_i - x e_i mod N
```

atau:

```text
k_i - s_i ≡ x e_i mod N
```

Karena `k_i` berasal dari XOR dengan OTP:

```text
k_i = P_i XOR otp
```

dengan `P_i` diketahui dari message.

---

## Exploitation

### Step 3 — Convert XOR Nonce Into Linear Form

Walaupun XOR bukan linear terhadap integer biasa, XOR dengan nilai yang diketahui bisa ditulis sebagai ekspresi linear terhadap bit-bit OTP.

Untuk setiap bit OTP `b_j ∈ {0,1}`:

```text
jika bit P_i[j] = 0:
    bit k_i[j] = b_j

jika bit P_i[j] = 1:
    bit k_i[j] = 1 - b_j
```

Sehingga:

```text
k_i = P_i + Σ c_i,j b_j
```

dengan:

```text
c_i,j = +2^j  jika bit P_i[j] = 0
c_i,j = -2^j  jika bit P_i[j] = 1
```

Artinya setiap nonce bisa dimodelkan sebagai persamaan linear atas bit-bit OTP.

---

### Step 4 — Eliminate Private Key `x`

Dari dua signature:

```text
k_i - s_i ≡ x e_i mod N
k_0 - s_0 ≡ x e_0 mod N
```

Kurangkan:

```text
(k_i - k_0) - (s_i - s_0) ≡ x(e_i - e_0) mod N
```

Misalkan:

```text
L_i = k_i - k_0
S_i = s_i - s_0
D_i = e_i - e_0
```

Maka:

```text
L_i - S_i ≡ x D_i mod N
```

Untuk menghilangkan `x`, ambil dua indeks berbeda:

```text
D_j(L_i - S_i) - D_i(L_j - S_j) ≡ 0 mod N
```

Hasilnya adalah beberapa persamaan modular linear yang hanya berisi bit-bit OTP.

Ini menjadi problem:

```text
Σ A_j b_j ≡ B mod N
```

dengan `b_j ∈ {0,1}`.

Problem seperti ini bisa diselesaikan dengan lattice reduction / LLL.

---

## Solver

### Step 5 — Build Lattice and Recover OTP Bits

Saya menggunakan LLL untuk menemukan vector pendek berisi bit-bit OTP.

Core idea lattice embedding:

```text
v = last_row - Σ b_j row_j - Σ z_i modulus_row_i
```

Jika tebakan bit benar, bagian modular menjadi nol dan bagian bit menjadi `±1`.

solver di solve.sage
untuk mendapakan value x di get_x.py
decrypt di flag.py

---

## Decryption

Setelah private key `x` ditemukan, AES key bisa dihitung persis seperti challenge:

```python
key = sha224(long_to_bytes(x)).digest()[:16]
```

Lalu ciphertext didekripsi menggunakan AES-CBC:

```python
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ct), 16)
```

Plaintext yang didapat:

```text
RAM{1_10V3_M47r1C35_P13453_D0N7_F1r3_M3}
```

---

## Flag

```text
RAM{1_10V3_M47r1C35_P13453_D0N7_F1r3_M3}
```

---


---

## Attack Flow

```text
Read chall.py
      │
      ▼
Identify Schnorr-like signature:
s = k - x e mod (p - 1)
      │
      ▼
Notice nonce generation:
k_i = bytes_to_long(pad(msg_i, 32)[::-1][:32] XOR otp)
      │
      ▼
OTP reused across all signatures
      │
      ▼
Model each k_i as linear expression over OTP bits
      │
      ▼
Use signature equations:
k_i - s_i ≡ x e_i mod (p - 1)
      │
      ▼
Eliminate x between equations
      │
      ▼
Solve modular binary linear system using LLL
      │
      ▼
Recover OTP bits
      │
      ▼
Recover private key x
      │
      ▼
Verify pow(g, x, p) == y
      │
      ▼
Derive AES key:
sha224(long_to_bytes(x))[:16]
      │
      ▼
Decrypt ct with AES-CBC
      │
      ▼
RAM{1_10V3_M47r1C35_P13453_D0N7_F1r3_M3}
```
