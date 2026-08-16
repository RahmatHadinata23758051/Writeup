# Nonce Sense — THJCC CTF Write-up

* **CTF:** THJCC
* **Challenge:** Nonce Sense
* **Category:** Cryptography
* **Service:** `nc chal.thjcc.org 12001`
* **Flag:** `THJCC{n3v3r_3v3r_r3us3_th3_s4m3_n0nc3}`

## 1. Deskripsi Soal

Pada challenge ini, kita diberikan akses ke sebuah koneksi socket:

```bash
nc chal.thjcc.org 12001
```

Saat terhubung, server memberikan beberapa informasi:

* `PUB`: Public key server.
* `SIG (1)`: Signature untuk pesan `transfer 1 coin to alice`.
* `SIG (2)`: Signature untuk pesan `transfer 2 coins to bob`.
* `TARGET`: Pesan yang harus kita forge signature-nya, yaitu:

```text
admin=true;action=release_flag
```

Tujuannya adalah memberikan signature ECDSA yang valid untuk pesan `TARGET` sehingga server mengembalikan flag.

---

## 2. Identifikasi Kerentanan

Perhatikan dua signature yang diberikan server.

### Signature 1

```text
r  = 1d582b9f128dd5a6e82fbf9232f9b8febc3945f35412de53cfa6b152cf8b4cb9
s1 = 53b1a5659e4fc1d84a97afc9fc33eaaf59621beddfdb495dfe0ffeba9d04ef1a
```

### Signature 2

```text
r  = 1d582b9f128dd5a6e82fbf9232f9b8febc3945f35412de53cfa6b152cf8b4cb9
s2 = e874a347d981c50230ca90851d931537adb49e28f31a38d0d6920b3fbd499c80
```

Terlihat bahwa:

```text
r1 = r2
```

Padahal kedua pesan berbeda.

Dalam ECDSA, nilai `r` berasal dari nonce `k`. Jika dua pesan berbeda menghasilkan `r` yang sama, hal tersebut mengindikasikan bahwa nonce yang sama telah digunakan kembali.

Ini merupakan kelemahan fatal pada implementasi ECDSA karena nonce reuse memungkinkan kita menghitung kembali private key.

---

## 3. Dasar Matematis ECDSA

Persamaan ECDSA untuk komponen `s` adalah:

$$
s \equiv k^{-1}(z + r \cdot d) \pmod n
$$

dengan:

* `k` = nonce
* `z` = hash dari pesan
* `r, s` = komponen signature
* `d` = private key
* `n` = order dari elliptic curve

Untuk dua signature dengan nonce yang sama:

$$
s_1 \cdot k \equiv z_1 + r \cdot d \pmod n
$$

$$
s_2 \cdot k \equiv z_2 + r \cdot d \pmod n
$$

Kurangkan kedua persamaan tersebut:

$$
k(s_1-s_2) \equiv z_1-z_2 \pmod n
$$

Sehingga nonce dapat dihitung:

$$
k \equiv (z_1-z_2)(s_1-s_2)^{-1} \pmod n
$$

Setelah mendapatkan `k`, private key dapat dihitung dari:

$$
d \equiv (s_1k-z_1)r^{-1} \pmod n
$$

Dengan demikian, kita dapat memperoleh private key server hanya dari dua signature yang diberikan.

---

## 4. Validasi Public Key

Challenge tidak langsung memberi tahu curve yang digunakan. Solver dapat mencoba curve yang umum digunakan, yaitu:

* NIST P-256 (`NIST256p`)
* secp256k1 (`SECP256k1`)

Setelah mendapatkan kandidat private key `d`, kita membuat public key dari private key tersebut dan membandingkan koordinat `x` dan `y` dengan public key yang diberikan server.

Jika keduanya sama, berarti curve dan private key yang ditemukan benar.

---

## 5. Membuat Signature untuk TARGET

Setelah private key berhasil diperoleh, kita dapat membuat signature baru untuk:

```text
admin=true;action=release_flag
```

Signature tersebut kemudian dikirim ke server dalam format:

```text
r s
```

Server akan memverifikasi signature menggunakan public key yang sama. Karena signature dibuat menggunakan private key yang valid, server menerima signature tersebut dan mengembalikan flag.

---

## 6. Solver Script

Berikut solver otomatis menggunakan Python, `pwntools`, `ecdsa`, dan `pycryptodome`:

```python
from pwn import *
import hashlib
from Crypto.Util.number import inverse
from ecdsa import SigningKey, NIST256p, SECP256k1

HOST = 'chal.thjcc.org'
PORT = 12001


def solve():
    io = remote(HOST, PORT)

    # 1. Parsing data dari server
    io.recvuntil(b"PUB ")
    pub_x_hex, pub_y_hex = (
        io.recvline().decode().strip().split()
    )

    io.recvuntil(b"SIG ")
    msg1_hex, r1_hex, s1_hex = (
        io.recvline().decode().strip().split()
    )

    io.recvuntil(b"SIG ")
    msg2_hex, r2_hex, s2_hex = (
        io.recvline().decode().strip().split()
    )

    io.recvuntil(b"TARGET ")
    target_hex = io.recvline().decode().strip()

    # 2. Konversi ke integer / bytes
    r = int(r1_hex, 16)
    s1 = int(s1_hex, 16)
    s2 = int(s2_hex, 16)

    pub_x = int(pub_x_hex, 16)
    pub_y = int(pub_y_hex, 16)

    msg1 = bytes.fromhex(msg1_hex)
    msg2 = bytes.fromhex(msg2_hex)
    target_msg = bytes.fromhex(target_hex)

    # Hash pesan menggunakan SHA-256
    z1 = int.from_bytes(
        hashlib.sha256(msg1).digest(),
        'big'
    )

    z2 = int.from_bytes(
        hashlib.sha256(msg2).digest(),
        'big'
    )

    log.info("Mengekstrak private key...")

    correct_sk = None

    # 3. Coba curve yang mungkin digunakan
    for curve_name, CURVE in [
        ("NIST256p", NIST256p),
        ("SECP256k1", SECP256k1)
    ]:
        n = CURVE.order

        try:
            # Recover nonce k
            k = (
                (z1 - z2)
                * inverse(s1 - s2, n)
            ) % n

            # Recover private key d
            d = (
                (s1 * k - z1)
                * inverse(r, n)
            ) % n

            # Generate public key dari private key
            sk = SigningKey.from_secret_exponent(
                d,
                curve=CURVE
            )

            vk = sk.get_verifying_key()

            # Validasi terhadap public key server
            if (
                vk.pubkey.point.x() == pub_x
                and
                vk.pubkey.point.y() == pub_y
            ):
                log.success(
                    f"Kurva yang benar: {curve_name}"
                )

                log.success(
                    f"Private key: {hex(d)}"
                )

                correct_sk = sk
                break

        except Exception:
            continue

    if not correct_sk:
        log.error("Gagal mengekstrak private key.")
        return

    # 4. Buat signature untuk TARGET
    sig_target = correct_sk.sign_deterministic(
        target_msg,
        hashfunc=hashlib.sha256
    )

    r_target = sig_target[:32].hex()
    s_target = sig_target[32:].hex()

    # 5. Kirim signature ke server
    payload = f"{r_target} {s_target}".encode()

    log.info("Mengirim signature untuk TARGET...")

    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    solve()
```

> **Catatan:** Pemotongan `sig_target[:32]` dan `sig_target[32:]` mengasumsikan signature yang dihasilkan library berada dalam format raw `r || s`, masing-masing 32 byte. Jika implementasi challenge menggunakan format signature berbeda, gunakan encoder/decoder ECDSA yang sesuai.

---

## 7. Exploit Flow

Secara singkat, exploit bekerja seperti berikut:

```text
              SIG 1                  SIG 2
                │                      │
                │      r1 = r2        │
                └──────────┬───────────┘
                           │
                    Nonce Reuse
                           │
                           ▼
                  Recover nonce k
                           │
                           ▼
                Recover private key d
                           │
                           ▼
                  Validate dengan PUB
                           │
                           ▼
             Sign pesan TARGET
                           │
                           ▼
                 Kirim r_target, s_target
                           │
                           ▼
                         FLAG
```

---

