# Talking to the Sun

## Informasi Challenge

* Kategori: Web
* Judul: Talking to the Sun
* Deskripsi: `Easy one, all you need is to sing a song`
* Kriptografi: ECDSA dengan kurva BrainpoolP512r1
* Target akun: `whale@whale-tw.com`

Aplikasi bernama **SinGen** memungkinkan user membuat sebuah lyric key. Token tersebut berisi account, message, dan signature ECDSA.

Tujuan challenge adalah menghasilkan token valid atas nama akun administrator agar endpoint verifikasi mengeluarkan flag.

## Menjalankan Challenge Secara Lokal

Challenge menyediakan source code lengkap dan konfigurasi Docker. Karena Docker daemon tidak aktif, aplikasi cukup dijalankan langsung dengan Python:

```bash
python3 app.py
```

Service berjalan di:

```text
http://127.0.0.1:5000
```

Endpoint informasi dapat diperiksa dengan:

```bash
curl -s http://127.0.0.1:5000/api/info | jq
```

Output penting:

```json
{
  "admin_account": "whale@whale-tw.com",
  "curve": "BrainpoolP512r1",
  "max_account_chars": 39321,
  "nonce_tail_bits": 128,
  "stored_account_chars": 65536,
  "target": "SinGen Said: At sunrise, when it answers over my signal, I sit by the sun."
}
```

## Audit Source Code

Ada tiga bagian yang menjadi inti vulnerability:

1. Validasi panjang account dilakukan sebelum `.lower()`.
2. Account yang disimpan dipotong menjadi 65.536 karakter.
3. Nonce ECDSA memiliki prefix deterministik berdasarkan account dan hanya 128 bit acak.

Source juga mengeluarkan flag selama token memiliki signature valid dan nilai `account` sama dengan akun administrator.

## Bug Pertama: Unicode Lowercase Expansion

Validasi account dilakukan seperti berikut:

```python
MAX_ACCOUNT_CHARS = 0x9999
STORED_ACCOUNT_CHARS = 0x10000

def check_account(value: str) -> tuple[bool, str]:
    account = (value or "").strip()

    if not account or len(account) >= MAX_ACCOUNT_CHARS:
        return False, ""

    if ACCOUNT_RE.fullmatch(account) is None:
        return False, ""

    return True, account.lower()
```

Batas input sebelum lowercase adalah:

```text
0x9999 = 39321 karakter
```

Namun hasil `.lower()` tidak diperiksa ulang.

Python melakukan Unicode-aware lowercase. Salah satu karakter yang menarik adalah:

```text
İ
```

Karakter tersebut adalah:

```text
U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE
```

Ketika diproses menggunakan `.lower()`:

```python
"İ".lower()
```

hasilnya bukan satu karakter, tetapi dua code point:

```text
i + U+0307 COMBINING DOT ABOVE
```

Contoh:

```python
>>> len("İ")
1

>>> len("İ".lower())
2
```

Artinya kita dapat mengirim account dengan panjang di bawah 39.321 karakter, tetapi setelah lowercase panjangnya bisa melebihi 65.536 karakter.

## Bug Kedua: Perbedaan Account Fingerprint dan Stored Account

Account yang disimpan ke database dipotong:

```python
def stored_account(account: str) -> str:
    return account[:STORED_ACCOUNT_CHARS]
```

Namun fingerprint dihitung dari account lengkap:

```python
def account_fingerprint(account: str) -> str:
    return hashlib.sha256(account.encode("utf-8")).hexdigest()
```

Saat registrasi:

```python
fingerprint = account_fingerprint(account)

conn.execute(
    """
    INSERT INTO users (
        account,
        account_fingerprint,
        password_salt,
        password_hash,
        created_at
    )
    VALUES (?, ?, ?, ?, ?)
    """,
    (
        stored_account(account),
        fingerprint,
        salt,
        password_hash,
        now,
    ),
)
```

Akibatnya dua account dapat memiliki:

* `account_fingerprint` berbeda;
* account yang tersimpan di database identik.

Ini bisa dilakukan dengan membuat 65.536 karakter pertama dari hasil lowercase sama, lalu menambahkan suffix unik setelah batas tersebut.

## Membuat Stored Account Collision

Prefix account yang digunakan:

```python
COLLISION_PREFIX = "a@" + "\u0130" * 32767
```

Setelah lowercase:

```text
"a@"                            = 2 karakter
32767 × lowercase("İ")          = 32767 × 2
                                = 65534 karakter
------------------------------------------------
Total                           = 65536 karakter
```

Jadi:

```text
2 + 32767 × 2 = 65536
```

Suffix unik kemudian ditambahkan setelah prefix:

```python
email = COLLISION_PREFIX + f"{run_id}{index:04x}.x"
```

Input asli tetap di bawah batas 39.321 karakter karena setiap `İ` baru berkembang menjadi dua karakter setelah `.lower()`.

Contoh sederhananya:

```text
Account 1:
a@İİİ...İ<suffix-1>.x

Account 2:
a@İİİ...İ<suffix-2>.x
```

Fingerprint kedua account berbeda karena suffix-nya berbeda.

Tetapi setelah lowercase dan dipotong:

```python
account[:65536]
```

keduanya menjadi account tersimpan yang sama:

```text
a@i̇i̇i̇i̇i̇...
```

Dengan cara ini kita dapat membuat banyak user berbeda yang semuanya memiliki nilai `user["account"]` identik.

## ECDSA Nonce Generation

Nonce dibuat menggunakan fungsi berikut:

```python
NONCE_PREFIX_BYTES = 48
NONCE_TAIL_BYTES = 16

def nonce_for_account(account: str) -> int:
    prefix = hashlib.sha384(
        NONCE_SALT + account.encode("utf-8")
    ).digest()

    while True:
        raw = prefix + os.urandom(NONCE_TAIL_BYTES)
        value = int.from_bytes(raw, "big") % ORDER

        if value:
            return value
```

Struktur nonce:

```text
k = SHA384(NONCE_SALT || account) || random_128_bit
```

Prefix nonce sepanjang:

```text
48 byte = 384 bit
```

Tail acak hanya:

```text
16 byte = 128 bit
```

Karena semua akun collision memiliki stored account identik, nilai:

```python
SHA384(NONCE_SALT + account)
```

juga identik.

Nonce yang dihasilkan berbentuk:

```text
k₁ = K + t₁
k₂ = K + t₂
k₃ = K + t₃
...
```

Dengan:

```text
K   = prefix nonce yang sama
tᵢ  = random tail 128 bit
```

Maka selisih antar-nonce kecil:

```text
kᵢ - k₀ = tᵢ - t₀
```

Sehingga:

```text
|kᵢ - k₀| < 2¹²⁸
```

Ini mengubah masalah ECDSA menjadi Hidden Number Problem yang bisa diselesaikan menggunakan lattice reduction.

## Persamaan ECDSA

Untuk setiap signature ECDSA:

```text
rᵢ = x(kᵢG) mod n
```

dan:

```text
sᵢ = kᵢ⁻¹(zᵢ + rᵢd) mod n
```

Dengan:

* `n` adalah order kurva;
* `d` adalah private signing key;
* `zᵢ` adalah hash message;
* `kᵢ` adalah nonce;
* `(rᵢ, sᵢ)` adalah signature.

Persamaan kedua dapat disusun ulang:

```text
sᵢkᵢ = zᵢ + rᵢd mod n
```

Kalikan dengan invers modular `sᵢ`:

```text
kᵢ = rᵢsᵢ⁻¹d + zᵢsᵢ⁻¹ mod n
```

Definisikan:

```text
αᵢ = rᵢsᵢ⁻¹ mod n
βᵢ = zᵢsᵢ⁻¹ mod n
```

Sehingga:

```text
kᵢ = αᵢd + βᵢ mod n
```

Karena setiap nonce memiliki prefix yang sama, kita kurangi persamaan signature ke-`i` dengan signature referensi:

```text
kᵢ - k₀ =
(αᵢ - α₀)d + (βᵢ - β₀) mod n
```

Definisikan:

```text
Aᵢ = αᵢ - α₀ mod n
Cᵢ = βᵢ - β₀ mod n
δᵢ = kᵢ - k₀
```

Maka:

```text
Aᵢd + Cᵢ = δᵢ mod n
```

Dengan batas:

```text
|δᵢ| < 2¹²⁸
```

Kita sekarang mencari private key `d` yang membuat seluruh persamaan modular memiliki error kecil.

## Lattice Construction

Untuk `m` persamaan, solver membangun lattice berdimensi `m + 1`.

Scaling factor yang digunakan:

```python
scale = N // (1 << 128)
```

Basis lattice:

```text
[n·scale       0           ...        0]
[0             n·scale     ...        0]
[...           ...         ...        ...]
[A₁·scale      A₂·scale    ...        1]
```

Target vector:

```text
[-C₁·scale, -C₂·scale, ..., 0]
```

Sebuah lattice vector dapat ditulis sebagai:

```text
[
  scale(nq₁ + A₁d),
  scale(nq₂ + A₂d),
  ...,
  d
]
```

Jarak terhadap target pada setiap koordinat pertama menjadi:

```text
scale(nqᵢ + Aᵢd + Cᵢ)
```

Karena untuk private key yang benar:

```text
Aᵢd + Cᵢ = δᵢ mod n
```

maka ada nilai integer `qᵢ` yang membuat koordinat tersebut bernilai kecil:

```text
scale · δᵢ
```

Sage kemudian menggunakan approximate Closest Vector Problem dengan algoritma nearest-plane atau Babai:

```python
closest = lattice.approximate_closest_vector(
    target,
    delta=0.99,
    algorithm="nearest_plane",
)
```

Koordinat terakhir dari vector terdekat menjadi kandidat private key:

```python
private_key = int(closest[-1]) % N
```

## Memvalidasi Private Key

Kandidat private key tidak langsung dipercaya.

Untuk setiap signature, nonce direkonstruksi:

```python
k = (
    (z + r * private_key)
    * pow(s, -1, N)
) % N
```

Kemudian selisih seluruh nonce terhadap nonce pertama dihitung secara centered modulo `N`.

Private key dianggap benar apabila:

```text
max |kᵢ - k₀| < 2¹²⁸
```

Pada local instance, solver memperoleh:

```text
[+] Private key recovered
[+] Maksimum nonce difference: 127 bits
```

Pada remote instance:

```text
[+] Private key recovered
[+] Maksimum nonce difference: 128 bits
```

## Mengumpulkan Signature

Setiap akun hanya dapat menghasilkan satu lyric key:

```text
One account can generate one signed line.
```

Karena itu solver membuat 12 akun collision.

Setiap akun melakukan:

1. Registrasi.
2. Login.
3. Request ke `/api/generate`.
4. Decode token.
5. Simpan nilai `account`, `message`, `r`, dan `s`.

Request generate menggunakan pilihan yang sama:

```python
SELECTIONS = {
    "time": 0,
    "motion": 0,
    "place": 0,
    "seat": 0,
}
```

Stored account dimulai dengan:

```text
a@
```

Fungsi `make_message()` mengambil bagian sebelum `@` sebagai speaker, sehingga semua account menghasilkan message yang sama:

```text
A Said: At night, when it glows over my room, I sit by myself.
```

Output collector:

```text
[*] Mengumpulkan 12 signature...
[+] Signature 1/12
[+] Signature 2/12
...
[+] Signature 12/12
[+] Stored account identik, panjang = 65536
[+] Message: A Said: At night, when it glows over my room, I sit by myself.
```

## Token Format

Token memiliki format:

```text
singen.<payload-base64url>.<signature-base64url>
```

Payload adalah canonical JSON:

```json
{
  "account": "...",
  "message": "..."
}
```

Signature terdiri dari:

```text
r || s
```

Masing-masing sepanjang 64 byte.

Setelah private key didapat, solver membuat payload administrator:

```python
account = "whale@whale-tw.com"

message = (
    "SinGen Said: At sunrise, when it answers "
    "over my signal, I sit by the sun."
)
```

Kemudian dipilih nonce acak baru:

```python
k = random_scalar()
```

Signature admin dibuat menggunakan private key hasil recovery:

```text
r = x(kG) mod n
s = k⁻¹(z + rd) mod n
```

Implementasinya:

```python
point = nonce * G
r = int(point.x()) % N

s = (
    pow(nonce, -1, N)
    * (z + r * private_key)
) % N
```

Token lalu dikirim ke:

```text
POST /api/verify
```

Dengan body:

```json
{
  "token": "<forged-token>"
}
```

## Kondisi Flag

Endpoint verifikasi memeriksa signature terlebih dahulu:

```python
if not verify_parts(account, message, r, s):
    return {
        "ok": False,
        "message": "Signature check failed."
    }
```

Setelah signature valid, flag diberikan apabila account sama dengan:

```python
ADMIN_ACCOUNT = "whale@whale-tw.com"
```

Logikanya:

```python
if account == ADMIN_ACCOUNT:
    return {
        "ok": True,
        "message": message,
        "flag": os.environ.get("FLAG", DEFAULT_FLAG),
    }
```

Tidak ada pemeriksaan bahwa token tersebut pernah dibuat oleh database.

Server hanya mempercayai validitas signature. Setelah private key berhasil direcover, kita bebas menandatangani payload administrator.

## Pengujian Lokal

Solver dijalankan menggunakan Sage:

```bash
sage -python solve.py http://127.0.0.1:5000
```

Output:

```text
[*] Target: http://127.0.0.1:5000
[*] Curve: BrainpoolP512r1
[*] Nonce tail: 128 bits
[*] Mengumpulkan 12 signature...
[+] Signature 1/12
[+] Signature 2/12
[+] Signature 3/12
[+] Signature 4/12
[+] Signature 5/12
[+] Signature 6/12
[+] Signature 7/12
[+] Signature 8/12
[+] Signature 9/12
[+] Signature 10/12
[+] Signature 11/12
[+] Signature 12/12
[+] Stored account identik, panjang = 65536
[+] Message: A Said: At night, when it glows over my room, I sit by myself.
[*] Menjalankan lattice/CVP...
[+] Private key recovered (ref=0, scale=1, algorithm=nearest_plane)
[+] Maksimum nonce difference: 127 bits
[*] Verify response: {
    "flag": "NHNC{TEST_ME}",
    "message": "SinGen Said: At sunrise, when it answers over my signal, I sit by the sun.",
    "ok": true
}

[FLAG] NHNC{TEST_ME}
```

Local challenge berhasil diselesaikan sebelum instancer remote dijalankan.

## Eksploitasi Remote

Setelah instance aktif, solver cukup diarahkan ke URL remote:

```bash
sage -python solve.py http://nhnc2.whale-tw.com:10015/
```

Output:

```text
[*] Target: http://nhnc2.whale-tw.com:10015
[*] Curve: BrainpoolP512r1
[*] Nonce tail: 128 bits
[*] Mengumpulkan 12 signature...
[+] Signature 1/12
[+] Signature 2/12
[+] Signature 3/12
[+] Signature 4/12
[+] Signature 5/12
[+] Signature 6/12
[+] Signature 7/12
[+] Signature 8/12
[+] Signature 9/12
[+] Signature 10/12
[+] Signature 11/12
[+] Signature 12/12
[+] Stored account identik, panjang = 65536
[+] Message: A Said: At night, when it glows over my room, I sit by myself.
[*] Menjalankan lattice/CVP...
[+] Private key recovered (ref=0, scale=1, algorithm=nearest_plane)
[+] Maksimum nonce difference: 128 bits
[*] Verify response: {
    "flag": "NHNC{its_always_a_good_time_(_to_play_with_python_lower_)}",
    "message": "SinGen Said: At sunrise, when it answers over my signal, I sit by the sun.",
    "ok": true
}
```

## Flag

```text
NHNC{its_always_a_good_time_(_to_play_with_python_lower_)}
```

## Ringkasan Exploit Chain

Rangkaian bug yang digunakan:

```text
Unicode lowercase expansion
        ↓
Input pendek berkembang melewati 65536 karakter
        ↓
Fingerprint dihitung dari account lengkap
        ↓
Account database dipotong menjadi 65536 karakter
        ↓
Banyak akun berbeda memiliki stored account identik
        ↓
Nonce SHA384 prefix identik untuk semua signature
        ↓
Hanya 128 bit nonce yang berbeda
        ↓
ECDSA Hidden Number Problem
        ↓
Private signing key direcover dengan lattice/CVP
        ↓
Token admin ditandatangani
        ↓
/api/verify mengeluarkan flag
```
