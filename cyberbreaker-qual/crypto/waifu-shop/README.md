# Writeup: Waifu Shop (Crypto/Web)

## 1. Observasi Awal
Pas buka URL-nya, kita dikasih lihat toko waifu "Celestial Waifu". Ada beberapa item yang bisa kita beli, tapi item incaran kita, **Shinano (Celestial Waifu)**, statusnya *sold out* atau hanya untuk pemenang lottery.

Pas kita coba beli item lain (yang `available`), web ini bakal kasih kita semacam **Sealed Receipt** atau `order_token`. Token ini nantinya dikirim ke endpoint `/claim` untuk diverifikasi.

Target kita jelas: **Gimana cara dapet token buat Shinano dengan harga 0?** Karena di source code (`app.py`), syarat dapet flag adalah:
```python
if order_data.get('item') == 'celestial_waifu' and order_data.get('price') == '000000':
    return render_template('result.html', ok=True, title='Preorder secured', message=FLAG)
```

## 2. Analisis Source Code
Cek `app.py`, bagian enkripsinya menarik:

```python
KEY = os.urandom(16)
NONCE = os.urandom(8)

def crypt(data):
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=NONCE)
    return cipher.encrypt(data)
```

**Fatal Error:** Di sini `NONCE` didefinisikan sekali di level global. Setiap kali fungsi `crypt` dipanggil, dia pakai `NONCE` yang sama persis. 

Dalam **AES-CTR**, kalau kita pakai Key dan Nonce yang sama untuk dua pesan yang berbeda, kita bakal dapet **Keystream Reuse**. 
Rumusnya simpel:
1. `Ciphertext = Plaintext ^ Keystream`
2. `Keystream = Ciphertext ^ Plaintext`

Berarti kalau kita tahu satu pasang Plaintext dan Ciphertext, kita bisa dapet Keystream-nya. Setelah dapet Keystream, kita bisa bikin Ciphertext palsu buat Plaintext apa pun yang kita mau.

## 3. Strategi Serangan
1. **Dapatkan Token Valid:** Pesan item yang tersedia (contoh: `enterprise_gold`). Web bakal kasih `order_token`.
2. **Decode Token:** Token itu di-encode pakai `urlsafe_b64`. Kita decode buat dapet `Ciphertext_A`.
3. **Identifikasi Plaintext:** Dari code, kita tahu format order itu: 
   `item=enterprise_gold&price=004800&buyer=guest&ship=standard`
   Ini adalah `Plaintext_A`.
4. **Hitung Keystream:** `Keystream = Ciphertext_A ^ Plaintext_A`.
5. **Forge Token:** 
   Plaintext target kita adalah: `item=celestial_waifu&price=000000&buyer=guest&ship=standard`.
   `Ciphertext_Baru = Plaintext_Target ^ Keystream`.
6. **Submit:** Encode `Ciphertext_Baru` ke Base64, terus kirim ke `/claim`.

## 4. Scripting (solve.py)
Biar cepet, kita pakai Python buat hitung XOR-nya:

```python
import requests
import base64
import re
import urllib3

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# URL Target
BASE_URL = "https://waifu-shop.cbd2026.cloud"

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# 1. Ambil token legal (Enterprise)
print("[*] Mengambil token Enterprise...")
resp = requests.post(f"{BASE_URL}/order", data={"item": "enterprise_gold"}, verify=False)
token_legal = re.search(r'name="order_token" value="([^"]+)"', resp.text).group(1)

# 2. Decode Ciphertext A
ciphertext_a = base64.urlsafe_b64decode(token_legal + "==")

# 3. Plaintext A (dari source code)
plaintext_a = b"item=enterprise_gold&price=004800&buyer=guest&ship=standard"

# 4. Cari Keystream
keystream = xor(ciphertext_a, plaintext_a)

# 5. Rakit Plaintext Target & XOR dengan Keystream
plaintext_target = b"item=celestial_waifu&price=000000&buyer=guest&ship=standard"
ciphertext_target = xor(plaintext_target, keystream)

# 6. Encode jadi token baru
token_palsu = base64.urlsafe_b64encode(ciphertext_target).decode().strip("=")

# 7. Claim Flag!
print(f"[*] Token palsu: {token_palsu}")
final_resp = requests.post(f"{BASE_URL}/claim", data={"order_token": token_palsu}, verify=False)

if "CBC{" in final_resp.text:
    flag = re.search(r'CBC\{.*\}', final_resp.text).group(0)
    print(f"[+] Flag ditemukan: {flag}")
```

## 5. Hasil Akhir
Setelah script dijalankan, server menerima token palsu kita karena hasil dekripsinya menghasilkan plaintext yang valid (`celestial_waifu` dengan price `000000`). Server pun memberikan flag-nya:

**Flag:**
`CBC{enterprise_is_min333_4d0b8a}`
