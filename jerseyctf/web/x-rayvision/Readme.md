# CTF Writeup — X-Ray Vision

**Event:** JerseyCTF  
**Category:** Web  
**Difficulty:** Easy  
**Flag:** `jctf{r0t_y0ur_w4y_t0_4cc3ss}`

---

## Challenge Description

> X-Ray Vision's internal employee portal was accidentally pushed to staging with debug artifacts left behind. The developer API is locked down, but someone forgot to clean up before deploying. The credential is in there somewhere — but it won't be handed to you in plaintext.

**URL:** `http://x-ray-vision.aws.jerseyctf.com`

---

## Reconnaissance

### Step 1 — Inspect Page Source

Opening the target URL reveals a styled employee portal dashboard. A standard first step in web CTFs is to inspect the HTML source for hidden comments or debug artifacts.

Scrolling to the bottom of the source, a hidden `<div>` is found that was clearly meant to be removed before production:

```html
<div id="sys-cache"
     style="display:none"
     data-stage-note="remove before prod"
     data-h="x-secret-token"
     data-t="q3i3y0c3e_g00y5">
</div>
```

The attributes reveal:
- `data-h` → the HTTP header name: `x-secret-token`
- `data-t` → an encoded token value: `q3i3y0c3e_g00y5`
- `data-stage-note` → confirms this is a staging artifact, accidentally deployed

### Step 2 — Identify the Target Endpoint

The dashboard UI contains a button labeled **"Query API"** linking to `/api/status`, which currently returns `RESTRICTED` for the guest session.

---

## Exploitation

### Step 3 — Test Raw Token

Sending the raw token directly to the API:

```bash
curl -si http://x-ray-vision.aws.jerseyctf.com/api/status \
  -H "x-secret-token: q3i3y0c3e_g00y5"
```

Response:
```json
HTTP/1.1 403 FORBIDDEN
{"status": "forbidden", "hint": "Julius Caesar used to shift letters. So did ROT13."}
```

The server returns `403 Forbidden` but includes a helpful hint — the token is encoded with **ROT13** (a Caesar cipher with shift of 13).

### Step 4 — Decode the Token

ROT13 shifts each letter by 13 positions (non-alpha characters pass through unchanged):

```
q3i3y0c3e_g00y5
      ↓ ROT+13
d3v3l0p3r_t00l5
```

Reading the decoded value: **`d3v3l0p3r_t00l5`** → "developer_tools" in leet speak.

Python one-liner to verify:

```python
import codecs
print(codecs.encode("q3i3y0c3e_g00y5", "rot_13"))
# Output: d3v3l0p3r_t00l5
```

### Step 5 — Send Decoded Token

```bash
curl -si http://x-ray-vision.aws.jerseyctf.com/api/status \
  -H "x-secret-token: d3v3l0p3r_t00l5"
```

Response:
```json
HTTP/1.1 200 OK
{"status": "success", "flag": "jctf{r0t_y0ur_w4y_t0_4cc3ss}"}
```

---

## Flag

```
jctf{r0t_y0ur_w4y_t0_4cc3ss}
```

---

## Vulnerability Summary

| # | Vulnerability | Detail |
|---|---|---|
| 1 | **Exposed Debug Artifact** | Hidden `<div>` with `display:none` left in production HTML containing API credentials |
| 2 | **Security Through Obscurity** | Token "protected" only by ROT13 — a trivially reversible encoding, not encryption |
| 3 | **Client-Side Secret Storage** | Credentials embedded in frontend HTML instead of being kept server-side |

---

## Remediation

1. **Never embed credentials in HTML** — use environment variables and server-side authentication flows
2. **Automate cleanup checks** — CI/CD pipelines should scan for `data-stage-*`, `display:none` secrets, and `TODO: remove` comments before deployment
3. **Use real encryption** — ROT13 / Caesar ciphers provide zero security; use HMAC or signed tokens

---

## Tools Used

- `curl` — HTTP request with custom headers
- Python `codecs.rot_13` — decode the token

---

## Attack Flow

```
View Page Source
      │
      ▼
Find hidden <div id="sys-cache">
  data-h = "x-secret-token"
  data-t = "q3i3y0c3e_g00y5"
      │
      ▼
Test raw token → 403 + hint: "ROT13"
      │
      ▼
Decode: q3i3y0c3e_g00y5 → d3v3l0p3r_t00l5
      │
      ▼
curl /api/status -H "x-secret-token: d3v3l0p3r_t00l5"
      │
      ▼
200 OK → jctf{r0t_y0ur_w4y_t0_4cc3ss}
```
