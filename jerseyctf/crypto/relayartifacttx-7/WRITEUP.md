# CTF Writeup — Relay Artifact TX-7

**Event:** JerseyCTF  
**Category:** Crypto  
**Difficulty:** Medium  
**Flag:** `JCTF{INDIRECT_CONTROL_IS_THE_ONLY_CONTROL}`

---

## Challenge Description

> Relay node TX-7 was recovered from a decommissioned corridor between the outer and inner system. Diagnostics show it prepared a final transmission but never sent it - the relay restrained itself. Reconstruct what TX-7 was trying to say; its last unsent message may point toward the only viable route inward.

**Files:**
- `relay_pub.pem`
- `relay_diag.json`
- `relay_notes.log`
- `tx_fragment.bin`
- `unsent_notice.log`

---

## Reconnaissance

### Step 1 — Basic Artifact Review

```bash
ls -la
```

Interesting clues:
- `relay_pub.pem` contains an RSA public key.
- `tx_fragment.bin` size is 384 bytes (matches RSA-3072 ciphertext length).
- `relay_diag.json` has a huge hex field: `relay_fingerprint`.
- `relay_notes.log` explicitly says: **"Prime reuse flagged but ignored."**

### Step 2 — Inspect RSA Public Key

```bash
openssl rsa -pubin -in relay_pub.pem -text -noout
```

Result summary:
- Public key is ~3072-bit RSA
- Exponent `e = 65537`

### Step 3 — Identify the Crypto Weakness

The log hints at weak entropy and prime reuse. A common failure pattern:
- target modulus `n = p*q`
- another value accidentally shares one prime (e.g. also divisible by `p`)
- then `gcd(n, other_value) = p`

`relay_diag.json` contains `relay_fingerprint`, a 3072-bit integer-like hex blob, perfect candidate for GCD attack.

---

## Exploitation

### Step 4 — Recover Prime via GCD

```python
from Crypto.PublicKey import RSA
from math import gcd
import json

key = RSA.import_key(open("relay_pub.pem", "rb").read())
n = key.n
f = int(json.load(open("relay_diag.json"))["relay_fingerprint"], 16)

p = gcd(n, f)
q = n // p
```

This produced a non-trivial factor (`1 < p < n`), so factorization succeeded instantly.

### Step 5 — Rebuild Private Exponent and Decrypt

```python
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

ct = open("tx_fragment.bin", "rb").read()
c = int.from_bytes(ct, "big")
m = pow(c, d, n)
```

The decrypted block starts with `00 02 ... 00`, indicating **PKCS#1 v1.5 encryption padding**. After removing padding, plaintext is readable text containing the flag.

### Step 6 — Extract Flag

Recovered plaintext includes:

```
Relay Transmission — UNSENT
...
JCTF{INDIRECT_CONTROL_IS_THE_ONLY_CONTROL}
```

---

## Flag

```
JCTF{INDIRECT_CONTROL_IS_THE_ONLY_CONTROL}
```

---

## Vulnerability Summary

| # | Technique | Detail |
|---|---|---|
| 1 | **RSA Prime Reuse / Shared Factor** | `relay_fingerprint` shares a prime with public modulus `n`, enabling `gcd(n, fingerprint)` attack |
| 2 | **Deterministic Private-Key Recovery** | Once `p,q` are known, compute `d` and decrypt ciphertext directly |

---

## Tools Used

- `openssl` — inspect RSA public parameters
- Python (`pycryptodome`, `math.gcd`, `json`, `re`) — factor recovery and decryption
- `xxd` / shell utils — artifact inspection

---

## Attack Flow

```
relay_pub.pem + relay_diag.json + tx_fragment.bin
                │
                ▼
Extract n,e and relay_fingerprint
                │
                ▼
p = gcd(n, relay_fingerprint)
                │
                ▼
q = n/p, phi = (p-1)(q-1), d = e^{-1} mod phi
                │
                ▼
RSA decrypt tx_fragment.bin
                │
                ▼
PKCS#1 v1.5 unpad
                │
                ▼
JCTF{INDIRECT_CONTROL_IS_THE_ONLY_CONTROL}
```

---

## Installation

```bash
# Optional: activate provided environment
source /home/nata/ctf_env/bin/activate

# Run solver
python3 solve.py
```
