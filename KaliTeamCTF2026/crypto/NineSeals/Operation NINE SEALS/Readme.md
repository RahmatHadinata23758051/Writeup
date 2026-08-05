# Operation NINE SEALS - Crypto Writeup

## Challenge Information

| Field | Value |
|------|------|
| Category | Crypto |
| Challenge | Operation NINE SEALS |

### Description

> Recovered from a dead research host: a stripped binary, a 150MB memory dump, and a public key. Nine seals guard the record — only three are real. Chain them.

---

# Given Files

```
archive.bin
arcomega_ref
enc_aes_key.bin
flag.bin
rsa_pub.txt
signal.png
```

The challenge provides several files, but only three are required for the real cryptographic solve:

- `rsa_pub.txt`
- `enc_aes_key.bin`
- `flag.bin`

The remaining files (`archive.bin`, `arcomega_ref`, and `signal.png`) mainly serve as hints and decoys.

---

# Initial Recon

List the files:

```bash
ls -lh
file *
```

Inspect the RSA public key:

```bash
cat rsa_pub.txt
```

The public key contains:

```
N = 22809372564632431956344838558771942450598371846217962326535730103915001241315815033212323134290346471474056891958291602757667646665833193690583344295372476990143702827655290319448752811980463218963383500530195835501085453862931445627659951234071312304062320618445927999875641704737916544067817158903763694913224000489152705308556768000332719438290112493878473175618631654931478292115338412655576667549199738302510701146129077640293331657834587476070352997821273202433497408470398053271862236983983630959535423878658275969947503465791000316751734773139813847583583413116390028745219630170973961159414781638930191516589

e = 65537
```

Check the remaining important files:

```bash
ls -lh enc_aes_key.bin flag.bin rsa_pub.txt
```

Expected sizes:

```
enc_aes_key.bin   256 bytes
flag.bin           83 bytes
rsa_pub.txt       632 bytes
```

A 256-byte RSA ciphertext strongly suggests a 2048-bit RSA key.

---

# Decoy Path — `signal.png`

The PNG contains metadata hidden inside a `tEXt` chunk.

Extract it with:

```python
from pathlib import Path

raw = Path("signal.png").read_bytes()

pos = 8
while pos < len(raw):
    n = int.from_bytes(raw[pos:pos+4], "big")
    typ = raw[pos+4:pos+8]
    data = raw[pos+8:pos+8+n]

    if typ == b"tEXt":
        print(data.decode(errors="ignore"))

    pos += 12 + n
```

The image also contains a Vigenère-style ciphertext.

Using the key:

```
seal
```

produces:

```
THE NINE SEALS ARE BROKEN.
THE FLAG IS

KaliTeam{v1g3n3r3_w4s_nev3r_th3_r34l_ch4ll3ng3}

PRESENT THIS TO THE JUDGES FOR YOUR POINTS.
```

However, this flag is **rejected**.

The sentence itself hints that the Vigenère puzzle is only a distraction.

---

# Real Vulnerability

The actual weakness lies in the RSA modulus.

For RSA:

```
N = p × q
```

If the prime factors are extremely close together, Fermat Factorization becomes trivial.

Fermat expresses the modulus as:

```
N = a² − b²
```

where

```
a = ceil(sqrt(N))
b² = a² − N

p = a − b
q = a + b
```

Normally, several iterations are required before `a² − N` becomes a perfect square.

In this challenge, the very first value already satisfies the condition.

Therefore, the modulus can be factored almost instantly.

---

# Recovering the Private Key

Once the factors are known:

```
φ(N) = (p − 1)(q − 1)

d = e⁻¹ mod φ(N)
```

The recovered private key is then used to decrypt the RSA-encrypted AES key via OAEP (SHA-256).

The resulting AES key decrypts `flag.bin`, which is encrypted using AES-GCM.

The file layout is:

```
12 bytes  -> nonce
16 bytes  -> authentication tag
remaining -> ciphertext
```

---

# Solver

```python
from pathlib import Path
import re
import math

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256

pub = Path("rsa_pub.txt").read_text()

N = int(re.search(r"N\s*=\s*(\d+)", pub).group(1))
e = int(re.search(r"e\s*=\s*(\d+)", pub).group(1))

# Fermat factorization
a = math.isqrt(N)
if a * a < N:
    a += 1

b2 = a * a - N
b = math.isqrt(b2)

if b * b != b2:
    raise SystemExit("Fermat factorization failed")

p = a - b
q = a + b

print("[+] Fermat factorization success")

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

rsa_key = RSA.construct((N, e, d, p, q))

enc_key = Path("enc_aes_key.bin").read_bytes()

aes_key = PKCS1_OAEP.new(
    rsa_key,
    hashAlgo=SHA256
).decrypt(enc_key)

print("[+] AES key:", aes_key.hex())

flag_data = Path("flag.bin").read_bytes()

nonce = flag_data[:12]
tag = flag_data[12:28]
ciphertext = flag_data[28:]

cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
flag = cipher.decrypt_and_verify(ciphertext, tag)

print("[+] FLAG:", flag.decode())
```

---

# Result

Running the solver:

```bash
python3 solve_final.py
```

Output:

```
[+] Fermat factorization success
[+] p bits: 1024
[+] q bits: 1024
[+] AES key: ...
[+] FLAG: KaliTeam{l4tt1c3_r3v3rs1ng_4nd_f3rm4t_4ll_4t_0nc3_9001}
```

---

# Flag

```text
KaliTeam{l4tt1c3_r3v3rs1ng_4nd_f3rm4t_4ll_4t_0nc3_9001}
```

---

