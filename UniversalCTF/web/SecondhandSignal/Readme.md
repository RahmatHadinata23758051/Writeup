# Writeup Web — Secondhand Signal

## Summary

Secondhand Signal is a web challenge about a message relay that uses browser-side Schnorr signatures. The application stores public keys and signed dispatch messages. The interesting part is that old public messages expose their signatures and canonical payloads, which makes it possible to analyze the signing scheme.

The bug is a reused Schnorr nonce. Two admin messages reuse the same commitment value `r`. Since Schnorr signatures are linear in the private key, two signatures with the same nonce are enough to recover the admin private key. After recovering the key, we can generate a valid login proof as admin and read the flag.

## Recon

The homepage exposes the crypto parameters inside `window.RelayAppConfig`. It contains `p`, `q`, and `g`, with `g = 4`. The page also shows that the application uses browser-held identities and signatures for dispatch traffic.

The login panel explains the Schnorr verification logic:

```text id="yyi2v3"
y = g^x mod p
choose random k in [1, q-1]
r = g^k mod p
e = H(y | r | payload) mod q
s = (k + e*x) mod q
```

The server verifies:

```text id="tmucaz"
g^s = r * y^e mod p
```

This means that if the same `r` is reused for two different payloads signed by the same user, the private key can be recovered.

The JavaScript confirms how the hash and payload are built. The hash function uses SHA-256 over `parts.join("|")`, then reduces it modulo `q`.

The message payload format is:

```text id="gweq4k"
message
from=<sender>
visibility=<visibility>
to=<recipient>
signed_at=<signedAt>
body=<body>
```

This format is defined directly in `messagePayload()`.

The signing function then computes:

```text id="kxabwx"
nonce = H("nonce", privateKey, payload)
r = g^nonce mod p
e = H(publicKey, r, payload)
s = nonce + e * privateKey mod q
```

This is visible in `signBrowserPayload()`.

## Finding the Weak Signatures

The public board contains multiple public messages, including messages from `admin`. Message IDs 14 and 15 are both from `admin`, have the same timestamp, and are visible on the public board.

When viewing the detail pages for messages 14 and 15, both expose their canonical payload. The important detail is that both messages have the same `signed_at` value and the same commitment `r`.

Message 14 canonical payload:

```text id="d6z5wp"
message
from=admin
visibility=public
to=
signed_at=1772302338
body=Dispatch keys remain local. Do not export them to relay storage.
```

Message 15 canonical payload:

```text id="y03deo"
message
from=admin
visibility=public
to=
signed_at=1772302338
body=Shift overlap is live. Any signer alert from 18:12 stays noisy until review.
```

The important point is that `to=` is empty for public messages, even though the UI displays the recipient as “public board”. The exploit must use the canonical payload exactly, not the rendered UI text.

## Vulnerability

Schnorr signatures have this form:

```text id="k64900"
s = k + e*x mod q
```

For two signatures from the same private key `x` with the same nonce `k`:

```text id="cylkbx"
s1 = k + e1*x mod q
s2 = k + e2*x mod q
```

Subtracting them removes the nonce:

```text id="o28539"
s1 - s2 = (e1 - e2) * x mod q
```

So the private key is:

```text id="ybwo4e"
x = (s1 - s2) * inverse(e1 - e2, q) mod q
```

Because messages 14 and 15 reuse the same `r`, they also reuse the same nonce. This allows recovering the admin private key.

## Exploit Flow

The exploit performs these steps:

1. Fetch the homepage and parse `p`, `q`, and `g`.
2. Fetch the admin profile and parse the admin public key.
3. Fetch message 14 and message 15.
4. Extract the signature pair `(r, s)` and canonical payload from each message.
5. Confirm that both messages reuse the same `r`.
6. Compute `e14 = H(admin_y, r, payload14)` and `e15 = H(admin_y, r, payload15)`.
7. Recover the admin private key with:

```python id="dqpsel"
x = ((s14 - s15) * pow((e14 - e15) % q, -1, q)) % q
```

8. Verify the recovered key:

```python id="foi6nf"
pow(g, x, p) == admin_y
```

9. Request a login challenge for `admin`.
10. Sign the challenge payload using the recovered private key.
11. Submit the signed proof and log in as admin.
12. Visit the homepage and read the flag.

## Result

The recovered admin private key was valid:

```text id="d2c9wf"
[+] key valid: True
```

After signing the admin login challenge, the server accepted the proof:

```text id="qfbosi"
[+] login: 200 {"ok":true,"redirect":"/index.php?page=home"}
```

The flag appeared after logging in as admin:

```text id="l1he30"
uctf{86eef8532e377be299678f89651db20ac179}
```

## Flag

```text id="swwlmj"
uctf{86eef8532e377be299678f89651db20ac179}
```
