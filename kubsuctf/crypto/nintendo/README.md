# Nintendo 3DS - Crypto Challenge Writeup

## Challenge Description
The challenge title "Nintendo 3DS" and the hint "something very similar to Nintendo 3DS" strongly suggest the **3DES (Triple DES)** encryption algorithm.

## Analysis of `output.txt`
The file `output.txt` contained the following information:
- `CBC+PKCS5`: Indicates the mode (CBC) and padding (PKCS5).
- `1 = TjFudDNuZG8=` (Base64)
- `2 = 83 51 99 117 114 49 116 121` (Decimal ASCII)
- `3 = 4b33792132303236` (Hex)
- `ivx = 0a001f0273760054`
- `ivm = M4r10Br0`
- A long hex string (the ciphertext).

### Key Reconstruction
The 3DES key consists of three parts (K1, K2, K3), each 8 bytes long.
1. `K1 = base64_decode("TjFudDNuZG8=") = "NiNt3ndo"`
2. `K2 = bytes([83, 51, 99, 117, 114, 49, 116, 121]) = "S3cur1ty"`
3. `K3 = bytes.fromhex("4b33792132303236") = "K3y!2026"`
**Full Key:** `NiNt3ndoS3cur1tyK3y!2026`

### IV Reconstruction
The IV was derived from `ivx` and `ivm`:
- `ivx = 0a001f0273760054` (Hex)
- `ivm = "M4r10Br0"`
- `IV = ivx XOR ivm = "G4m3C4rd"`

## Solution Script
The following Python script was used to decrypt the ciphertext:

```python
from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad
import base64

# Key components
k1 = base64.b64decode("TjFudDNuZG8=")
k2 = bytes([83, 51, 99, 117, 114, 49, 116, 121])
k3 = bytes.fromhex("4b33792132303236")
key = k1 + k2 + k3

# IV components
ivx = bytes.fromhex("0a001f0273760054")
ivm = b"M4r10Br0"
iv = bytes([a ^ b for a, b in zip(ivx, ivm)])

# Ciphertext
ciphertext_hex = "072a8e75459a545679f3aa56a9fafb38871022de0c9bd5d7ef55e8dad7861662eb0fb630d9cdf9dd8c64a3a8ac28b86a"
ciphertext = bytes.fromhex(ciphertext_hex)

# Decryption
cipher = DES3.new(key, DES3.MODE_CBC, iv)
decrypted = cipher.decrypt(ciphertext)
plaintext = unpad(decrypted, 8)
print(f"Decrypted: {plaintext.decode()}")
```

## Flag
**KubSTU{3d3s_n1nt3nd0_cbc_m0d3_n07_h4rd_3n0ugh}**
