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
try:
    decrypted = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted, 8)
    print(f"Decrypted: {plaintext.decode()}")
except Exception as e:
    print(f"Error: {e}")
    print(f"Decrypted (raw): {decrypted.hex()}")
