import base64
from Crypto.Cipher import DES

# 1. Grab the ciphertext from output.txt
ciphertext_b64 = "T/tGpZNyHdhnf1oxwRmMPFcLiH//AfZdTpmYdp8daU0="
ciphertext = base64.b64decode(ciphertext_b64)

# 2. Use the exact same key
key = bytes.fromhex("E1E1E1E1F0F0F0F0")

# 3. Initialize DES in ECB mode
cipher = DES.new(key, DES.MODE_ECB)

# 4. Encrypting the ciphertext decrypts it due to the weak key property
plaintext_padded = cipher.encrypt(ciphertext)

# 5. Clean up the padding
flag = plaintext_padded.rstrip(b"*")
print(flag.decode())
