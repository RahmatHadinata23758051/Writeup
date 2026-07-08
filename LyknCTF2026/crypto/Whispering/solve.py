import requests
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import unpad

# Ganti dengan URL instance-mu
BASE_URL = "http://257b4d35-2463-4079-b6a7-3b941a58e977.51.79.140.18.nip.io:8080"

print("[*] Fetching data dari server...")
public_data = requests.get(f"{BASE_URL}/public.json").json()
side_channel = requests.get(f"{BASE_URL}/side_channel.json").json()

# Ekstrak parameter publik
N = public_data["parameters"]["N"]
q = public_data["parameters"]["q"]
q_prime = public_data["parameters"]["q_prime"]

enc_flag = public_data["encrypted_flag"]
ciphertext = bytes.fromhex(enc_flag["ciphertext"])
iv = bytes.fromhex(enc_flag["iv"])
salt = enc_flag["salt"]

# Ekstrak side channel leakage
constraints = side_channel["constraints"]
f_even_mod = constraints["f_even_sum_mod_127"]
f_odd_mod = constraints["f_odd_sum_mod_127"]
g_even_mod = constraints["g_even_sum_mod_127"]
g_odd_mod = constraints["g_odd_sum_mod_127"]

def center_lift(val, mod=127):
    # Mengembalikan nilai asli ke rentang [-63, 64]
    return val - mod if val > mod // 2 else val

# Rekonstruksi nilai sum asli
f_even = center_lift(f_even_mod)
f_odd = center_lift(f_odd_mod)
g_even = center_lift(g_even_mod)
g_odd = center_lift(g_odd_mod)

sum_f = f_even + f_odd
sum_g = g_even + g_odd

# Hitung nilai V (algebraic signature) langsung!
V = (sum_f * sum_g) % q_prime
print(f"[+] Recovered V (Algebraic Signature): {V}")

# Rekonstruksi HKDF Key derivation sesuai server
ikm = (
    V.to_bytes(4, "big")
    + N.to_bytes(2, "big")
    + q.to_bytes(2, "big")
    + salt.encode("utf-8")
)

key = HKDF(
    master=ikm,
    key_len=32,
    salt=str(N).encode("utf-8"),
    hashmod=SHA256,
)

# Dekripsi ciphertext flag
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(ciphertext)

try:
    flag = unpad(decrypted, AES.block_size).decode()
    print(f"\n[+] FLAG FOUND: {flag}")
except Exception as e:
    print(f"[-] Gagal melakukan unpadding, kemungkinan key salah: {e}")
