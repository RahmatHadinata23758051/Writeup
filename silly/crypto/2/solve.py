from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
import gmpy2

# 1. Load Public Key
with open("challenge.pub", "r") as f:
    key = RSA.import_key(f.read())

n = key.n
e = key.e
ciphertext = 16180705626253079377831812490700

print(f"[+] Modulus (n): {n}")
print(f"[+] Exponent (e): {e}")

# 2. Faktorisasi n (Karena n sangat kecil, kita bisa gunakan root)
# Menggunakan iroot untuk mengecek apakah n adalah prima atau hasil kali p*q
# Namun cara paling mudah untuk n kecil adalah pemfaktoran sederhana
def factorize(n):
    # Mencoba mencari p dengan akar kuadrat n
    p = gmpy2.iroot(n, 2)[0]
    while n % p != 0:
        p -= 1
    return int(p), int(n // p)

p, q = factorize(n)
print(f"[+] Found Factors: \n    p: {p} \n    q: {q}")

# 3. Hitung Private Key
phi = (p - 1) * (q - 1)
d = int(gmpy2.invert(e, phi))

# 4. Decrypt Ciphertext
# Formula: m = c^d mod n
message_int = pow(ciphertext, d, n)
flag = long_to_bytes(message_int).decode()

print(f"\n[!] Flag: sillyCTF{{{flag}}}")
