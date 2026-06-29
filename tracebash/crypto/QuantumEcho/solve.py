from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
import math

# 1. Load data dari file
with open("public1.pem", "r") as f:
    key1 = RSA.import_key(f.read())

with open("public2.pem", "r") as f:
    key2 = RSA.import_key(f.read())

with open("ciphertext.txt", "r") as f:
    # Membersihkan karakter '%' atau whitespace di ujung string jika ada
    c = int(f.read().strip().replace('%', ''))

n1, e1 = key1.n, key1.e
n2, e2 = key2.n, key2.e

print(f"[+] Key 1 Loaded: e1={e1}")
print(f"[+] Key 2 Loaded: e2={e2}")

# 2. Cek Kondisi 1: Common Modulus Attack (N sama, e berbeda)
if n1 == n2:
    print("[!] Mendeteksi: Common Modulus Attack!")
    n = n1
    
    # Algoritma Extended Euclidean untuk mencari nilai a dan b sehingga a*e1 + b*e2 = gcd(e1, e2)
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, a, b = extended_gcd(e1, e2)
    
    if gcd == 1:
        # Jika nilai a atau b negatif, kita gunakan modular inverse
        # c^a * c^b mod n
        # Jika a negatif, kita cari invers dari c mod n terlebih dahulu
        if a < 0:
            c1 = pow(c, -a, n)
            c1 = pow(c1, -1, n)  # Invers modular
        else:
            c1 = pow(c, a, n)
            
        if b < 0:
            c2 = pow(c, -b, n)
            c2 = pow(c2, -1, n)  # Invers modular
        else:
            c2 = pow(c, b, n)
            
        m = (c1 * c2) % n
        flag = long_to_bytes(m)
        print(f"\n[🎉] FLAG DITEMUKAN: {flag.decode(errors='ignore')}")
    else:
        print("[-] Gagal: GCD dari e1 dan e2 tidak bernilai 1.")

# 3. Cek Kondisi 2: Shared Prime Attack (N berbeda tapi berbagi faktor p yang sama)
else:
    print("[*] N1 dan N2 berbeda. Mengecek shared prime (GCD)...")
    p = math.gcd(n1, n2)
    
    if p > 1:
        print("[!] Mendeteksi: Shared Prime Attack (GCD Berhasil)!")
        # Mencari q untuk n1
        q1 = n1 // p
        phi1 = (p - 1) * (q1 - 1)
        
        # Mencari private key d untuk key 1
        try:
            d1 = pow(e1, -1, phi1)
            m = pow(c, d1, n1)
            flag = long_to_bytes(m)
            print(f"\n[🎉] FLAG DITEMUKAN: {flag.decode(errors='ignore')}")
        except ValueError:
            # Jika enkripsi menggunakan key 2
            q2 = n2 // p
            phi2 = (p - 1) * (q2 - 1)
            d2 = pow(e2, -1, phi2)
            m = pow(c, d2, n2)
            flag = long_to_bytes(m)
            print(f"\n[🎉] FLAG DITEMUKAN: {flag.decode(errors='ignore')}")
    else:
        print("[-] Metode otomatis gagal. Modulus tidak sama dan tidak berbagi faktor prima.")
