from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

# Data dari capture.txt
p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031
iv = bytes.fromhex("fa919bb993a1befde685c90421595e27")
ciphertext = bytes.fromhex("534c708e7dd75a1b7ada5cb512d16bb2e8b6bf0df62b6f5e5df0e7e444fa46166426cb5a77d85b53032c3f959aeba907")

# Dua kemungkinan nilai shared secret karena B = p - 1
possible_shared_secrets = [1, p - 1]

print("[*] Menyerang Broken Trust Protocol...")

for shared in possible_shared_secrets:
    # Rekonstruksi key menggunakan sha256 seperti pada protocol.py
    key = sha256(str(shared).encode()).digest()[:16]
    
    try:
        # Dekripsi ciphertext
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        
        # Unpad flag
        flag = unpad(decrypted, 16)
        
        print(f"\n[+] Flag ditemukan (shared secret = {shared}):")
        print(flag.decode('utf-8'))
        break
    except (ValueError, KeyError):
        # Jika padding salah, lanjut ke kemungkinan berikutnya
        print(f"[-] Shared secret {shared} salah (Padding Error).")
