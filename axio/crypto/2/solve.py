import hashlib
from Crypto.Cipher import AES

# Data dari tahap sebelumnya
d = 0xc5ca80fe511a1f34567a4d5ef3ce046f5dd7016280fd37c0d3f3b6feffafe883
ct_hex = "5dda446bb9a9bbef3f34b999a2da8e0b6bc64735f7322cbacfc0b4c726fd2d0441"
ct = bytes.fromhex(ct_hex)

# Menyiapkan kemungkinan kunci (d_bytes langsung atau di-hash)
d_bytes = d.to_bytes(32, "big")
d_hash = hashlib.sha256(d_bytes).digest()
d_str_hash = hashlib.sha256(str(d).encode()).digest()

keys = [d_bytes, d_hash, d_str_hash]

print("[*] Memulai percobaan dekripsi AES dan XOR...")
found = False

for key in keys:
    # 1. Uji coba XOR sederhana
    pt_xor = bytes([a ^ b for a, b in zip(ct, key)])
    if b"axiom{" in pt_xor:
        print(f"\n[+] BERHASIL (XOR)!")
        print(f"[+] Flag: {pt_xor.decode('ascii', errors='ignore')}")
        found = True
        
    # 2. Uji coba AES-ECB
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        pt_aes = cipher.decrypt(ct)
        if b"axiom{" in pt_aes:
            print(f"\n[+] BERHASIL (AES-ECB)!")
            # Bersihkan padding jika ada
            print(f"[+] Flag: {pt_aes.decode('ascii', errors='ignore').strip()}")
            found = True
    except Exception:
        pass

if not found:
    print("[-] Flag tidak ditemukan dengan metode standar.")
