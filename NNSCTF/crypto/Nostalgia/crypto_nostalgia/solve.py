from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
import time

# Ciphertext target dari chall.py
ct_hex = '85c43735b8442a69843bdc2ca0fb2d41eb548057c43b912704abdf2e27a8d8bc97017ec30b5d100498f12183c9e2ebed'
ct = bytes.fromhex(ct_hex)

def lcg(s):
    return (16843009 * int(s) + 826366247) % (2**32)

print("[*] Memulai pencarian seed...")

# Perkiraan timestamp (misal dari rentang beberapa tahun ke belakang hingga saat ini)
# Anda bisa menyesuaikan rentang waktu ini jika tahu kapan chall dibuat.
end_time = int(time.time())
start_time = end_time - 86400 * 30  # 30 hari ke belakang sebagai contoh awal

for base_t in range(end_time, start_time, -1):
    # Karena time.time() memiliki presisi desimal, kita bisa coba beberapa variasi milidetik/mikrodetik 
    # atau mengecek bagian integer-nya terlebih dahulu jika seed dikonversi ke int di lcg().
    # Di lcg(s): int(s), jadi bagian desimal terabaikan di awal pemanggilan!
    
    seed = float(base_t)
    for _ in range(1337):
        seed = lcg(seed)
    
    key = sha256(str(seed).encode()).digest()
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(ct), AES.block_size)
        if decrypted.startswith(b'NNS{'):
            print(f"[+] BERHASIL! Timestamp: {base_t}")
            print(f"[+] Flag: {decrypted.decode()}")
            break
    except Exception:
        continue
else:
    print("[-] Seed tidak ditemukan dalam rentang waktu tersebut. Perlu memperluas range waktu.")
