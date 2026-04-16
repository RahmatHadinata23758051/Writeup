import base64
from Crypto.Cipher import AES
import string

flag_enc = "eVxqWrw1CbpuaDrQbREuBH3wWB8rgsNBDaPccxa4DvInlG5TfCYf5oyKhFPOLOtz"
key = b"encryptionkey123"

def caesar_shift(text, shift):
    result = ""
    for char in text:
        if char.islower():
            result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        elif char.isupper():
            result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        else:
            result += char
    return result

print("[*] Memulai Eksekusi: Caesar Salad + AES-128 Lattice")
print("="*55)

for shift in range(26):
    # 1. Caesar Shift pada string Base64
    shifted_b64 = caesar_shift(flag_enc, shift)
    
    try:
        # 2. Decode Base64 string yang sudah digeser
        data = base64.b64decode(shifted_b64)
    except:
        continue # Lewati jika hasil pergeseran bukan Base64 yang valid
        
    # 3. Definisikan kemungkinan mode AES (Lattice Key)
    modes = {
        "AES-ECB": AES.new(key, AES.MODE_ECB),
        "AES-CBC (Null IV)": AES.new(key, AES.MODE_CBC, iv=b'\x00'*16),
        "AES-CBC (Key=IV)": AES.new(key, AES.MODE_CBC, iv=key),
        "AES-CBC (Inline IV)": AES.new(key, AES.MODE_CBC, iv=data[:16]) if len(data) > 16 else None 
    }
    
    # 4. Uji semua mode tanpa memvalidasi padding (raw bytes attack)
    for mode_name, cipher in modes.items():
        if not cipher: continue
        try:
            if mode_name == "AES-CBC (Inline IV)":
                decrypted = cipher.decrypt(data[16:])
            else:
                decrypted = cipher.decrypt(data)
                
            # Cek apakah raw bytes mengandung format flag standar
            if b"flag{" in decrypted.lower() or b"ctf{" in decrypted.lower():
                print(f"[+] BINGO! Flag ditemukan!")
                print(f"    - Shift Caesar : {shift}")
                print(f"    - Mode Cipher  : {mode_name}")
                print(f"    - Raw Output   : {decrypted}")
                
        except Exception:
            pass

    # Fallback: Siapa tahu "Salad" maksudnya operasi byte XOR sederhana
    xor_dec = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
    if b"flag{" in xor_dec.lower() or b"ctf{" in xor_dec.lower():
         print(f"[+] BINGO! Flag ditemukan di XOR Fallback! (Shift: {shift})")
         print(f"    - Raw Output   : {xor_dec}")
