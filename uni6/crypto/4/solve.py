def vigenere_decrypt(ciphertext, key):
    key = key.lower()
    key_length = len(key)
    key_as_int = [ord(k) - ord('a') for k in key]
    
    plaintext = ""
    key_idx = 0
    
    for char in ciphertext:
        if char.isalpha():
            # Tentukan apakah huruf besar atau kecil
            base = ord('a') if char.islower() else ord('A')
            
            # Rumus dekripsi Vigenere: (Cipher - Key) mod 26
            shift = key_as_int[key_idx % key_length]
            decrypted_char = chr((ord(char) - base - shift) % 26 + base)
            
            plaintext += decrypted_char
            key_idx += 1  # Indeks kunci hanya maju kalau ketemu huruf
        else:
            # Angka dan simbol dibiarkan apa adanya
            plaintext += char
            
    return plaintext

def solve():
    ciphertext = "grt6{gbkblzbb_mr_wpqucfw}"
    key = "melody"
    
    print("[*] Memulai dekripsi Vigenère...")
    print(f"[*] Ciphertext : {ciphertext}")
    print(f"[*] Kunci      : {key}")
    
    flag = vigenere_decrypt(ciphertext, key)
    
    print(f"\n[✔] Alunan melodi berhasil dipecahkan:")
    print(f"--> FLAG: {flag}")

if __name__ == "__main__":
    solve()
