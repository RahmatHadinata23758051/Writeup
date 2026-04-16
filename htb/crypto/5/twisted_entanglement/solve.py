import random
from hashlib import sha256
from Crypto.Cipher import AES
from pwn import remote

# 1. Private Key yang kamu temukan
private_key = 3262827136301000405966

def solve():
    # --- TAHAP 1: Prediksi Basis Server ---
    random.seed(private_key)
    predicted_bases = ""
    for _ in range(256):
        r = random.randint(0, 1)
        predicted_bases += "Z" if r else "X"
    
    print(f"[*] Basis terprediksi: {predicted_bases[:30]}...")

    # --- TAHAP 2: Ambil Data dari Server ---
    io = remote('154.57.164.69', 31205)
    io.recvuntil(b"> ")
    io.sendline(b"2")
    io.sendlineafter(b"KEP: ", predicted_bases.encode())

    # Ambil User Key (Hex) dan Ciphertext
    io.recvuntil(b"The Quantum key: ")
    q_user_key_hex = io.recvline().decode().strip()
    io.recvuntil(b"Flag Encrypted: ")
    ciphertext_hex = io.recvline().decode().strip()
    
    print(f"[+] User Key Hex: {q_user_key_hex}")
    
    # --- TAHAP 3: Rekonstruksi Kunci Server ---
    # Konversi hex ke bits
    user_bytes = bytes.fromhex(q_user_key_hex)
    user_bits = []
    for b in user_bytes:
        user_bits.extend([int(x) for x in f"{b:08b}"])

    # Karena Singlet State + Basis Sama, Server Bit = NOT(User Bit)
    srv_bits = [1 - b for b in user_bits]
    
    # Hash bit server sesuai fungsi bitsToHash di util.py
    bit_string = ''.join([str(i) for i in srv_bits])
    blocks = bytes([int(bit_string[i:i + 8], 2) for i in range(0, len(bit_string), 8)])
    srv_aes_key = sha256(blocks).digest()

    # --- TAHAP 4: Dekripsi Flag ---
    ciphertext = bytes.fromhex(ciphertext_hex)
    cipher = AES.new(srv_aes_key, AES.MODE_ECB)
    flag = cipher.decrypt(ciphertext)

    print("\n" + "="*40)
    print(f"FLAG: {flag.decode(errors='ignore').strip()}")
    print("="*40)
    io.close()

if __name__ == "__main__":
    solve()
