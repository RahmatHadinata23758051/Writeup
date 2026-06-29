import binascii

def custom_sbox(val):
    return ((val ^ 0x5A) + 0x33) % 256

def decrypt(ciphertext, seed_a, seed_b):
    state_a = seed_a
    state_b = seed_b
    plaintext = bytearray()

    for byte in ciphertext:
        clock_steps = (state_a & 0x0F) + 1
        for _ in range(clock_steps):
            feedback = ((state_b >> 7) ^ (state_b >> 5) ^ (state_b >> 2) ^ (state_b >> 1)) & 1
            state_b = ((state_b << 1) | feedback) & 0xFF

        state_a = custom_sbox(state_a ^ state_b)

        keystream_byte = custom_sbox(state_b) ^ state_a
        plaintext.append(byte ^ keystream_byte)

    return plaintext

# Ciphertext dari deskripsi soal
ct_hex = "1ad9756e666a336be1388c7d132c0a83aecfb9735366374196e187f78e38ece6"
ciphertext = binascii.unhexlify(ct_hex)

print("[*] Memulai Brute Force 16-bit Keyspace...")

# Brute force semua kemungkinan seed_a dan seed_b (0-255)
found = False
for seed_a in range(256):
    for seed_b in range(256):
        decrypted = decrypt(ciphertext, seed_a, seed_b)
        
        # Validasi header flag yang dicari
        if decrypted.startswith(b"TBCTF{"):
            print(f"\n[+] Flag ditemukan!")
            print(f"[+] Seed A: {seed_a} | Seed B: {seed_b}")
            print(f"[+] Plaintext: {decrypted.decode('utf-8', errors='ignore')}")
            found = True
            break
    if found:
        break
