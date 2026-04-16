def rc4(key, data):
    S = list(range(256))
    j = 0
    out = []

    # KSA (Key Scheduling Algorithm)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA (Pseudo-Random Generation Algorithm)
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        out.append(byte ^ k)

    return bytes(out)

# Pengaturan berdasarkan hasil Radare2 lo tadi
FILE_PATH = "infohazard"
KEY = b"infohazard"
FLAG_OFFSET = 0x102380  # paddr dari obj.encrypted_flag_png
FLAG_LEN = 2673         # dari obj.encrypted_flag_png_len

try:
    with open(FILE_PATH, "rb") as f:
        f.seek(FLAG_OFFSET)
        encrypted_data = f.read(FLAG_LEN)

    print("[*] Melakukan dekripsi RC4...")
    decrypted_png = rc4(KEY, encrypted_data)

    with open("recovered_flag.png", "wb") as f:
        f.write(decrypted_png)
    
    print("[+] Sukses! Flag disimpan di: recovered_flag.png")

except Exception as e:
    print(f"[-] Error: {e}")
