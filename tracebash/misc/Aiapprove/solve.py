import socket
import re

host = "13.127.119.28"
port = 1339

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, port))
    
    # 1. Ambil banner awal dan ekstrak Encrypted Flag
    resp1 = s.recv(4096).decode('utf-8', errors='ignore')
    enc_flag_match = re.search(r'Encrypted flag:\s*([0-9a-f]+)', resp1)
    if not enc_flag_match:
        print("[-] Gagal mendapatkan Encrypted Flag. Coba lagi.")
        exit(1)
        
    enc_flag = enc_flag_match.group(1)
    print(f"[*] Remote Encrypted Flag : {enc_flag}")
    
    # 2. Kirim 16 byte '00' (32 karakter hex) untuk memancing Key keluar
    print("[*] Mengirim 32 nol untuk mencuri XOR key...")
    s.send(b"00000000000000000000000000000000\n")
    
    # 3. Tangkap Key dari response ciphertext server
    resp2 = s.recv(4096).decode('utf-8', errors='ignore')
    key_match = re.search(r'Ciphertext:\s*([0-9a-f]+)', resp2)
    if not key_match:
        print("[-] Gagal mendapatkan Key.")
        exit(1)
        
    key = key_match.group(1)[:32] # Ambil 16 byte (32 hex) pertama
    print(f"[*] Remote XOR Key        : {key}")
    
    # 4. Dekripsi Encrypted Flag dengan XOR Key
    flag_bytes = bytes.fromhex(enc_flag)
    key_bytes = bytes.fromhex(key)
    
    flag = "".join(chr(flag_bytes[i] ^ key_bytes[i % 16]) for i in range(len(flag_bytes)))
    print(f"\n[+] Misi Selesai. FLAG: {flag}")
