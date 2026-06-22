import requests

def solve():
    # Meniru rekonstruksi URL hasil analisis KPA (Known Plaintext Attack)
    # dari fungsi internal sym.connect() pada binary
    url_base = "https://files.catbox.moe/"
    file_id = "ymweyc"
    extension = ".txt"
    
    target_url = f"{url_base}{file_id}{extension}"
    print(f"[*] Mengunduh berkas flag tersembunyi dari: {target_url}\n")
    
    try:
        response = requests.get(target_url)
        if response.status_code == 200:
            print(response.text)
        else:
            print(f"[-] Gagal menghubungi server. Status Code: {response.status_code}")
    except Exception as e:
        print(f"[-] Terjadi error saat melakukan request: {e}")

if __name__ == '__main__':
    solve()
