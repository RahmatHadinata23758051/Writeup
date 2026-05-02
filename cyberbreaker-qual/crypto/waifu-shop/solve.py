import requests
import base64
import urllib3

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://waifu-shop.cbd2026.cloud"

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def solve():
    # 1. Get a valid token for 'enterprise_gold'
    print("[*] Getting token for 'enterprise_gold'...")
    resp = requests.post(f"{BASE_URL}/order", data={"item": "enterprise_gold"}, verify=False)
    
    # The token is in the HTML. I'll search for it.
    # <input type="hidden" name="order_token" value="...">
    import re
    match = re.search(r'name="order_token" value="([^"]+)"', resp.text)
    if not match:
        print("[-] Could not find token in response")
        return
    
    token = match.group(1)
    print(f"[*] Got token: {token}")
    
    # 2. Decode the token
    # urlsafe_b64decode needs padding
    ciphertext = base64.urlsafe_b64decode(token + '=' * (-len(token) % 4))
    
    # 3. Construct original plaintext
    # item=enterprise_gold&price=004800&buyer=guest&ship=standard
    original_plaintext = b"item=enterprise_gold&price=004800&buyer=guest&ship=standard"
    
    print(f"[*] Ciphertext length: {len(ciphertext)}")
    print(f"[*] Original plaintext length: {len(original_plaintext)}")
    
    if len(ciphertext) != len(original_plaintext):
        print("[-] Length mismatch!")
        return
    
    # 4. Derive keystream
    keystream = xor(ciphertext, original_plaintext)
    
    # 5. Construct target plaintext
    # item=celestial_waifu&price=000000&buyer=guest&ship=standard
    target_plaintext = b"item=celestial_waifu&price=000000&buyer=guest&ship=standard"
    
    # 6. Create new ciphertext
    new_ciphertext = xor(target_plaintext, keystream)
    
    # 7. Encode new token
    new_token = base64.urlsafe_b64encode(new_ciphertext).decode().rstrip('=')
    print(f"[*] New token: {new_token}")
    
    # 8. Claim the flag
    print("[*] Claiming flag...")
    resp = requests.post(f"{BASE_URL}/claim", data={"order_token": new_token}, verify=False)
    
    if "CBC{" in resp.text:
        flag = re.search(r'CBC\{[^}]+\}', resp.text).group(0)
        print(f"[+] Found flag: {flag}")
        print(f"<FLAG>{flag}</FLAG>")
    else:
        print("[-] Flag not found in response")
        print(resp.text)

if __name__ == "__main__":
    solve()
