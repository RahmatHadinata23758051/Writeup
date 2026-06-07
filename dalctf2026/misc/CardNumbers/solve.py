import requests

def is_luhn_valid(n):
    r = [int(ch) for ch in str(n)][::-1]
    return (sum(r[0::2]) + sum(sum(divmod(d*2, 10)) for d in r[1::2])) % 10 == 0

url = "https://dalctf-card-numbers-204-64616c.instancer.dalctf2026.com/checksum"
prefix = "310488"

count = 0
for i in range(100000, 200000):
    # prefix (6 digit) + i berjarak 13 digit = 19 digit
    num_str = f"{prefix}{i:013d}"
    if is_luhn_valid(num_str):
        count += 1
        print(f"[*] Trying: {num_str} (Length: {len(num_str)})")
        res = requests.post(url, json={"number": num_str}).json()
        print(f"[-] Response: {res['message']}")
        
        # Jika ketemu pesan berbeda selain "not valid" atau "length", berarti jackpot
        if "not valid" not in res['message'] and "length" not in res['message']:
            print(f"[+] FOUND IT: {num_str} -> {res['message']}")
            break
        if count >= 5:
            break
