import json
import socket
import time

HOST = "chals2.apoorvctf.xyz"
PORT = 13337

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(20.0)
    s.connect((HOST, PORT))
    f = s.makefile('rw')
    f.readline()  # Consume banner
    return s, f

def send_recv(f, msg_dict):
    f.write(json.dumps(msg_dict) + '\n')
    f.flush()
    line = f.readline()
    if not line:
        raise ConnectionError("Server memutus koneksi sepihak.")
    return json.loads(line)

def build_payload(ct_bytes, block_idx, byte_idx, guess, known_pt):
    prev_block = bytearray(ct_bytes[(block_idx-1)*16 : block_idx*16])
    target_block = ct_bytes[block_idx*16 : (block_idx+1)*16]
    
    pad_val = 16 - byte_idx
    prev_block[byte_idx] ^= guess ^ pad_val
    for i in range(byte_idx + 1, 16):
        prev_block[i] ^= known_pt[i] ^ pad_val
        
    return (prev_block + target_block).hex()

def solve_byte(f, ct_bytes, block_idx, byte_idx, known_pt):
    candidates = list(b"0123456789abcdef")
    scores = {c: 0 for c in candidates}
    
    phases = [(8, 8), (10, 4), (12, 2), (27, 1)]
    
    for k_pulls, keep in phases:
        for c in candidates:
            for _ in range(k_pulls):
                payload = build_payload(ct_bytes, block_idx, byte_idx, c, known_pt)
                res = send_recv(f, {"option": "unpad", "ct": payload})
                # Oracle bias: Valid padding mengembalikan False ~55% of the time
                if res.get("result") is False:
                    scores[c] += 1
        
        candidates.sort(key=lambda c: scores[c], reverse=True)
        candidates = candidates[:keep]
        
    return candidates[0]

def attempt_solve():
    s, f = connect()
    try:
        res_ct = send_recv(f, {"option": "encrypt"})
        ct_bytes = bytes.fromhex(res_ct["ct"])
        flag_hex = ""

        print("[*] Koneksi stabil! Memulai evaluasi noise padding oracle...")
        for block_idx in [1, 2]:
            known_pt = {}
            for byte_idx in range(15, -1, -1):
                c = solve_byte(f, ct_bytes, block_idx, byte_idx, known_pt)
                known_pt[byte_idx] = c
                print(f"[+] Block {block_idx} Byte {byte_idx}: {chr(c)}")
                
            flag_hex += "".join(chr(known_pt[i]) for i in range(16))

        print(f"[*] Secret message berhasil ditebak: {flag_hex}")
        final_res = send_recv(f, {"option": "check", "message": flag_hex})
        return final_res
    finally:
        s.close()

if __name__ == "__main__":
    attempt = 1
    while True:
        print(f"\n--- Attempt {attempt} ---")
        try:
            res = attempt_solve()
            if res and "flag" in res:
                print(f"\n[SUCCESS] Flag: {res['flag']}")
                break
            elif res and "error" in res:
                print(f"[!] Pesan dari server: {res['error']}")
        except ConnectionRefusedError:
            print("[!] Connection refused. Server mati atau kepenuhan.")
        except Exception as e:
            print(f"[!] Error / Terputus: {e}")
        
        print("[*] Jeda 3 detik sebelum retry agar tidak kena rate-limit...")
        time.sleep(3)
        attempt += 1
