import json, math, random, sys
from pwn import *
from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long

HOST, PORT = 'chals2.apoorvctf.xyz', 13424
context.log_level = 'error'

def solve():
    io = remote(HOST, PORT)
    init_data = json.loads(io.recvline().decode())
    A, S_0 = init_data['lcg_params']['A'], init_data['lcg_params']['S_0']
    flag_ct = bytes.fromhex(init_data['flag_ct'])
    
    io.sendline(json.dumps({"option": "math_test", "data": 0}).encode())
    b = json.loads(io.recvline().decode())['result']

    print("[*] Mengambil sample p...")
    diffs = []
    for _ in range(5):
        x = random.randint(2**60, 2**64)
        io.sendline(json.dumps({"option": "math_test", "data": x}).encode())
        diffs.append(A * x + b - json.loads(io.recvline().decode())['result'])
    
    p = diffs[0]
    for d in diffs[1:]: p = math.gcd(p, d)
    
    if p.bit_length() != 32:
        print("[!] p tidak valid. Restart script.")
        return

    print(f"[+] Parameter Fix! p={p} (32 bits)")
    
    state = S_0
    # Karena kita kirim 48 byte, sisa byte setelah 8 byte pertama adalah 40 byte (320 bits)
    INV_2_320 = inverse(pow(2, 320), p)

    def lcg_oracle(test_iv, target_block):
        nonlocal state
        state = (A * state + b) % p
        
        # Payload 48-byte: [16 byte IV Dummy] + [16 byte test_iv] + [16 byte target]
        payload_base = b'\x00'*16 + bytes(test_iv) + target_block
        L = bytes_to_long(payload_base[8:])
        H_target = ((state - L) * INV_2_320) % p
        
        new_payload = long_to_bytes(H_target).rjust(8, b'\x00') + payload_base[8:]
        
        io.sendline(json.dumps({"option": "decrypt", "ct": new_payload.hex()}).encode())
        res = io.recvline()
        resp = json.loads(res.decode())
        
        if "error" in resp: return False
        return resp["oracle"] == "padding_ok"

    blocks = [flag_ct[i:i+16] for i in range(0, len(flag_ct), 16)]
    decrypted_full = b""
    charset = b"etaoinshrdlucmfwypvbgkqjxz{}0123456789_!?" + bytes(range(256))

    for b_idx in range(len(blocks) - 1, 0, -1):
        target, prev = blocks[b_idx], blocks[b_idx-1]
        dec_block = bytearray(16)
        print(f"\n[*] Cracking Block {b_idx}...")
        
        for i in range(15, -1, -1):
            pad = 16 - i
            test_iv = bytearray(16)
            for j in range(i + 1, 16): test_iv[j] = dec_block[j] ^ pad ^ prev[j]
            
            found = False
            for cand in charset:
                test_iv[i] = cand ^ pad ^ prev[i]
                if lcg_oracle(test_iv, target):
                    # --- TRAP PROTECTION ---
                    if i == 15:
                        test_iv[14] ^= 1 
                        is_still_ok = lcg_oracle(test_iv, target)
                        test_iv[14] ^= 1 
                        if not is_still_ok: continue 
                    
                    dec_block[i] = cand
                    found = True
                    print(f"\r  [+] {dec_block[i:].decode(errors='ignore')}", end="", flush=True)
                    break
                    
            if not found:
                print(f"\n[!] Gagal di byte {i}. Tidak ada kandidat cocok.")
                return
        decrypted_full = bytes(dec_block) + decrypted_full

    print(f"\n\nFLAG: {decrypted_full.decode(errors='ignore').strip()}")

if __name__ == "__main__": solve()
