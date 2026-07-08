import struct
import json
from pwn import *

# --- IMPLEMENTASI MURNI SHA-256 HLE ---
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def rright(val, n):
    return (val >> n) | ((val & ((1 << n) - 1)) << (32 - n))

def sha256_compress(state, chunk):
    w = list(struct.unpack(">16I", chunk)) + [0] * 48
    for i in range(16, 64):
        s0 = rright(w[i - 15], 7) ^ rright(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rright(w[i - 2], 17) ^ rright(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        s1 = rright(e, 6) ^ rright(e, 11) ^ rright(e, 25)
        ch = (e & f) ^ (~e & g)
        temp1 = (h + s1 + ch + K[i] + w[i]) & 0xFFFFFFFF
        s0 = rright(a, 2) ^ rright(a, 13) ^ rright(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 + maj) & 0xFFFFFFFF

        h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF

    return [(x + y) & 0xFFFFFFFF for x, y in zip(state, [a, b, c, d, e, f, g, h])]

def sha256_padding(msg_len):
    padding = b'\x80'
    padding += b'\x00' * ((56 - (msg_len + 1) % 64) % 64)
    padding += struct.pack(">Q", msg_len * 8)
    return padding

def hle_sha256(original_token_hex, original_msg, append_data, secret_length):
    state = [int(original_token_hex[i:i+8], 16) for i in range(0, 64, 8)]
    total_orig_len = secret_length + len(original_msg)
    pad = sha256_padding(total_orig_len)
    new_msg = original_msg + pad + append_data
    total_new_len = total_orig_len + len(pad) + len(append_data)
    data_to_hash = append_data + sha256_padding(total_new_len)
    
    for i in range(0, len(data_to_hash), 64):
        state = sha256_compress(state, data_to_hash[i:i+64])
        
    new_token = "".join(f"{x:08x}" for x in state)
    return new_token, new_msg

# --- MAIN EXPLOIT ---
def solve_hash_dash():
    host = '51.79.140.18'
    port = 13963
    
    # Kita ubah tebakan payload-nya ke parameter "admin"
    append_data = b"&admin=true" 
    secret_length = 16 # Langsung kunci di angka yang sudah pasti benar!
    
    context.log_level = 'error'

    print("[*] Mengirim payload HLE dengan admin=true...")
    
    try:
        r = remote(host, port)
        
        # Baca token fresh dari server
        raw_data = r.recvline().decode('utf-8').strip()
        server_data = json.loads(raw_data)
        
        original_msg = server_data["message"].encode()
        original_token = server_data["token"]
        
        # Hitung HLE
        new_token, new_msg = hle_sha256(original_token, original_msg, append_data, secret_length)
        
        # Bentuk payload
        payload = json.dumps({
            "msg": new_msg.hex(),
            "tag": new_token
        }).encode()

        # Kirim payload
        r.recvuntil(b'> ')
        r.sendline(payload)
        
        # Baca respons
        response = r.recvall(timeout=2).decode('utf-8', errors='ignore').strip()
        r.close()
        
        print(f"\n[+] Response Server:\n{response}")
            
    except Exception as e:
        print(f"[-] Gagal terkoneksi: {e}")

if __name__ == "__main__":
    solve_hash_dash()
