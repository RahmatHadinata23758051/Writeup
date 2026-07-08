LYKNCTF 2026 Writeup: Hash & Dash

Challenge Name: Hash & Dash
Category: Crypto
Tags: Hash Length Extension Attack (HLE), SHA-256, Merkle-Damgård, Python
Flag: LYKNCTF{d252dd0610d9402fb18addbcb970f67d}

Overview

In this challenge, we are provided with a netcat service (nc 51.79.140.18 17896) that acts as a tiny access-token service. Upon connecting, the server gives us a JSON object containing a message, its hex representation, and a valid guest token:

{"message": "user=guest&role=viewer", "message_hex": "757365723d677565737426726f6c653d766965776572", "token": "1fb8b6844df355ffbfcaaf436b2a35e78ced80adbe054ae943bf903533851e93"}


The goal is to submit a valid token for a modified message that grants "admin access".

Vulnerability Analysis

The token provided is exactly 64 characters long in hexadecimal, which corresponds to 256 bits. This strongly indicates the use of the SHA-256 hashing algorithm.

The service appears to be generating tokens using a vulnerable MAC (Message Authentication Code) construction:
MAC = SHA-256(secret_key || message)

Because SHA-256 is based on the Merkle-Damgård construction, it processes messages in blocks and maintains an internal state. If an attacker knows the length of the secret_key and the final hash (token) of the original message, they can use that hash as the starting state to append new data to the message and calculate a valid new hash—without ever knowing the actual secret key.

This vulnerability is known as a Hash Length Extension Attack (HLE).

The Dynamic Token Twist

Initially, one might try to compute the forged token offline and manually submit it. However, the server generates a new, dynamic token every time a connection is established. This means the exploit must be fully automated: the script must connect, read the active token, forge the payload, and submit it within a single session.

Python 3.12 Compatibility Issues

Standard HLE tools and libraries like hashpumpy or hlextend often rely on legacy C-extensions that fail to compile or run on modern Python 3.12 environments (throwing SystemError: PY_SSIZE_T_CLEAN). To bypass this, we can implement the SHA-256 compression function and padding logic entirely in pure Python.

The Application Logic Flaw

Once the cryptographic hurdle is bypassed, we need to determine the correct payload to escalate privileges. Appending &role=admin results in a valid token, but the server responds with:
{"ok": true, "admin": false, "error": "token valid but no admin grant"}

This reveals a secondary logic puzzle: the server isn't looking for role=admin, but rather a specific boolean/flag parameter indicating admin status. By changing our appended data to &admin=true, the server grants access and returns the flag.

During the exploit development, we also dynamically brute-forced the unknown length of the secret_key, which turned out to be exactly 16 bytes.

Solution (Exploit Script)

Below is the final, pure-Python exploit script that connects to the server, parses the dynamic token, performs the Hash Length Extension attack on the fly (assuming a secret length of 16), and grabs the flag.

import struct
import json
from pwn import *

# --- PURE PYTHON SHA-256 HLE IMPLEMENTATION ---
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
    port = 17896
    
    append_data = b"&admin=true"
    secret_length = 16 
    
    context.log_level = 'error'
    print("[*] Sending HLE payload with admin=true...")
    
    try:
        r = remote(host, port)
        
        # Parse dynamic server data
        raw_data = r.recvline().decode('utf-8').strip()
        server_data = json.loads(raw_data)
        
        original_msg = server_data["message"].encode()
        original_token = server_data["token"]
        
        # Calculate HLE
        new_token, new_msg = hle_sha256(original_token, original_msg, append_data, secret_length)
        
        # Build JSON payload
        payload = json.dumps({
            "msg": new_msg.hex(),
            "tag": new_token
        }).encode()

        # Send payload and retrieve response
        r.recvuntil(b'> ')
        r.sendline(payload)
        
        response = r.recvall(timeout=2).decode('utf-8', errors='ignore').strip()
        r.close()
        
        print(f"\n[+] Server Response:\n{response}")
            
    except Exception as e:
        print(f"[-] Connection failed: {e}")

if __name__ == "__main__":
    solve_hash_dash()
