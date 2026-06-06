#!/usr/bin/env python3
from pwn import *
import ast

def solve():
    # 1. Koneksi ke server
    host = 'poached-anchovies-with-sliced-tahini-caii.gpn24.ctf.kitctf.de'
    port = 443
    log.info(f"Connecting to {host}:{port}...")
    r = remote(host, port, ssl=True)

    # 2. Skip sampai ke ciphertext 'c='
    r.recvuntil(b"c= ")
    c_line = r.recvline().decode().strip()
    c_vec = ast.literal_eval(c_line)
    log.success(f"Berhasil mengambil vector c dengan panjang {len(c_vec)}")

    # 3. Dekripsi instan dengan Celah Modulo 3
    # Mapping: -1 (2 mod 3) -> "A", 0 -> "C", 1 -> "B"
    MAPPING = {2: "A", 0: "C", 1: "B"}
    
    msg_guess = []
    for x in c_vec:
        sisa_bagi = x % 3
        msg_guess.append(MAPPING[sisa_bagi])
        
    pesan_asli = "".join(msg_guess)
    log.success(f"Pesan terekstrak instan: {pesan_asli}")

    # 4. Kirim dan ambil Flag!
    r.recvuntil(b"Give me the message:")
    r.sendline(pesan_asli.encode())
    
    response = r.recvall(timeout=3).decode()
    log.info("Response dari Server:\n" + response)

if __name__ == "__main__":
    solve()
