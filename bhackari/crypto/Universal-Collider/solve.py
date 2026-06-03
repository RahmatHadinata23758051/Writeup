#!/usr/bin/env python3
import hashlib
import os
import subprocess
from pwn import *

def generate_128_collisions():
    bin_path = "./fastcoll_bin"
    if not os.path.exists(bin_path):
        print(f"[-] Binary '{bin_path}' tidak ditemukan!")
        exit(1)
        
    print("[*] Membuat prefix 64-byte (0xFF) untuk mencegah integer byte-shifting...")
    with open("init.bin", "wb") as f:
        f.write(b"\xff" * 64)
        
    print("[*] Memulai Joux Multicollision (7 iterasi)... (Butuh waktu ~15-30 detik)")
    
    subprocess.run([bin_path, "-p", "init.bin", "-o", "c0a.bin", "c0b.bin"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open("c0a.bin", "rb") as f: a = f.read()
    with open("c0b.bin", "rb") as f: b = f.read()
    
    blocks = [a, b]
    
    for i in range(1, 7):
        print(f"[*] Generasi rantai layer {i+1}/7...")
        with open("prefix.bin", "wb") as f: 
            f.write(blocks[0])
            
        subprocess.run([bin_path, "-p", "prefix.bin", "-o", "ca.bin", "cb.bin"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        with open("ca.bin", "rb") as f: tail_a = f.read()[-128:]
        with open("cb.bin", "rb") as f: tail_b = f.read()[-128:]
        
        next_blocks = []
        for blk in blocks:
            next_blocks.append(blk + tail_a)
            next_blocks.append(blk + tail_b)
        blocks = next_blocks
        
    os.system("rm -f init.bin c0a.bin c0b.bin prefix.bin ca.bin cb.bin")
    print(f"[+] {len(blocks)} Multicollision berhasil dibuat!")
    return [int.from_bytes(b, 'big') for b in blocks]

# --- LCG (PRNG) EXPLOIT ---
A = 1664525
C = 1013904223
M = 1 << 48

def find_top_bits(target_md5):
    for i in range(1 << 24):
        b = max(1, (i.bit_length() + 7) // 8)
        if hashlib.md5(i.to_bytes(b, 'big')).hexdigest() == target_md5:
            return i
    return None

def crack_lcg(top0, top1, md5_2_str):
    print("[*] Memverifikasi kandidat LCG State dengan MD5 ketiga (Akurasi 100%)...")
    for bottom in range(1 << 24):
        state = (top0 << 24) | bottom
        next_state = (A * state + C) % M
        
        # Jika top1 cocok, JANGAN LANGSUNG DIAMBIL! Verifikasi lagi dengan top2.
        if (next_state >> 24) == top1:
            next_next_state = (A * next_state + C) % M
            cand_top2 = next_next_state >> 24
            b = max(1, (cand_top2.bit_length() + 7) // 8)
            if hashlib.md5(cand_top2.to_bytes(b, 'big')).hexdigest() == md5_2_str:
                return state
    return None

def main():
    COLLISIONS = generate_128_collisions()
    
    print("\n[*] Menghubungkan ke server CTF...")
    io = remote("collider.challs.ctf.bhackari.it", 10002)

    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(b"Enter the expression (only: x, digits, + - * / % ^): ")
    io.sendline(b"x//16777216")

    io.recvuntil(b"> ")
    io.sendline(b"3")
    
    # Teknik Parsing Super Aman
    io.recvuntil(b"[OK] Common digest = ")
    md5_0 = io.recvline().decode().strip()
    
    io.recvuntil(b"Common digest != ")
    md5_1 = io.recvline().decode().strip().split()[0]
    
    io.recvuntil(b"Common digest != ")
    md5_2 = io.recvline().decode().strip().split()[0]

    # Bersihkan sisa output server sampai prompt berikutnya muncul
    io.recvuntil(b"> ")

    print(f"[*] Brute-forcing LCG State MD5...")
    top0 = find_top_bits(md5_0)
    top1 = find_top_bits(md5_1)
    
    s0 = crack_lcg(top0, top1, md5_2)
    if s0 is None:
        print("[-] Gagal menemukan LCG State yang valid. Coba ulangi jalankan script-nya.")
        exit(1)
        
    print(f"[+] LCG State Recovered & Verified: {s0}")
    
    # Sinkronisasi ke state ke-128 (Saat server mulai mengecek planet kita)
    current_state = s0
    for _ in range(128):
        current_state = (A * current_state + C) % M

    predicted_x = []
    sim_state = current_state
    for _ in range(128):
        predicted_x.append(sim_state)
        sim_state = (A * sim_state + C) % M

    print("[*] Menanam 128 planet (Kombinasi X state LCG dengan Joux Collision)...")
    for i in range(128):
        io.sendline(b"2")
        io.recvuntil(b"Position (integer): ")
        io.sendline(str(predicted_x[i]).encode())
        io.recvuntil(b"State (integer): ")
        io.sendline(str(COLLISIONS[i]).encode())
        io.recvuntil(b"> ")

    print("[*] Memicu UNIVERSAL COLLAPSE! 💥")
    io.sendline(b"3")
    
    print("\n[+] SERVER RESPONSE:")
    print(io.recvall(timeout=5).decode('utf-8', 'ignore'))

if __name__ == "__main__":
    main()
