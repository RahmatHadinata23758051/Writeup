#!/usr/bin/env python3
import sys
import os
import hashlib
import socket
import ssl
from pwn import *

# Atur ke 'debug' jika kamu ingin melihat data mentah, 'info' untuk lebih bersih
context.log_level = 'info'

def solve(host, port=443):
    log.info(f"Menghubungkan ke {host} via Native Python SSL...")
    
    # 1. Buka jalur TCP raw & Bungkus dengan TLS asli dari Python (Handle SNI/TLS 1.3)
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.connect((host, int(port)))
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
    
    # 2. "Suntikkan" socket murni tersebut ke pwntools menggunakan fromsocket
    io = remote.fromsocket(ssl_sock)

    # Peta kemenangan: Jika server milih kunci, kita milih value-nya
    win_map = {
        "rock": b"paper",
        "paper": b"scissors",
        "scissors": b"rock"
    }

    io.recvuntil(b"I want to play a game...\n")
    log.success("Berhasil terhubung! Memulai 100 ronde eksploitasi...")

    for i in range(100):
        # Buat nonce acak agar komitmen selalu unik
        nonce = os.urandom(8)
        
        # Base payload: nonce + rockpaperscissors + X (dummy byte penangkal crash)
        base_payload = nonce + b"rockpaperscissorsX"
        com = hashlib.sha256(base_payload).hexdigest()
        
        # Kirim komitmen
        io.recvuntil(b"Commitment (hex): ")
        io.sendline(com.encode())
        
        # Baca pilihan server (Contoh: "I choose rock.")
        response = io.recvline().decode().strip()
        server_choice = response.split(" ")[2].replace(".", "")
        
        # Tentukan pilihan kita agar menang
        our_choice = win_map[server_choice]
        
        # Kirim pilihan kita
        io.recvuntil(b"What did you choose? ")
        io.sendline(our_choice)
        
        # Hitung r1 dan r2 (Proof) berdasarkan pilihan kita (Pastikan r2 memiliki ekor b"X")
        if our_choice == b"rock":
            r1 = nonce
            r2 = b"paperscissorsX"
        elif our_choice == b"paper":
            r1 = nonce + b"rock"
            r2 = b"scissorsX"
        elif our_choice == b"scissors":
            r1 = nonce + b"rockpaper"
            r2 = b"X"  # <--- r2 tidak akan kosong lagi, mencegah ValueError!
            
        # Kirim proof dalam bentuk hex
        proof = f"{r1.hex()} {r2.hex()}"
        io.recvuntil(b"Proof (hex): ")
        io.sendline(proof.encode())
        
        # Tampilkan progress setiap 10 ronde
        if (i + 1) % 10 == 0:
            log.info(f"Berhasil melewati {i + 1}/100 ronde...")

    # Ambil Flag setelah 100 ronde selesai
    io.recvuntil(b"Here is your flag: ")
    flag = io.recvline().decode().strip()
    log.success(f"FLAG: {flag}")
    
    io.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        log.error(f"Cara penggunaan: python3 {sys.argv[0]} <host_instans_competition>")
        sys.exit(1)
        
    HOST = sys.argv[1]
    solve(HOST)
