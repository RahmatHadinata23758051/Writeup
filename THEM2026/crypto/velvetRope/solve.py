#!/usr/bin/env python3
from pwn import *
from Crypto.Util.number import long_to_bytes

def ceil(a, b): return (a + b - 1) // b
def floor(a, b): return a // b
def merge_intervals(intervals):
    intervals.sort(key=lambda x: x[0])
    merged = []
    for interval in intervals:
        if not merged: merged.append(interval)
        else:
            prev = merged[-1]
            if interval[0] <= prev[1]: merged[-1] = (prev[0], max(prev[1], interval[1]))
            else: merged.append(interval)
    return merged

def solve_bleichenbacher_perfect():
    host = '74.113.234.79'
    port = 30300
    
    context.log_level = 'error'
    print("[*] Menyambungkan ke bouncer...")
    io = remote(host, port)
    
    io.recvuntil(b"n = ")
    n = int(io.recvline().strip())
    io.recvuntil(b"e = ")
    e = int(io.recvline().strip())
    io.recvuntil(b"c = ")
    c = int(io.recvline().strip())
    
    # Flush buffer
    io.clean(timeout=0.5)
    
    k = (n.bit_length() + 7) // 8
    B = 2**(8 * (k - 2))
    BATCH_SIZE = 1000

    # ==================================================
    # DIAGNOSTIK ORACLE (Cek respons Bouncer yang asli)
    # ==================================================
    # Kita kirim angka acak (misal 2) yang pasti padding-nya salah
    io.sendline(b"02")
    bad_resp = io.recvline().decode().strip().lower()
    print(f"[*] Respons Bouncer untuk padding SALAH : '{bad_resp}'")

    def oracle_batch(c_list):
        if not c_list: return []
        payloads = []
        for c_val in c_list:
            hx = hex(c_val)[2:]
            if len(hx) % 2 != 0: hx = '0' + hx
            payloads.append(hx.encode())
            
        io.send(b'\n'.join(payloads) + b'\n')
        
        results = []
        for _ in range(len(c_list)):
            resp = io.recvline().decode().strip().lower()
            
            # CEK KETAT: Jika responnya persis sama dengan bad_resp, berarti False.
            # Jika mengandung kata penolakan, False.
            if resp == bad_resp or "invalid" in resp or "false" in resp or "not" in resp:
                results.append(False)
            elif "valid" in resp or "true" in resp or "yes" in resp or "matches" in resp:
                results.append(True)
            else:
                results.append(False)
        return results

    # ==================================================
    # TAHAP 1: TURBO BLINDING
    # ==================================================
    print("\n[*] Tahap 1: Blinding (Menyelundupkan 'guest' asli)...")
    s0 = 1
    c0 = c
    
    # Uji c0 (s0=1)
    if oracle_batch([c0])[0]:
        print("[+] Ciphertext asli sudah memiliki padding valid (s0 = 1).")
    else:
        print("[-] Ciphertext asli TIDAK valid. Memulai pencarian multiplier...")
        s0 = 2
        found_s0 = False
        while not found_s0:
            s0_tries = list(range(s0, s0 + BATCH_SIZE))
            c_tests = [(c * pow(st, e, n)) % n for st in s0_tries]
            results = oracle_batch(c_tests)
            
            for idx, res in enumerate(results):
                if res:
                    s0 = s0_tries[idx]
                    c0 = c_tests[idx]
                    found_s0 = True
                    break
            
            if found_s0:
                print(f"\n[+] Blinding sukses! Ditemukan s0 = {s0}")
                break
                
            s0 += BATCH_SIZE
            print(f"    [>] Mencari s0 di atas {s0}...", end="\r")

    # ==================================================
    # TAHAP 2: BLEICHENBACHER INTERVAL SEARCH
    # ==================================================
    M = [(2 * B, 3 * B - 1)]
    i = 1
    s = ceil(n, 3 * B)

    print("[*] Tahap 2: Memulai pencarian interval Bleichenbacher...")
    
    while True:
        if i == 1 or len(M) > 1:
            found = False
            while not found:
                s_tries = list(range(s, s + BATCH_SIZE))
                c_tests = [(c0 * pow(st, e, n)) % n for st in s_tries]
                results = oracle_batch(c_tests)
                
                for idx, res in enumerate(results):
                    if res:
                        s = s_tries[idx]
                        found = True
                        break
                if not found:
                    s += BATCH_SIZE
                    print(f"    [>] Scanning s di sekitar {s}...", end="\r")
                    
        elif len(M) == 1:
            a, b = M[0]
            if a == b: break
                
            r = ceil(2 * (b * s - 2 * B), n)
            s_found = False
            
            while not s_found:
                s_min = ceil(2 * B + r * n, b)
                s_max = floor(3 * B - 1 + r * n, a)
                
                if s_max >= s_min:
                    s_tries = list(range(s_min, s_max + 1))
                    for batch_idx in range(0, len(s_tries), BATCH_SIZE):
                        batch = s_tries[batch_idx:batch_idx + BATCH_SIZE]
                        c_tests = [(c0 * pow(st, e, n)) % n for st in batch]
                        results = oracle_batch(c_tests)
                        
                        for idx, res in enumerate(results):
                            if res:
                                s = batch[idx]
                                s_found = True
                                break
                        if s_found: break
                if not s_found: r += 1
                    
        M_new = []
        for a, b in M:
            r_min = ceil(a * s - 3 * B + 1, n)
            r_max = floor(b * s - 2 * B, n)
            for r in range(r_min, r_max + 1):
                start = max(a, ceil(2 * B + r * n, s))
                end = min(b, floor(3 * B - 1 + r * n, s))
                if start <= end: M_new.append((start, end))
                    
        M = merge_intervals(M_new)
        
        if len(M) == 0:
            print("\n[-] FATAL: Interval kosong (0).")
            break
        elif len(M) == 1:
            diff = M[0][1] - M[0][0]
            print(f"\n[*] Iterasi {i} | Sisa Jarak: {diff} bytes")
            if diff == 0: break
        else:
            print(f"\n[*] Iterasi {i} | Menemukan {len(M)} interval baru.")
            
        i += 1

    # ==================================================
    # TAHAP 3: UNBLINDING & EKSTRAKSI FLAG
    # ==================================================
    if len(M) == 1 and M[0][0] == M[0][1]:
        m0 = M[0][0]
        print("\n[+] Plaintext terenkripsi (m0) ditemukan!")
        
        m = (m0 * pow(s0, -1, n)) % n
        flag = long_to_bytes(m)
        print(f"\n[!] FLAG ASLI: {flag.decode('utf-8', errors='ignore')}")
    
    io.close()

if __name__ == "__main__":
    solve_bleichenbacher_perfect()
