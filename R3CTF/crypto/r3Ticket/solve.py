#!/usr/bin/env sage
import sys
import math
import time
import numpy as np
from sage.all import *
from pwn import *

def get_parts(index, N=128):
    parts = []
    for i in range(N):
        part = 1
        for j in range(N):
            if j == i: continue
            part *= (index - j) // (i - j)
        parts.append(part)
    return parts

def solve():
    # PASTIKAN UPDATE PORT SESUAI SESI TERBARU ANDA
    r = remote("challenge.ctf2026.r3kapig.com", 31864)
    
    try:
        # === PHASE 1: LLL KNAPSACK ===
        r.recvuntil(b"Which number you want to know: ")
        index = -2**40
        r.sendline(str(index).encode())
        
        r.recvuntil(b"Here is what you want: ")
        result = int(r.recvline().strip())
        print("[+] Phase 1 result received, building Lattice...")

        parts = get_parts(index)
        W = 2**200  
        
        B = Matrix(ZZ, 129, 129)
        for i in range(128):
            B[i, i] = 1
            B[i, 128] = W * parts[i]
            B[128, i] = -32768  
        B[128, 128] = -W * result

        L = B.LLL()
        
        nums = None
        for row in L:
            if row[128] == 0:
                cand = [row[i] + 32768 for i in range(128)]
                if all(0 <= x <= 65535 for x in cand):
                    nums = cand
                    break
                cand2 = [32768 - row[i] for i in range(128)]
                if all(0 <= x <= 65535 for x in cand2):
                    nums = cand2
                    break
                    
        if not nums:
            print("[-] Failed to extract nums. Retrying...")
            r.close()
            return False
            
        print("[+] Extracted all 128 nums successfully!")
        nums = [int(n) for n in nums] 

        # === PRA-KOMPUTASI & O(log N) SORTING ===
        print("[*] Server is sleeping for 10s. Precomputing AND Sorting...")
        t0 = time.time()
        
        m1 = max(nums)
        counts = {}
        for n in nums:
            if n: counts[n] = counts.get(n, 0) + 1

        S_arr = np.full(16777216, counts[m1], dtype=np.float64)
        X_float = np.arange(16777216, dtype=np.float64)

        for m, c in counts.items():
            if m == m1 or m == 0: continue
            ratio = m / m1
            log_ratio = math.log(ratio)
            limit = int(-80 / log_ratio) 
            limit = min(limit + 1, 16777216)
            if limit > 0:
                S_arr[:limit] += c * np.exp(X_float[:limit] * log_ratio)

        C_long = np.log10(np.longdouble(m1))
        X_long = np.arange(16777216, dtype=np.longdouble)
        
        H_base_long = (X_long * C_long) % 1.0
        
        H_base = H_base_long.astype(np.float64)
        H_base += np.log10(S_arr)
        H_base %= 1.0
        
        H_mod = np.empty(16777216, dtype=np.float64)
        print(f"[+] Prep finished in {time.time() - t0:.2f} seconds! Ready to bypass timeout.")

        # === PHASE 2: BINARY SEARCH MPFR ===
        r.recvuntil(b"Lets play!\n")

        RR = RealField(300)
        RR_check = RealField(800)
        D_m1 = RR_check(m1)
        D_C = D_m1.log10()
        
        ratios_RR = []
        for m, c in counts.items():
            if m == m1 or m == 0: continue
            ratios_RR.append((RR_check(m)/D_m1, c, math.log(m/m1)))

        for round_idx in range(16):
            r.recvuntil(b"challenge = ")
            S_target = r.recvline().strip().decode()
            t_search = time.time()

            D_V_frac = RR_check(S_target).log10() % 1
            V_float = float(D_V_frac)

            # Ambil kandidat terdekat langsung dari array mantissa.
            np.subtract(H_base, V_float, out=H_mod)
            np.mod(H_mod, 1.0, out=H_mod)
            np.minimum(H_mod, 1.0 - H_mod, out=H_mod)

            idx_n = np.argpartition(H_mod, 256)[:256]
            check_indices = idx_n[np.argsort(H_mod[idx_n])]
            
            best_x = -1
            for x in check_indices:
                x = int(x)
                s_exact = RR_check(counts.get(m1, 0))
                for rat, c, log_r in ratios_RR:
                    if x * log_r > -250: 
                        s_exact += c * (rat**x)

                F_exact = (x * D_C + s_exact.log10()) % 1
                cand_prefix = str(int((RR_check(10) ** (F_exact + 63)).floor()))
                if cand_prefix == S_target:
                    best_x = x
                    break
                    
            if best_x == -1:
                print("[-] FATAL: x not found in binary search radius!")
                r.close()
                return False
                
            waktu = time.time() - t_search
            print(f"[*] Round {round_idx+1}/16 | Found x = {best_x} in {waktu:.5f} seconds!")
            
            # BLIND FIRE Instan
            r.sendline(str(best_x).encode())

            # Membaca respons agar tidak jatuh ke perangkap out-of-sync
            try:
                resp = r.recvline(timeout=2.0).decode(errors="ignore")
                if "Too slow" in resp:
                    print("[-] Server: Too slow... (Network Latency Spike)")
                    r.close()
                    return False
                elif "lose" in resp:
                    print("[-] Server: You lose... (Math Error/Bad Precision)")
                    r.close()
                    return False
                elif "won" in resp or "flag" in resp.lower():
                    print(f"\n[+] BINGO!!! YOU WON! Flag: {resp.strip()}\n")
                    return True
                # Jika tidak ada error, loop berlanjut dengan mulus ke putaran berikutnya
            except EOFError:
                raise EOFError

    except EOFError:
        print("\n[-] EOFError: Server Docker terkena OOM Crash!")
        r.close()
        return False
    except Exception as e:
        print(f"\n[-] Unexpected Error: {e}")
        r.close()
        return False

if __name__ == "__main__":
    # AUTO FARMING LOOP: Biarkan skrip berjalan sendiri sampai dapat Flag!
    percobaan = 1
    while True:
        print(f"\n{'='*40}\n[+] MEMULAI PERCOBAAN KE-{percobaan}\n{'='*40}")
        sukses = solve()
        if sukses:
            print("[+] Misi Selesai!")
            break
        print("[!] Memulai ulang koneksi dalam 2 detik...")
        time.sleep(2)
        percobaan += 1
