import random
import time
import re
from pwn import *

# Konfigurasi Target
HOST = '154.57.164.67'
PORT = 32214

# Fungsi LCG dari server: (a * seed + c) % m
def lcg(seed, a=1664525, c=1013904223, m=2**32):
    return (a * seed + c) % m

def check_shiny(mac_int, t):
    """Replikasi simulasi RNG server secara presisi"""
    # 1. Hitung Seed
    initial_seed = t + mac_int
    seed = lcg(initial_seed)
    
    # 2. Generate TID & SID (dari seed utama)
    random.seed(seed)
    tid = random.randint(0, 65535)
    sid = random.randint(0, 65535)
    
    natures = ["Adamant", "Bashful", "Bold", "Brave", "Calm", "Careful", "Docile", "Gentle", "Hardy", "Hasty", "Impish", "Jolly", "Lax", "Lonely", "Mild", "Modest", "Naive", "Naughty", "Quiet", "Quirky", "Rash", "Relaxed", "Sassy", "Serious", "Timid"]
    
    # 3. Cek 3 Starter (Bulbasaurus, Charedmander, Squirturtle)
    for i in range(3):
        # Setiap starter punya seed sendiri: seed + i
        random.seed(seed + i)
        
        # Simulasi konsumsi angka acak untuk Stats (6x)
        for _ in range(6): random.randint(20, 31)
        
        # Simulasi konsumsi angka acak untuk Nature (1x)
        random.choice(natures)
        
        # Ambil PID
        pid = random.randint(0, 2**32 - 1)
        
        # Rumus Shiny: ((TID ^ SID) ^ (PID_Low ^ PID_High))
        shiny_value = ((tid ^ sid) ^ (pid & 0xFFFF) ^ (pid >> 16))
        
        if shiny_value < 8:
            return i + 1 # Return pilihan (1, 2, atau 3)
            
    return None

def solve():
    attempt = 0
    while True:
        attempt += 1
        print(f"\n[*] --- Attempt {attempt} ---")
        try:
            # Buka koneksi (level='warn' agar tidak spamming)
            r = remote(HOST, PORT, level='warn')
            
            # 1. Ambil MAC Address & Sinkronisasi Waktu
            # Server mengirim Preferences Loaded lalu sleep(2) baru mencatat boot_time
            data = r.recvuntil(b"Preferences Loaded: OK").decode()
            sync_time = time.time()
            
            mac_match = re.search(r"Mac Address: ([0-9a-f:]+)", data)
            if not mac_match:
                r.close()
                continue
            
            mac_str = mac_match.group(1)
            mac_int = int(mac_str.replace(":", ""), 16)
            print(f"[+] Connected! MAC: {mac_str}")

            # 2. Brute-force detik (t) di masa depan
            target_t = None
            starter_choice = None
            
            # Kita cari di rentang 25 - 150 detik
            for t in range(25, 150):
                res = check_shiny(mac_int, t)
                if res:
                    target_t = t
                    starter_choice = res
                    break
            
            if not target_t:
                print("[-] No shiny in near future. Re-rolling MAC...")
                r.close()
                continue

            print(f"[!] SHINY DETECTED! Detik: {target_t} | Pilih Starter: {starter_choice}")
            print(f"[*] Waiting for the perfect moment (Target: {target_t}s)...")

            # 3. Tunggu sampai Detik Target + Offset
            # OFFSET 2.5: 2.0 detik sleep server + 0.5 detik buffer keamanan
            wait_until = target_t + 2.5
            
            while True:
                elapsed = time.time() - sync_time
                if elapsed >= wait_until:
                    break
                # Print progress setiap 10 detik
                if int(elapsed) % 10 == 0 and int(elapsed) > 0:
                    print(f"    Timer: {elapsed:.1f}s / {wait_until}s")
                time.sleep(0.1)
            
            # 4. Eksekusi
            print(f"[+] MOMENT REACHED! Sending name...")
            r.sendline(b"ShinyHunter_Nata")
            
            print(f"[+] Choosing starter {starter_choice}...")
            r.sendlineafter(b"or 3): ", str(starter_choice).encode())
            
            # 5. Ambil Flag
            final_resp = r.recvall(timeout=5).decode()
            if "HTB{" in final_resp:
                print("\n" + "="*30)
                print("       POKETMON CHAMPION!")
                print("="*30)
                # Ekstrak flag
                flag = re.search(r"HTB\{.*?\}", final_resp)
                print(f"FLAG: {flag.group(0) if flag else final_resp}")
                return
            else:
                print("[-] Not shiny. Timing was slightly off. Retrying...")
                r.close()

        except Exception as e:
            print(f"[!] Error: {e}")
            try: r.close()
            except: pass

if __name__ == "__main__":
    solve()
