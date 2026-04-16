import socket
import time
import re
import sys

HOST = "chals4.apoorvctf.xyz"
PORT = 1337

def busy_wait(delay_ns):
    """Busy-wait loop untuk presisi nanodetik."""
    if delay_ns <= 0:
        return
    start = time.perf_counter_ns()
    while time.perf_counter_ns() - start < delay_ns:
        pass

def clear_buffer(s, timeout=0.5):
    """Membaca dan membersihkan semua data yang menggantung di buffer TCP."""
    s.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    s.settimeout(None) # Kembalikan ke blocking mode
    return data.decode(errors='ignore').strip()

def solve():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        print("[*] Menghubungkan ke server...")
        s.connect((HOST, PORT))
        print("[+] Terhubung!")

        # --- FASE 1: HANDSHAKE ---
        banner = clear_buffer(s, timeout=0.5)
        
        print("[*] Mengirim perintah CALIBRATE (tanpa newline)...")
        # Mengirim tanpa \n untuk menghindari fuse putus
        s.sendall(b"CALIBRATE") 
        time.sleep(0.1)
            
        print("[*] Mengirim trigger byte (0xCA)...")
        s.sendall(b"\xCA")
        time.sleep(0.1)

        # --- FASE 2: CALIBRATION BURST ---
        delay_ns = 3450 
        consecutive_good = 0
        target_time_ns = 268579 # Target waktu teoritis untuk 63 byte
        
        print("[*] Memulai Calibration Burst...")
        while True:
            for _ in range(64):
                s.sendall(b"\x55")
                busy_wait(delay_ns)
            
            resp = clear_buffer(s, timeout=1.0)
            
            if not resp:
                print("[-] Tidak ada respons.")
                break
                
            print(f"[<] Server: {resp}")
            
            if "LOCKED" in resp:
                print("\n[+] LOCK ACHIEVED! Oscillator tersinkronisasi.")
                break
            elif "ERR:HSM_TAMPER_FUSE_BLOWN" in resp:
                print("[-] Fuse putus. Server mendeteksi byte ilegal.")
                sys.exit(1)
            elif "TIMEOUT" in resp:
                print("[-] Waktu 45 detik habis.")
                sys.exit(1)
                
            ppm = None
            # Menangkap format ERR:±00123
            if "ERR:" in resp and "PPM" not in resp: 
                match = re.search(r"ERR:([+-]\d+)", resp)
                if match:
                    ppm = int(match.group(1))
            # Menangkap format EXEC_TIME:123456
            elif "EXEC_TIME" in resp:
                match = re.search(r"EXEC_TIME:(\d+)", resp)
                if match:
                    exec_time = int(match.group(1))
                    diff = exec_time - target_time_ns
                    # Konversi selisih waktu ke estimasi PPM
                    ppm = int((diff / target_time_ns) * 1_000_000)
                    print(f"    -> Selisih waktu: {diff} ns | Kalkulasi: {ppm} PPM")

            if ppm is not None:
                if abs(ppm) <= 1000:
                    consecutive_good += 1
                    print(f"[+] Error = {ppm} PPM (Aman! Berhasil: {consecutive_good}/5)")
                else:
                    consecutive_good = 0 
                    
                # Auto-Tuner logic
                adjustment = int(delay_ns * (ppm / 1_000_000.0) * 0.8)
                delay_ns -= adjustment 
                delay_ns = max(0, delay_ns)
                print(f"[*] Auto-Tuning target delay menjadi: {delay_ns} ns")

        # --- FASE 3: LOCKED MODE ---
        print("\n[*] Mengeksekusi hardware multiplier...")
        payload = b"\xAA" + (b"\x01" * 64) + (b"\x02" * 64)
        s.sendall(payload)
        
        time.sleep(1.0)
        final_resp = clear_buffer(s, timeout=2.0)
        print(f"\n[+] Hasil Akhir:\n{final_resp}")

if __name__ == "__main__":
    solve()
