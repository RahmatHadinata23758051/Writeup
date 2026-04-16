import socket

# Konfigurasi Server HTB
HOST = "94.237.50.128"
PORT = 51373

# Password yang sudah diperbaiki (Tepat 32 Karakter)
PASSWORD = "TheCrucialRustEngineering@2021;)"

def solve():
    try:
        # Membuat koneksi TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"[*] Menghubungkan ke {HOST}:{PORT}...")
            s.connect((HOST, PORT))
            
            # Menerima banner/sambutan dari server
            banner = s.recv(1024).decode(errors='ignore')
            print(banner)
            
            # Mengirim password + newline
            print(f"[*] Mengirim password: {PASSWORD}")
            s.sendall(PASSWORD.encode() + b"\n")
            
            # Menerima respon (Flag Asli)
            response = s.recv(1024).decode(errors='ignore')
            print(f"[+] Server Response:\n{response}")
            
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    solve()
