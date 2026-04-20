import socket
import re

HOST = 'enigma.aws.jerseyctf.com'
PORT = 9001

def solve():
    print("[*] Menghubungkan ke server...")
    # Setup socket TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    
    # Menerima data dari server (berisi print(p*q) dan input prompt)
    data = s.recv(1024).decode('utf-8')
    print(f"[*] Pesan Server:\n{data}")
    
    # Mengekstrak angka totient menggunakan Regex
    match = re.search(r"The totient is (\d+)", data)
    if match:
        tot_n = int(match.group(1))
        print(f"[+] Ditemukan Totient: {tot_n}")
        
        # Kalkulasi payload (e = tot_n + 1)
        e = tot_n + 1
        print(f"[+] Mengirimkan e = {e}")
        
        # Kirim payload ditambah newline (enter)
        s.sendall(f"{e}\n".encode('utf-8'))
        
        # Terima balasan berisi flag!
        response = s.recv(1024).decode('utf-8')
        print("="*50)
        print("[*] Hasil Balasan Server:")
        print(response.strip())
        print("="*50)
    else:
        print("[-] Gagal menemukan totient dari output server.")
        
    s.close()

if __name__ == '__main__':
    solve()
