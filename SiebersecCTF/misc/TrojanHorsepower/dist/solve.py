
import socket

def solve():
    host = "chal.sieberr.live"
    port = 23002
    
    phrase = "oats invoice bridle mango pasture hoof delta saddle\n"
    
    with socket.create_connection((host, port)) as s:
        # Read banner
        banner = s.recv(1024).decode()
        print(banner)
        
        # Send phrase
        s.sendall(phrase.encode())
        
        # Read response
        response = s.recv(1024).decode()
        print(response)
        
        if "sctf{" in response:
            import re
            flag = re.search(r"sctf\{.*\}", response).group(0)
            print(f"FOUND FLAG: {flag}")

if __name__ == "__main__":
    solve()
