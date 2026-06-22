from pwn import *

context.log_level = 'error'
HOST = 'thww9zyp6ygt.boroctf.com'
PORT = 19350

def solve():
    io = remote(HOST, PORT)
    
    # Pilih menu flag
    io.sendlineafter(b"> ", b"flag")
    # Konfirmasi pilihan
    io.sendlineafter(b"(y/n)", b"y")
    
    # Ambil output flag
    io.recvuntil(b"FINE. I guess if you insist.\n")
    flag = io.recvline().decode().strip()
    print(flag)

if __name__ == "__main__":
    solve()
