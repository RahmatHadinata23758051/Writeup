from pwn import *
from fractions import Fraction
import sys

# Set context for logging
context.log_level = 'info'

def solve():
    # Use the environment python's path if needed, but here we just run it
    host = 'tjc.tf'
    port = 31001

    try:
        r = remote(host, port)
    except Exception as e:
        print(f"Failed to connect: {e}")
        return

    r.recvuntil(b'n = ')
    n = int(r.recvline().strip())
    r.recvuntil(b'e = ')
    e = int(r.recvline().strip())
    r.recvuntil(b'ciphertext = ')
    c = int(r.recvline().strip())

    print(f"n: {n}")
    print(f"e: {e}")
    print(f"c: {c}")

    def get_lsb(ct):
        r.sendline(b'1')
        r.sendlineafter(b'ciphertext = ', str(ct).encode())
        r.recvuntil(b'lsb = ')
        res = r.recvline().strip()
        return int(res)

    low = Fraction(0)
    high = Fraction(n)

    num_bits = n.bit_length()
    print(f"Modulus bits: {num_bits}")

    for i in range(1, num_bits + 1):
        ct_query = (c * pow(2, i * e, n)) % n
        lsb = get_lsb(ct_query)
        
        mid = (low + high) / 2
        if lsb == 0:
            high = mid
        else:
            low = mid
        
        if i % 50 == 0:
            current_m = int(high)
            print(f"Iteration {i}/{num_bits}")
            try:
                flag_bytes = current_m.to_bytes((current_m.bit_length() + 7) // 8, 'big')
                print(f"Current guess: {flag_bytes}")
            except:
                pass

    final_m = int(high)
    flag = final_m.to_bytes((final_m.bit_length() + 7) // 8, 'big')
    print(f"Recovered flag: {flag}")
    
    # Check if flag format is there
    if b'tjcctf{' in flag:
        start = flag.find(b'tjcctf{')
        end = flag.find(b'}', start) + 1
        print(f"\n<FLAG>{flag[start:end].decode()}</FLAG>")

    r.close()

if __name__ == "__main__":
    solve()
