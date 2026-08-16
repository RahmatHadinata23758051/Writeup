from pwn import *
import re
import subprocess
import os

def solve():
    host = 'chal.thjcc.org'
    port = 11451
    io = remote(host, port)
    
    log.info("Mengambil parameter LCG...")
    io.recvuntil(b"Generator params: ")
    params_line = io.recvline().decode().strip()
    
    a = int(re.search(r'a = (0x[0-9a-f]+)', params_line).group(1), 16)
    b = int(re.search(r'b = (0x[0-9a-f]+)', params_line).group(1), 16)
    
    log.info("Mengambil data signatures...")
    io.recvuntil(b"Here are your signatures:\n")
    
    sigs = []
    while True:
        line = io.recvline().decode().strip()
        if "Can you find the private key?" in line:
            break
        if line.startswith('h ='):
            h = int(line.split('=')[1].strip(), 16)
            r = int(io.recvline().decode().split('=')[1].strip(), 16)
            s = int(io.recvline().decode().split('=')[1].strip(), 16)
            sigs.append((h, r, s))
            
    log.success(f"Berhasil memuat {len(sigs)} signatures.")
    
    # Generate script SageMath untuk menggabungkan 2 Dunia dengan CRT & Lattice
    sage_script = f'''
import sys

a = {a}
b = {b}
sigs = {sigs}

curves = [
    ("secp256k1", 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141),
    ("secp256r1", 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff, 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551)
]

def solve():
    N = min(len(sigs), 15)  # 15 signature udah lebih dari cukup buat Lattice
    
    for name, p, n in curves:
        A = []
        B = []
        for i in range(N):
            h, r, s = sigs[i]
            s_inv = inverse_mod(s, n)
            A.append((h * s_inv) % n)
            B.append((r * s_inv) % n)
        
        B1_inv = inverse_mod(B[0], n)
        
        C = []
        D = []
        
        U = 1
        V = 0
        M = n * p
        
        for i in range(N):
            # Dunia 1: Modulo n (Berasal dari ECDSA)
            u_i = (B[i] * B1_inv) % n
            v_i = (A[i] - u_i * A[0]) % n
            
            # Menggabungkan dua dunia dengan CRT (Chinese Remainder Theorem)
            c_i = crt([ZZ(u_i), ZZ(U)], [ZZ(n), ZZ(p)])
            d_i = crt([ZZ(v_i), ZZ(V)], [ZZ(n), ZZ(p)])
            
            C.append(c_i)
            D.append(d_i)
            
            # Dunia 2: Modulo p (Berasal dari state PRNG LCG)
            U = (U * a) % p
            V = (V * a + b) % p
            
        # Bangun Matriks Lattice
        mat = matrix(ZZ, N + 2, N + 2)
        for i in range(N):
            mat[i, i] = M
            mat[N, i] = C[i]
            mat[N+1, i] = D[i]
        
        mat[N, N] = 1
        mat[N+1, N+1] = n
        
        # Reduksi LLL
        L = mat.LLL()
        
        for row in L:
            if abs(row[N+1]) == n:
                sign = 1 if row[N+1] > 0 else -1
                k1 = row[N] * sign
                
                # Jika k1 valid, ekstrak Private Key (d)
                if 0 < k1 < n:
                    d = (B1_inv * (k1 - A[0])) % n
                    print(d)
                    return
solve()
'''
    with open('solver_lattice.sage', 'w') as f:
        f.write(sage_script)
        
    log.info("Menjalankan SageMath (CRT + LLL Lattice)...")
    try:
        output = subprocess.check_output(
            ['sage', 'solver_lattice.sage'], 
            stderr=subprocess.STDOUT
        ).decode().strip()
    except subprocess.CalledProcessError as e:
        log.error(f"Error SageMath:\n{e.output.decode('utf-8', errors='ignore')}")
        io.close()
        return
        
    if not output:
        log.error("Lattice gagal menemukan private key.")
        io.close()
        return
        
    try:
        d = int(output.strip().split('\n')[-1])
        log.success(f"BINGO! Private Key (d) Ditemukan: {hex(d)}")
        
        io.recvuntil(b"Private Key (d) in hex: ")
        io.sendline(hex(d).encode())
        log.info("Tembus shell! Silakan catat flag-nya di bawah ini:")
        io.interactive()
    except Exception as e:
        log.error(f"Gagal parse output dari Sage:\n{output}")
        io.close()

if __name__ == '__main__':
    solve()
