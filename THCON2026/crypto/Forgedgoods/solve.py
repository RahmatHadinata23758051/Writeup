from pwn import *
from z3 import *
import json

def solve():
    # Konek ke server target
    io = remote("40.66.60.171", 4244)
    
    # 1. Ambil Public Key (T)
    io.sendlineafter(b'> ', b'1')
    io.recvuntil(b'Public key T (8x8):\n')
    T_raw = io.recvline().decode().strip()
    T = json.loads(T_raw)
    
    # 2. Ambil Intercepted Signed Orders buat cari bocoran nilai (bounds)
    io.sendlineafter(b'> ', b'2')
    io.recvuntil(b'Intercepted signed orders (5):\n\n')
    
    orders = []
    # Loop sebanyak 5 order sesuai output server
    for _ in range(5):
        line = io.recvline().decode().strip()
        if not line:
            break
        # Parsing string JSON dari output "Order #X: {...}"
        json_str = line.split(": ", 1)[1]
        orders.append(json.loads(json_str))
        
    M_DIM, N_DIM, K_DIM = 8, 8, 7
    
    log.info("Memulai Z3 Solver untuk memfaktorkan matriks Min-Plus...")
    solver = Solver()
    
    # Deklarasi array Z3 untuk X (8x7) dan Y (7x8)
    X = [[Int(f'X_{i}_{j}') for j in range(K_DIM)] for i in range(M_DIM)]
    Y = [[Int(f'Y_{i}_{j}') for j in range(N_DIM)] for i in range(K_DIM)]
    
    # Constraint dasar: semua entry nilainya 0 - 255
    for i in range(M_DIM):
        for j in range(K_DIM):
            solver.add(X[i][j] >= 0, X[i][j] <= 255)
            
    for i in range(K_DIM):
        for j in range(N_DIM):
            solver.add(Y[i][j] >= 0, Y[i][j] <= 255)
            
    # Constraint Aturan Perkalian Matriks Min-Plus (X * Y = T)
    for i in range(M_DIM):
        for j in range(N_DIM):
            t_val = T[i][j]
            for k in range(K_DIM):
                solver.add(X[i][k] + Y[k][j] >= t_val)
            solver.add(Or([X[i][k] + Y[k][j] == t_val for k in range(K_DIM)]))
            
    log.info("Menyuntikkan batasan (bounds) dari data signature...")
    # Constraint Bocoran (Information Leakage) dari matriks A dan B
    for order in orders:
        M = order['M']
        A = order['A']
        B = order['B']
        
        # A_ij <= M_ik + X_kj  =>  X_kj >= A_ij - M_ik
        for i in range(M_DIM):
            for j in range(K_DIM):
                for k in range(M_DIM):
                    solver.add(X[k][j] >= A[i][j] - M[i][k])
                    
        # B_ij <= Y_ik + M_kj  =>  Y_ik >= B_ij - M_kj
        for i in range(K_DIM):
            for j in range(N_DIM):
                for k in range(N_DIM):
                    solver.add(Y[i][k] >= B[i][j] - M[k][j])
                    
    # Eksekusi Z3
    if solver.check() == sat:
        log.success("Private Key (X, Y) berhasil ditemukan!")
        model = solver.model()
        
        X_ans = [[model[X[i][j]].as_long() for j in range(K_DIM)] for i in range(M_DIM)]
        Y_ans = [[model[Y[i][j]].as_long() for j in range(N_DIM)] for i in range(K_DIM)]
        
        # 3. Submit Private Key ke server
        io.sendlineafter(b'> ', b'3')
        
        payload = json.dumps({"X": X_ans, "Y": Y_ans})
        io.sendlineafter(b'> ', payload.encode())
        
        # Masuk mode interaktif buat ngeliat FLAG-nya
        io.interactive()
    else:
        log.error("Gagal nyari model, coba cek logic lagi.")

if __name__ == "__main__":
    solve()
