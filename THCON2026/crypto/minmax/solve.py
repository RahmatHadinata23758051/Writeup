from pwn import *
from z3 import *
import json

def solve():
    # Setup koneksi ke server
    io = remote("51.103.57.72", 4243)
    
    # 1. Pilih menu '1' (status) buat narik matrix K dan ciphertext
    io.sendlineafter(b'> ', b'1')
    
    # Ekstrak data JSON K dan ct
    io.recvuntil(b'K: ')
    K_raw = io.recvline().decode().strip()
    K = json.loads(K_raw)
    
    io.recvuntil(b'ct: ')
    ct_raw = io.recvline().decode().strip()
    ct = json.loads(ct_raw)
    
    log.info(f"Berhasil ekstrak Key dan {len(ct)} blok Ciphertext.")
    
    N = 8
    ans = []
    
    log.info("Memulai proses dekripsi dengan Z3...")
    for idx, block in enumerate(ct):
        solver = Solver()
        b = [Int(f'b_{i}') for i in range(N)]
        
        # Constraint 1: Batas nilai ASCII (0 - 127)
        for i in range(N):
            solver.add(b[i] >= 0, b[i] <= 127)
            
        # Constraint 2: Min-Plus Logic
        for i in range(N):
            c_i = block[i]
            # Semua kemungkinan K[i][j] + b[j] harus >= c_i
            for j in range(N):
                solver.add(K[i][j] + b[j] >= c_i)
            # Minimal ada 1 yang persis sama dengan c_i
            solver.add(Or([K[i][j] + b[j] == c_i for j in range(N)]))
            
        if solver.check() == sat:
            model = solver.model()
            # Ekstrak hasil block ini dan gabungin ke array jawaban
            solved_block = [model[b[j]].as_long() for j in range(N)]
            ans.extend(solved_block)
        else:
            log.error(f"Gagal solve block {idx}")
            return
            
    # Print array final hasil solver
    log.success(f"Z3 Array Found: {ans}")
    
    # 2. Masuk ke menu '2' (decrypt)
    io.sendlineafter(b'> ', b'2')
    
    # 3. Lempar format array JSON utuh, karena server parse input pakai json.loads()
    payload = json.dumps(ans)
    log.info(f"Mengirim payload JSON...")
    io.sendlineafter(b'key> ', payload.encode())
    
    # Masuk mode interaktif buat lihat respons server
    io.interactive()

if __name__ == "__main__":
    solve()
