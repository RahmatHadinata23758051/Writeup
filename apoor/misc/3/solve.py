from pwn import *

def build_array(target):
    if target == 0:
        return 3, [1, 1, 1]
    
    # Cari N terpendek di mana kapasitas air maksimalnya >= target
    N = 3
    while (N - 2) * (N - 2) < target:
        N += 1
        
    # Set tinggi tebing H maksimal N-1 biar server nggak IndexError
    H = N - 1
    arr = [1] * N
    arr[0] = H
    arr[-1] = H
    
    # Hitung sisa air yang harus "dibuang"
    excess = (N - 2) * (H - 1) - target
    
    # Tambal dasar lembah pakai batu untuk ngurangin air yang tertampung
    for i in range(1, N - 1):
        if excess == 0:
            break
        reduce_by = min(excess, H - 1)
        arr[i] += reduce_by
        excess -= reduce_by
        
    return N, arr

def main():
    context.log_level = 'info'
    io = remote('chals1.apoorvctf.xyz', 13001)

    io.sendlineafter(b"sswd:", b"test")
    io.sendlineafter(b"r3ddl3:", b"1")

    io.recvuntil(b"0uTpuTs: [")
    targets_str = io.recvuntil(b"]").decode()[:-1]
    targets = [int(x.strip()) for x in targets_str.split(",")]
    log.info(f"Target Trapping Rain Water: {targets}")

    # Harus diisi sesuai panjang target (5), gak boleh berlebih!
    io.sendlineafter(b"cnt =", str(len(targets)).encode())

    for i, target in enumerate(targets):
        log.info(f"Menyelesaikan level {i+1} dengan target: {target}")
        N, arr = build_array(target)
        
        io.recvuntil(f"cnt #{i+1}".encode())
        
        payload = f"{N} " + " ".join(map(str, arr))
        log.info(f"Aman! Payload N={N}, Max Elemen={max(arr)}, Size={len(payload)} bytes")
        
        io.sendline(payload.encode())

    io.interactive()

if __name__ == '__main__':
    main()
