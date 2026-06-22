from pwn import *
import subprocess

def solve():
    p = remote('chal.sieberr.live', 20003)

    # 1. Bypass Proof of Work (PoW)
    p.recvuntil(b'Run the following command and input the solution below to solve the proof-of-work:\n')
    cmd = p.recvline().strip().decode()
    log.info(f"PoW Command: {cmd}")
    
    log.info("Sedang menyelesaikan PoW (membutuhkan beberapa detik)...")
    # Mengeksekusi command PoW secara langsung lewat bash
    pow_solution = subprocess.check_output(cmd, shell=True, executable='/bin/bash').strip()
    
    p.sendlineafter(b'> ', pow_solution)
    p.recvuntil(b'Press enter to proceed to the challenge')
    p.sendline(b'')
    
    # 2. Ambil Public Key
    pk_hex = p.recvline().strip()
    log.info("Public Key UOV diterima.")
    
    # 3. Bypass Type Mismatch
    # String 'msg' tidak akan pernah dianggap sama dengan Bytes 'thought'
    payload = b'I am thinking of the flag'
    p.sendlineafter(b'msg: ', payload)
    
    # 4. Tangkap Tanda Tangan
    sig_hex = p.recvline().strip()
    log.success("Berhasil mengelabui server untuk menandatangani pesan rahasia!")
    
    # 5. Kirim kembali Tanda Tangan dan Dapatkan Flag
    p.sendlineafter(b'sig: ', sig_hex)
    
    flag = p.recvline().strip()
    log.success(f"FLAG DITEMUKAN: {flag.decode()}")
    
    p.close()

if __name__ == '__main__':
    solve()
