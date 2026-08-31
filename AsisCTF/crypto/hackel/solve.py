from pwn import *

io = remote('65.109.208.91', 3771)

# Go to Speed Challenge
io.sendlineafter(b'> ', b'5')
io.recvuntil(b'Challenge Words: ')
challenge_words = io.recvline().decode().strip().split()

# Solve it
classification = "".join(['1' if 'b' in word else '0' for word in challenge_words])
io.sendlineafter(b'Your Classification Bits: ', classification.encode())

# Read the flag and everything else the server spits out before closing
log.success(f"Passed speed challenge with: {classification}")
print(io.recvall().decode())
