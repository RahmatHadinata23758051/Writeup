from pwn import p64

# Nilai hex dari movabs rax/rdx (little-endian)
rax1 = p64(0x38213c2e39363b3e)
rdx1 = p64(0x3b2a0523283b3433)
rax2 = p64(0x273e3f32392e3b2a)

cipher = rax1 + rdx1 + rax2
key = 0x5a

flag = "".join(chr(b ^ key) for b in cipher if b != 0)
print(f"Flag: {flag}")
