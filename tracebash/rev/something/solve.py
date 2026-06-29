enc_expected = bytes([0xca,0x89,0xdb,0x99,0x8d,0x86,0xd8,0x86,
                       0xb4,0x99,0xdb,0x93,0xb4,0x9d,0xd8,0x99])

target = bytes([b ^ 0x16 for b in enc_expected])  # decoded comparison buffer

# reverse: input_middle[k] = target_reversed... derive directly
middle = bytearray(16)
for k in range(16):
    middle[k] = enc_expected[15-k] ^ 0xEB

flag = "TBCTF{" + middle.decode() + "}"
print(flag)
