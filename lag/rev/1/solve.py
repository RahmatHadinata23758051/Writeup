import struct

# Baca binary
with open('main', 'rb') as f:
    data = f.read()

# Extract encs array (offset 0x40e0 - 0x4080 = 0x60 dari data section start)
# encs ada di vaddr 0x40e0, file offset 0x30e0
encs_offset = 0x30e0
enc_len = 64  # dari ENC_LEN = 64

# Extract constants dari .rodata (0x2040, 0x2050, 0x2060)
# Ini LFSR constants untuk GF(2^16)
rodata_offset = 0x2000

def read_xmm(offset):
    return struct.unpack('<8H', data[offset:offset+16])

xmm_2040 = read_xmm(0x2040)
xmm_2050 = read_xmm(0x2050)  
xmm_2060 = read_xmm(0x2060)

print("xmm[0x2040]:", [hex(x) for x in xmm_2040])
print("xmm[0x2050]:", [hex(x) for x in xmm_2050])
print("xmm[0x2060]:", [hex(x) for x in xmm_2060])

# Lihat isi encs (100 entries x 64 bytes)
print("\nFirst enc entry (offset 0):")
print(data[encs_offset:encs_offset+64].hex())
print("\nSecond enc entry (offset 64):")  
print(data[encs_offset+64:encs_offset+128].hex())

# Lihat flag placeholder
flag_offset = 0x30a0
print("\nFlag bytes:", data[flag_offset:flag_offset+54].hex())
