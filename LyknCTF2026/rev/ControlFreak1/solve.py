import sys

target = [
    0x66, 0x15, 0xe4, 0x34, 0x0c, 0x1b, 0x3e, 0xd3, 0x22, 0xd1, 0xea, 0x25,
    0x86, 0x12, 0x88, 0x6f, 0xae, 0x57, 0x72, 0x18, 0xc9, 0xdb, 0x10, 0x36,
    0x3e, 0x0b, 0x48, 0x07, 0x44, 0xf9, 0x01, 0xff, 0x07
]

r13 = [0x52, 0x64, 0x71, 0x51, 0x54, 0x76, 0x2d, 0x39]
r12 = [0x17, 0x8b, 0x23, 0x42, 0xc1, 0x5e, 0x09, 0xa7]
rbp = [
    3, 10, 17, 24, 31, 5, 12, 19, 26, 0, 7, 14, 21, 28, 2, 9, 16, 23, 30, 4,
    11, 18, 25, 32, 6, 13, 20, 27, 1, 8, 15, 22, 29
]

def ror8(val, r_bits):
    return ((val >> r_bits) | (val << (8 - r_bits))) & 0xff

def backward_iter(new_buf, iter_num):
    cl_init = (0x5a + 0x31 * iter_num) & 0xff
    perm_buf = [0]*33
    prev_cl = cl_init
    for j in range(33):
        cl = new_buf[j]
        r8d = (cl ^ prev_cl) & 0xff
        perm_buf[j] = (r8d ^ (iter_num + 7 * j)) & 0xff
        prev_cl = cl

    buf_phase1 = [0]*33
    for j in range(33):
        buf_phase1[j] = perm_buf[rbp[j]]

    buf = [0]*33
    for i in range(33):
        idx_r13 = (i + 3 * iter_num) & 7
        idx_r12 = (iter_num + 5 * i) & 7
        edi = ((0x1d * iter_num) & 0xff + 13 * i) & 0xff
        
        esi = (buf_phase1[i] - r12[idx_r12] - edi) & 0xff
        shift = ((i + iter_num) % 7) + 1
        esi = ror8(esi, shift)
        buf[i] = (esi ^ r13[idx_r13]) & 0xff
    return buf

curr = target
for it in [2, 1, 0]:
    curr = backward_iter(curr, it)

flag = "".join(chr(c) for c in curr)
print(flag)
