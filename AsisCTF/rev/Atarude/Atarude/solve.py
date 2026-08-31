#!/usr/bin/env python3
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BIN = Path('Atarude')
ENC = Path('flag.enc')

MASK = (1 << 64) - 1
MUL = 0xA9C8666E28DBE1A3
MOD = 0xC0FFE0

def rol8(x, n):
    n &= 7
    return (((x << n) | (x >> (8 - n))) & 0xff) if n else (x & 0xff)

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def paddb(a, b):
    return bytes(((x + y) & 0xff) for x, y in zip(a, b))

def aes_enc(pt, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(pt) + enc.finalize()

def prng16(blob):
    table = blob[0x5064:0x5064 + MOD]
    arr = bytearray(16)
    r8 = 0x9E3779B97F4A7C15
    rdi = 0
    for ecx in range(0x1800):
        r9 = (ecx + 1) & MASK
        rax = ((r8 << 13) & MASK) ^ r8
        rdx = (rax >> 7) ^ rax
        r8 = (((rdx << 17) & MASK) ^ rdx) & MASK
        rsi = r8 ^ rdi
        prod = rsi * MUL
        q = ((prod >> 64) & MASK) >> 0x17
        rem = (rsi - q * MOD) & MASK
        i = ecx & 0xf
        v = rol8(arr[i], ecx)
        v ^= table[rem]
        v ^= table[rem + 0x11]
        v ^= (r8 >> 0x29) & 0xff
        arr[i] = v & 0xff
        rdi = (rdi + 0x9E37) & MASK
    return bytes(arr)

def C(blob, off):
    return blob[off:off + 16]

def mac_blocks(blocks, seed, const):
    state = seed
    ctr = 0
    for block in blocks:
        assert len(block) == 16
        ctrvec = bytes([ctr & 0xff]) * 16
        msg = xor(xor(paddb(ctrvec, const), block), state)
        state = aes_enc(msg, seed)
        ctr = (ctr + 0x1d) & 0xff
    return aes_enc(seed, state)

def derive_stream_key(blob):
    seed = prng16(blob)
    target_hash = C(blob, 0x32a0)

    state = seed
    state = aes_enc(xor(xor(seed, seed), C(blob, 0x3210)), seed)
    state = aes_enc(xor(state, C(blob, 0x3600)), seed)
    k50 = aes_enc(seed, state)

    state = seed
    state = aes_enc(xor(xor(seed, seed), C(blob, 0x3430)), seed)
    state = aes_enc(xor(state, C(blob, 0x33e0)), seed)
    k60 = aes_enc(seed, state)

    state = seed
    state = aes_enc(xor(xor(target_hash, state), C(blob, 0x34f0)), seed)
    state = aes_enc(xor(xor(k50, state), C(blob, 0x3270)), seed)
    state = aes_enc(xor(xor(k60, state), C(blob, 0x32c0)), seed)
    stream_key = aes_enc(seed, state)
    return seed, target_hash, stream_key

def decrypt_flag(blob, enc):
    if len(enc) < 20 or enc[:2] != b'\xa6\x3c':
        raise ValueError('bad flag.enc header')
    length = int.from_bytes(enc[2:4], 'big')
    if len(enc) != 4 + length + 16:
        raise ValueError('bad flag.enc length')
    ct = enc[4:4 + length]
    tag = enc[4 + length:]

    seed, target_hash, stream_key = derive_stream_key(blob)

    blocks = [stream_key, b'\x00' * 8 + length.to_bytes(8, 'big')]
    for i in range(0, len(ct), 16):
        block = ct[i:i + 16]
        blocks.append(block + b'\x00' * (16 - len(block)))
    calc_tag = mac_blocks(blocks, seed, C(blob, 0x3280))
    if calc_tag != tag:
        raise ValueError(f'tag mismatch: got {calc_tag.hex()}, expected {tag.hex()}')

    pt = bytearray()
    for i, c in enumerate(ct):
        block_no = i >> 4
        # Assembly: bswap(block_no), movq xmm0, pslldq xmm0, 8
        counter = b'\x00' * 8 + block_no.to_bytes(8, 'big')
        stream = aes_enc(counter, stream_key)
        pt.append(c ^ stream[i & 15])
    return bytes(pt)

if __name__ == '__main__':
    blob = BIN.read_bytes()
    enc = ENC.read_bytes()
    flag = decrypt_flag(blob, enc).decode()
    print(f'<FLAG>{flag}</FLAG>')
