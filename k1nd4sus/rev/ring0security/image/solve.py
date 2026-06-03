#!/usr/bin/env python3
import struct

def xtea_decrypt_block(v0: int, v1: int, key_words):
    sum_ = 0xC6EF3720
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) & 0xFFFFFFFF) ^ (v0 >> 5)) + v0 ^ ((sum_ + key_words[(sum_ >> 11) & 3]) & 0xFFFFFFFF))) & 0xFFFFFFFF
        sum_ = (sum_ - 0x9E3779B9) & 0xFFFFFFFF
        v0 = (v0 - ((((v1 << 4) & 0xFFFFFFFF) ^ (v1 >> 5)) + v1 ^ ((sum_ + key_words[sum_ & 3]) & 0xFFFFFFFF))) & 0xFFFFFFFF
    return v0, v1


def decrypt_flag(enc_flag: bytes, key_words):
    out = bytearray()
    for i in range(0, len(enc_flag), 8):
        v0, v1 = struct.unpack('<2I', enc_flag[i:i + 8])
        d0, d1 = xtea_decrypt_block(v0, v1, key_words)
        out.extend(struct.pack('<2I', d0, d1))
    return bytes(out)


def main():
    # Ciphertext flag (enc_flag) dari decoder.ko hasil reversing section .data.
    enc_flag = bytes.fromhex(
        '7e38614d358f6d302e25c10149953ef9'
        'b09cf265ff9459ec57fcb593b833c7b6'
    )

    for pin in range(10000):
        key = [
            0x13370000 | pin,  # session_key[0] <- pin via ioctl 0x401b3700
            0xCAFEBABE,         # session_key[1] set di ctls.cold
            0xDEADBEEF,         # session_key[2]
            0xFEEDFACE,         # session_key[3]
        ]

        pt = decrypt_flag(enc_flag, key)
        if b'KSUS{' in pt and b'}' in pt:
            flag = pt.split(b'\x00', 1)[0].decode('ascii', errors='ignore')
            print(f'[+] PIN  : {pin:04d}')
            print(f'[+] FLAG : {flag}')
            return

    print('[-] Flag tidak ditemukan')


if __name__ == '__main__':
    main()
