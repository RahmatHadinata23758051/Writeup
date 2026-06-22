#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def solve():
    # Array nilai heksadesimal yang diambil dari tumpukan memori stack fungsi main()
    encrypted_bytes = [
        0x9d, 0x90, 0x8d, 0x90, 0xbc, 0xab, 0xb9, 0x84, 
        0xb1, 0xcf, 0x8b, 0xa0, 0x91, 0xb0, 0xd4, 0xa0, 
        0x8b, 0xb7, 0xcc, 0xa0, 0xb9, 0xb3, 0xbf, 0x98, 0x82
    ]
    
    # Melakukan operasi bitwise NOT (~) pada setiap elemen array 
    # dan memotongnya ke ukuran 8-bit (& 0xFF)
    flag = "".join(chr((~x) & 0xFF) for x in encrypted_bytes)
    
    print(f"[+] Flag ditemukan: {flag}")

if __name__ == '__main__':
    solve()
