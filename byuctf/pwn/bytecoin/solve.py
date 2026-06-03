#!/usr/bin/env python3
from pwn import *
import hashlib
import hmac
import re
import os


HOST = "chals.cyberjousting.com"
PORT = 1362
ORIG_IV = b"303132333435363738396162"  # b"0123456789ab".hex()


def get_round(io):
    data = io.recvuntil(b">>> Enter a ciphertext to decrypt:")
    text = data.decode(errors="ignore")
    ct = re.search(r"Encrypted data: ([0-9a-f]+)", text).group(1)
    tag = re.search(r"Poly1305 authentication tag: ([0-9a-f]+)", text).group(1)
    mac = re.search(r"HMAC tag: ([0-9a-f]+)", text).group(1)
    return ct, tag, mac


def answer(io, ct, iv, tag, mac):
    io.sendline(ct if isinstance(ct, bytes) else ct.encode())
    io.recvuntil(b">>> Enter an IV for the message:")
    io.sendline(iv if isinstance(iv, bytes) else iv.encode())
    io.recvuntil(b">>> Enter a Poly1305 authentication tag for the message:")
    io.sendline(tag if isinstance(tag, bytes) else tag.encode())
    io.recvuntil(b">>> Enter an HMAC tag for the message:")
    io.sendline(mac if isinstance(mac, bytes) else mac.encode())


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    env = {"LD_LIBRARY_PATH": os.path.join(os.getcwd(), "wolfssl-install/lib")}
    return process("./challenge", env=env)


def main():
    io = start()

    leaked = bytearray()
    for i in range(32):
        _, tag, mac = get_round(io)
        # scan_hex_array increments its byte count before sscanf validates.
        # The invalid pair leaves tmp[i] unchanged, and tmp initially contains hmacKey.
        answer(io, "00" * i + "zz", ORIG_IV, tag, mac)
        out = io.recvuntil(b"Invalid HMAC tag!").decode(errors="ignore")
        msg = bytes.fromhex(re.search(r"Decrypting message ([0-9a-f]+)", out).group(1))
        leaked.append(msg[-1])

    ct, tag, _ = get_round(io)
    forged_ct = bytearray.fromhex(ct)
    forged_ct[0] ^= 1
    forged_mac = hmac.new(leaked, bytes(forged_ct) + bytes.fromhex(tag), hashlib.sha256).hexdigest()

    answer(io, forged_ct.hex(), ORIG_IV, tag, forged_mac)
    out = io.recvall(timeout=3).decode(errors="ignore")
    msg_hex = re.search(r"Here's your message:\n([0-9a-f]+)", out).group(1)
    msg = bytearray.fromhex(msg_hex)
    msg[0] ^= 1
    flag = bytes(msg).rstrip(b"\x00\r\n").decode(errors="ignore")
    print(flag)


if __name__ == "__main__":
    main()
