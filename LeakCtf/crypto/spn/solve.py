#!/usr/bin/env python3
from pwn import *
from z3 import *
import signal
from chall import SBOX, encrypt

signal.alarm(0)

HOST = "spn.instances.ctf.l3ak.team"
PORT = 1337

set_param("parallel.enable", True)

def sbox_z3(x):
    # table SBOX sebagai ITE, bukan Z3 Array
    y = BitVecVal(SBOX[0], 8)
    for i in range(1, 256):
        y = If(x == BitVecVal(i, 8), BitVecVal(SBOX[i], 8), y)
    return y

def byte_to_bits_z3(b):
    return [Extract(i, i, b) for i in range(7, -1, -1)]

def bits_to_byte_z3(bs):
    return Concat(*bs)

def rotate_bits_left_z3(state_bytes, amount):
    bits = []
    for b in state_bytes:
        bits.extend(byte_to_bits_z3(b))

    amount %= 128
    bits = bits[amount:] + bits[:amount]

    out = []
    for i in range(0, 128, 8):
        out.append(bits_to_byte_z3(bits[i:i+8]))

    return out

def encrypt_z3(pt, key_bytes):
    state = [BitVecVal(x, 8) for x in pt]

    for r in range(25):
        after_sbox = []
        for i in range(16):
            after_sbox.append(sbox_z3(state[i] ^ key_bytes[i]))

        state = rotate_bits_left_z3(after_sbox, r + 1)

    return state

def query(io, pt):
    io.recvuntil(b"Enter msg (hex) > ")
    io.sendline(pt.hex().encode())
    line = io.recvline().decode().strip()
    return bytes.fromhex(line.split(": ")[1])

def recover_key(pairs):
    key = [BitVec(f"k{i}", 8) for i in range(16)]

    # QF_BV + bit-blast SAT biasanya lebih kuat buat kasus ini
    solver = Then(
        "simplify",
        "propagate-values",
        "solve-eqs",
        "bit-blast",
        "sat"
    ).solver()

    for pt, ct in pairs:
        enc = encrypt_z3(pt, key)
        for i in range(16):
            solver.add(enc[i] == BitVecVal(ct[i], 8))

    print(f"[*] solving with {len(pairs)} pair(s)...")
    res = solver.check()
    print("[*] solver:", res)

    if res != sat:
        return None

    model = solver.model()
    return bytes(model.eval(k, model_completion=True).as_long() for k in key)

def main():
    io = remote(HOST, PORT, ssl=True)

    pairs = []

    # pair pertama
    pt = bytes.fromhex("00" * 16)
    ct = query(io, pt)
    print("[+] pt:", pt.hex())
    print("[+] ct:", ct.hex())
    pairs.append((pt, ct))

    while True:
        key = recover_key(pairs)
        if key is None:
            print("[!] solver gagal")
            return

        print("[+] candidate key:", key.hex())

        # Verifikasi ke oracle sebelum submit.
        # Kalau collision, tambah constraint dari plaintext baru.
        test_pt = bytes([len(pairs)]) * 16
        test_ct = query(io, test_pt)

        local_ct = encrypt(test_pt, key)
        if local_ct == test_ct:
            print("[+] verified key:", key.hex())
            break

        print("[!] candidate salah/collision, tambah pair")
        print("    test_pt:", test_pt.hex())
        print("    real_ct:", test_ct.hex())
        print("    calc_ct:", local_ct.hex())
        pairs.append((test_pt, test_ct))

    io.recvuntil(b"Enter msg (hex) > ")
    io.sendline(b"done")

    io.recvuntil(b"Enter key (hex) > ")
    io.sendline(key.hex().encode())

    print(io.recvall(timeout=5).decode(errors="ignore"))

if __name__ == "__main__":
    main()
