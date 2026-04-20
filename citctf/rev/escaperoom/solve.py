#!/usr/bin/env python3
from pwn import process
import re

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
SPICE = [0x13, 0x37, 0xC0DE, 0xBEEF, 0x5A, 0x0ACE, 0x4242, 0x900D, 0x1234, 0x777]


def rol32(x: int, r: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << r) & 0xFFFFFFFF) | (x >> (32 - r))


def build_token() -> str:
    # Final state yang dibutuhkan dari roomAligned + maintenance checks:
    # lights=OFF, vent=1, camera=3, patch=2, battery=1, mirror=1, hush=1
    lights = 0
    vent = 1
    cam = 3
    patch = 2
    battery = 1
    mirror = 1
    hush = 1

    sig = 0xA17C3E29
    sig ^= 0x13579BDF if lights else 0x2468ACE0
    sig = rol32(sig, 7)
    sig = (sig + ((vent + 1) * 0x1F123BB5)) & 0xFFFFFFFF
    sig ^= ((cam + 3) * 0x045D9F3B) & 0xFFFFFFFF
    sig = (sig + ((patch + 5) * 0x27D4EB2D)) & 0xFFFFFFFF
    sig ^= 0xA5A55A5A if battery else 0x5A5AA5A5
    sig = (sig + (0x31415926 if mirror else 0x27182818)) & 0xFFFFFFFF
    sig ^= 0xDEADBEEF if hush else 0xBAD0C0DE

    seed = sig ^ 0x6F70656E  # xor 'open'
    out = []
    for i, s in enumerate(SPICE):
        seed = (seed * 0x19660D + s + 0x3C6EF35F) & 0xFFFFFFFF
        out.append(ALPHABET[seed >> 27])
        if i in (2, 5):
            out.append("-")
    return "".join(out)


def send_menu(io, choice: str):
    io.sendlineafter(b"> ", choice.encode())


def main():
    token = build_token()  # RHY-QVT-KAXJ
    io = process("./escaperoom")

    # Stage room state
    send_menu(io, "2")  # lights OFF
    send_menu(io, "3")  # vent -> 1 (east bypass)
    send_menu(io, "4")  # cam 1
    send_menu(io, "4")  # cam 2
    send_menu(io, "4")  # cam 3 (mirror relay)
    send_menu(io, "5")  # patch 1
    send_menu(io, "5")  # patch 2
    send_menu(io, "6")  # battery engaged

    # maintenance shell: mirror + hush
    send_menu(io, "7")
    io.sendlineafter(b"svc> ", b"mirror")
    io.sendlineafter(b"svc> ", b"hush")
    io.sendlineafter(b"svc> ", b"back")

    # submit token
    send_menu(io, "8")
    io.sendlineafter(b"override token> ", token.encode())

    data = io.recvrepeat(1.0).decode(errors="ignore")
    m = re.search(r"CIT\{[^}]+\}", data)
    if not m:
        print("Flag tidak ditemukan. Output terakhir:")
        print(data)
        return

    print(m.group(0))


if __name__ == "__main__":
    main()
