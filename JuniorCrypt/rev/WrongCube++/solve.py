#!/usr/bin/env python3
"""Recover the encrypted flag from the bundled WrongKube validator."""
import struct
import sys
import zlib


def extract_validator(exe: bytes) -> bytes:
    magic = b"MEI\x0c\x0b\x0a\x0b\x0e"
    cookie_at = exe.rfind(magic)
    if cookie_at < 0:
        raise ValueError("PyInstaller cookie not found")
    _, archive_len, toc_off, toc_len, _, _ = struct.unpack(
        "!8sIIII64s", exe[cookie_at:cookie_at + 88]
    )
    archive_start = cookie_at + 88 - archive_len
    toc = exe[archive_start + toc_off:archive_start + toc_off + toc_len]
    pos = 0
    while pos < len(toc):
        entry_len, off, size, _, compressed, kind = struct.unpack(
            "!IIIIBc", toc[pos:pos + 18]
        )
        name = toc[pos + 18:pos + entry_len].rstrip(b"\0").decode()
        if name == "build\\wrongkube_validator.dll":
            data = exe[archive_start + off:archive_start + off + size]
            return zlib.decompress(data) if compressed else data
        pos += entry_len
    raise ValueError("validator DLL not found")


def rva_to_offset(pe: bytes, rva: int) -> int:
    pe_off = struct.unpack_from("<I", pe, 0x3C)[0]
    sections = struct.unpack_from("<H", pe, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", pe, pe_off + 20)[0]
    section_off = pe_off + 24 + opt_size
    for i in range(sections):
        off = section_off + i * 40
        virtual_size, virtual_addr, raw_size, raw_off = struct.unpack_from("<IIII", pe, off + 8)
        if virtual_addr <= rva < virtual_addr + max(virtual_size, raw_size):
            return raw_off + rva - virtual_addr
    raise ValueError(f"unmapped RVA: {rva:#x}")


def decrypt(ciphertext: bytes) -> str:
    mask = 0xFFFFFFFF
    state = (-0x3A4E2D01) & mask
    key = 0x49
    add_a, add_b, add_c = 0x47502943, 0x47502932, 0x3C6EF35F
    counter = 0
    plain = []
    for i in range(0, 45, 2):
        mixed = (state * 0x19660D + add_c) & mask
        plain.append(ciphertext[i] ^ ((key + 0xB7) & 0xFF) ^ (mixed >> 16 & 0xFF) ^ (mixed & 0xFF))
        if i == 44:
            break
        mixed = (state * 0x17385CA9) & mask
        state = (counter + 1 + (counter | 1) * 0x10 + add_b + mixed) & mask
        mixed = (mixed + add_a) & mask
        plain.append(ciphertext[i + 1] ^ (key & 0xFF) ^ (mixed >> 16 & 0xFF) ^ (mixed & 0xFF))
        counter = (counter + 2) & mask
        key = (key + 0x92) & mask
        add_a = (add_a + 0x35F8DDC) & mask
        add_b = (add_b + 0x35F8DBA) & mask
        add_c = (add_c + 0x22) & mask
    return bytes(plain).decode()


def main() -> None:
    path = sys.argv[1] if len(sys.argv) == 2 else "WrongKube++.exe"
    validator = extract_validator(open(path, "rb").read())
    cipher_off = rva_to_offset(validator, 0x2B310)
    print(decrypt(validator[cipher_off:cipher_off + 45]))


if __name__ == "__main__":
    main()
