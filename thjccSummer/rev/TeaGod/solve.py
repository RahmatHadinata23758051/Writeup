#!/usr/bin/env python3
from pathlib import Path
import struct

EXE = Path(__file__).with_name("TeaGod.exe")
IMAGE_BASE = 0x140000000

# Constants recovered from WndProc of TeaGodNote around VA 0x140001e74.
PTR_TABLE_VA = 0x140005210      # 3 x pointers to encrypted 12-byte chunks
BLOCK_KEYS_VA = 0x140005228     # 3 per-block xor bytes
XOR_KEY = b"hc_ehsna"           # qword stored at stack+0x78
ADD_TABLE = [0xE7, 0xE0, 0xD9, 0xD2, 0xCB, 0xC4,
             0xBD, 0xB6, 0xAF, 0xA8, 0xA1, 0x9A]


def parse_sections(pe: bytes):
    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError("not a PE file")

    coff = e_lfanew + 4
    number_of_sections = struct.unpack_from("<H", pe, coff + 2)[0]
    size_of_optional_header = struct.unpack_from("<H", pe, coff + 16)[0]
    section_table = coff + 20 + size_of_optional_header

    sections = []
    for i in range(number_of_sections):
        off = section_table + i * 40
        name = pe[off:off + 8].rstrip(b"\0").decode(errors="replace")
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", pe, off + 8)
        sections.append((name, virtual_address, virtual_size, raw_ptr, raw_size))
    return sections


def va_to_offset(va: int, sections) -> int:
    rva = va - IMAGE_BASE
    for _name, vaddr, vsize, raw_ptr, raw_size in sections:
        size = max(vsize, raw_size)
        if vaddr <= rva < vaddr + size:
            return raw_ptr + (rva - vaddr)
    raise ValueError(f"VA not mapped: {va:#x}")


def main():
    pe = EXE.read_bytes()
    sections = parse_sections(pe)

    ptr_table_off = va_to_offset(PTR_TABLE_VA, sections)
    key_off = va_to_offset(BLOCK_KEYS_VA, sections)

    chunk_ptrs = [struct.unpack_from("<Q", pe, ptr_table_off + i * 8)[0] for i in range(3)]
    block_keys = pe[key_off:key_off + 3]

    stage1 = bytearray()
    for block_index, ptr in enumerate(chunk_ptrs):
        enc = pe[va_to_offset(ptr, sections):va_to_offset(ptr, sections) + 12]
        k = block_keys[block_index]
        for i, c in enumerate(enc):
            # Decompiled operation:
            #   tmp[i] = ((enc[i] + ADD_TABLE[i]) & 0xff) ^ block_key
            stage1.append(((c + ADD_TABLE[i]) & 0xFF) ^ k)

    flag = bytearray()
    rax = 1
    for c in stage1:
        # The binary also XORs one extra byte twice; those two operations cancel.
        flag.append(c ^ XOR_KEY[rax & 7])
        rax += 3

    print(flag.decode())


if __name__ == "__main__":
    main()
