#!/usr/bin/env python3
from pathlib import Path
import struct


TARGET = Path("WrongCube+.exe")
DLL_NAME = "build\\wrongkube_validator.dll"
IMAGE_BASE = 0x180000000
ENC_VA = 0x18002BF00
ENC_LEN = 0x2F


def extract_validator(exe_path: Path) -> bytes:
    try:
        from PyInstaller.archive.readers import CArchiveReader
    except ImportError as exc:
        raise SystemExit("PyInstaller package is needed to extract the bundled DLL") from exc

    archive = CArchiveReader(str(exe_path))
    data = archive.extract(DLL_NAME)
    if isinstance(data, tuple):
        data = data[0]
    return data


def rva_to_offset(pe: bytes, rva: int) -> int:
    peoff = struct.unpack_from("<I", pe, 0x3C)[0]
    sections = struct.unpack_from("<H", pe, peoff + 6)[0]
    opt_size = struct.unpack_from("<H", pe, peoff + 20)[0]
    section_table = peoff + 24 + opt_size

    for i in range(sections):
        off = section_table + i * 40
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", pe, off + 8)
        size = max(vsize, raw_size)
        if vaddr <= rva < vaddr + size:
            return raw_ptr + (rva - vaddr)

    raise ValueError(f"RVA not mapped by any section: 0x{rva:x}")


def decrypt_flag(blob: bytes) -> str:
    rva = ENC_VA - IMAGE_BASE
    off = rva_to_offset(blob, rva)
    enc = blob[off : off + ENC_LEN]

    u32 = lambda x: x & 0xFFFFFFFF
    ebx = 0xF73449EF
    r9 = 0x49
    r14 = 0x47502943
    r15 = 1
    r12 = 0x47502932
    r13 = 0x3C6EF35F
    rsi = 0
    out = bytearray(ENC_LEN)

    while r15 != ENC_LEN:
        eax = u32(ebx * 0x19660D)
        eax = u32(eax + r13)
        r10 = eax >> 16
        ecx = u32(r9 - 0x49) ^ r10
        out[r15 - 1] = (enc[r15 - 1] ^ ecx ^ eax) & 0xFF

        eax = u32((rsi | 1) << 4)
        ecx = u32(ebx * 0x17385CA9)
        ebx = u32(rsi + eax + 1 + r12 + ecx)
        ecx = u32(ecx + r14)
        eax = (ecx >> 16) ^ r9 ^ enc[r15] ^ ecx
        out[r15] = eax & 0xFF

        rsi += 2
        r9 = u32(r9 + 0x92)
        r14 = u32(r14 + 0x35F8DDC)
        r15 += 2
        r12 = u32(r12 + 0x35F8DBA)
        r13 = u32(r13 + 0x22)

    return out.rstrip(b"\x00").decode()


def main() -> None:
    validator = extract_validator(TARGET)
    print(decrypt_flag(validator))


if __name__ == "__main__":
    main()
