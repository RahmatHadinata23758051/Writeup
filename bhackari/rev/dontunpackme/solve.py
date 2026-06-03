#!/usr/bin/env python3
from pathlib import Path
import struct
import zlib

# Byte selections recovered from the protected inner payload.
IDX = [
    (0x15A,), (0x234, 0x73), (0x191,), (0x111, 0x6B),
    (0x48,), (0x145, 0x15), (0xBF, 0x23), (0x99, 0x53),
    (0x189, 0x60), (0x111, 0x5C), (0x177, 0xAD), (0x18B, 0x156),
    (0x226,), (0xE7, 0x6B), (0x20D, 0x102), (0x2F,),
    (0x1A1, 0x9A), (0x1BC, 0x3D), (0x139, 0x7C), (0x1CC, 0x3E),
    (0x1B1,), (0x103, 0xA6), (0x226,), (0x2D,),
    (0x37,), (0x1DF, 0xDE), (0xAC, 0x7B), (0xE6, 0x21),
]

# Fallback constants derived from 7-Zip 24.09 x64 7z.dll::GetHandlerProperty2.
FALLBACK_KEY = bytes.fromhex("8c95cd23")
FALLBACK_CT = bytes.fromhex("4ea617b13a1b4db37a1ee082216a5202fab3e7e7dfd821e912f2d48f")


def u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def rva_to_offset(buf, rva):
    pe = u32(buf, 0x3C)
    number_of_sections = u16(buf, pe + 6)
    opt_size = u16(buf, pe + 20)
    sec = pe + 24 + opt_size

    for i in range(number_of_sections):
        base = sec + i * 40
        virtual_size = u32(buf, base + 8)
        virtual_address = u32(buf, base + 12)
        raw_size = u32(buf, base + 16)
        raw_ptr = u32(buf, base + 20)
        size = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + size:
            return raw_ptr + (rva - virtual_address)
    raise ValueError(f"RVA 0x{rva:x} is outside all PE sections")


def find_export_offset(buf, export_name):
    pe = u32(buf, 0x3C)
    export_rva = u32(buf, pe + 24 + 0x70)
    if export_rva == 0:
        raise ValueError("PE has no export directory")

    exp = rva_to_offset(buf, export_rva)
    number_of_functions = u32(buf, exp + 20)
    number_of_names = u32(buf, exp + 24)
    address_of_functions = u32(buf, exp + 28)
    address_of_names = u32(buf, exp + 32)
    address_of_ordinals = u32(buf, exp + 36)

    funcs = rva_to_offset(buf, address_of_functions)
    names = rva_to_offset(buf, address_of_names)
    ords = rva_to_offset(buf, address_of_ordinals)

    for i in range(number_of_names):
        name_rva = u32(buf, names + i * 4)
        name_off = rva_to_offset(buf, name_rva)
        end = buf.index(b"\x00", name_off)
        name = buf[name_off:end].decode("ascii", errors="replace")
        if name == export_name:
            ordinal = u16(buf, ords + i * 2)
            if ordinal >= number_of_functions:
                raise ValueError("invalid export ordinal")
            func_rva = u32(buf, funcs + ordinal * 4)
            return rva_to_offset(buf, func_rva)

    raise ValueError(f"export {export_name!r} not found")


def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]

    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def solve_from_7z_dll(path):
    buf = Path(path).read_bytes()
    off = find_export_offset(buf, "GetHandlerProperty2")
    func = buf[off:off + 0x250]
    if len(func) != 0x250:
        raise ValueError("GetHandlerProperty2 function bytes are too short")

    key = zlib.crc32(func).to_bytes(4, "little")
    ciphertext = bytes(
        func[item[0]] if len(item) == 1 else func[item[0]] ^ func[item[1]]
        for item in IDX
    )
    return rc4(key, ciphertext).decode("ascii")


def main():
    dll = Path("7z.dll")
    if dll.exists():
        flag = solve_from_7z_dll(dll)
    else:
        # Keeps the solver reproducible even when only the recovered constants are present.
        flag = rc4(FALLBACK_KEY, FALLBACK_CT).decode("ascii")
    print(flag)


if __name__ == "__main__":
    main()
