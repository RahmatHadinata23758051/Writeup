
from pathlib import Path
import struct

BIN = Path("rev_backrooms.exe")
TARGET_VA = 0x142F3F978
NBYTES = 60


def pe_va_to_offset(data: bytes, va: int) -> int:
    """Translate a PE virtual address to file offset."""
    pe = data.find(b"PE\0\0")
    if pe < 0:
        raise ValueError("PE header not found")

    coff = pe + 4
    number_of_sections = struct.unpack_from("<H", data, coff + 2)[0]
    optional_header_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20

    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20B:
        raise ValueError("expected PE32+ binary")
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    rva = va - image_base

    sec = opt + optional_header_size
    for i in range(number_of_sections):
        sh = sec + i * 40
        name = data[sh:sh + 8].rstrip(b"\0").decode(errors="replace")
        virtual_size, virtual_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, sh + 8)
        size = max(virtual_size, raw_size)
        if virtual_addr <= rva < virtual_addr + size:
            return raw_ptr + (rva - virtual_addr)

    raise ValueError(f"VA {va:#x} is not inside a section")


def ror8(x: int, n: int) -> int:
    n &= 7
    return ((x >> n) | ((x << (8 - n)) & 0xFF)) & 0xFF


def decode_bytes(enc: bytes) -> bytes:
    # This mirrors the loop at 0x140005276..0x14000536e.
    seed = 0xA3F1924D
    add_key = 0xDB
    out = []
    for i, c in enumerate(enc):
        seed = (seed * 0x41C64E6D + 0x3039) & 0xFFFFFFFF
        v = (c + add_key) & 0xFF
        v = ror8(v, (i % 7) + 1)
        v ^= (seed >> 16) & 0xFF
        out.append(v)
        add_key = (add_key + 0xF3) & 0xFF
    return bytes(out)


def bytes_to_glyphs(decoded: bytes) -> str:
    # The binary writes every decoded byte as 8 bits, then uses it as a
    # 4-row x 120-column bitmap. Each glyph is 4 columns wide.
    bits = []
    for b in decoded:
        bits.extend((b >> (7 - i)) & 1 for i in range(8))

    rows = ["".join("#" if bits[y * 120 + x] else "." for x in range(120)) for y in range(4)]

    font = {
        (".##.", "#...", "#...", ".##."): "C",
        ("###.", "#.#.", "#.#.", "###."): "O",
        ("##..", "###.", "#.#.", "#.#."): "M",
        ("###.", "#.#.", "###.", "#..."): "P",
        ("###.", "#...", "##..", "#..."): "F",
        ("###.", "##..", "#...", "###."): "E",
        (".##.", "##..", "..#.", "##.."): "S",
        ("###.", ".#..", ".#..", ".#.."): "T",
        ("##..", ".#..", ".#..", "###."): "1",
        (".##.", "###.", "#.#.", "###."): "8",
        ("..#.", "##..", ".#..", "..#."): "{",
        ("#.#.", "###.", "#.#.", "#.#."): "H",
        ("....", "....", "....", "###."): "_",
        ("###.", ".#..", ".#..", "###."): "I",
        ("##..", ".##.", "#...", "###."): "2",
        (".#..", "#.#.", "#.#.", ".#.."): "0",
        ("#.#.", "#.#.", ".#..", ".#.."): "Y",
        ("###.", "#.#.", "###.", "#.#."): "A",
        ("###.", "#.#.", "##..", "#.#."): "R",
        ("#...", "#...", "#...", "###."): "L",
        ("##..", "#.#.", "#.#.", "##.."): "D",
        ("#...", ".##.", ".#..", "#..."): "}",
    }

    chars = []
    for x in range(0, 120, 4):
        glyph = tuple(row[x:x + 4] for row in rows)
        chars.append(font[glyph])
    return "".join(chars)


def main() -> None:
    data = BIN.read_bytes()
    off = pe_va_to_offset(data, TARGET_VA)
    enc = data[off:off + NBYTES]
    decoded = decode_bytes(enc)
    flag = bytes_to_glyphs(decoded)
    print(flag)


if __name__ == "__main__":
    main()
