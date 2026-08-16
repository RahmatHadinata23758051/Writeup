#!/usr/bin/env python3
from pathlib import Path
import re
import struct

EXE_PATH = Path("BlackFrost.exe")
PCAP_PATH = Path("traffic.pcap")

# Disassembly shows the encrypted flag blob is read from VA 0x140003080.
# The image base in this PE is 0x140000000, so the RVA is 0x3080.
FLAG_BLOB_RVA = 0x3080
FLAG_BLOB_LEN = 34

REQUIRED_MARKERS = (
    b"campaign=BLACKFROST-26;",
    b"nonce=4c2f17;",
    b"directive=collect-only;",
)


def rva_to_offset(pe: bytes, rva: int) -> int:
    """Map a PE RVA to file offset using the section table."""
    if pe[:2] != b"MZ":
        raise ValueError("not a PE/MZ file")

    pe_off = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe[pe_off:pe_off + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature")

    number_of_sections = struct.unpack_from("<H", pe, pe_off + 6)[0]
    size_of_optional_header = struct.unpack_from("<H", pe, pe_off + 20)[0]
    section_table = pe_off + 24 + size_of_optional_header

    for i in range(number_of_sections):
        off = section_table + 40 * i
        name = pe[off:off + 8].rstrip(b"\0")
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", pe, off + 8)
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            return raw_ptr + (rva - virtual_address)

    raise ValueError(f"RVA 0x{rva:x} is not inside any section")


def decrypt_bf2(hex_payload: str, seed: int) -> bytes:
    """Reverse the BF2 packet decoder used by BlackFrost.exe."""
    cipher = bytes.fromhex(hex_payload)
    out = bytearray()
    add_key = 0x5A

    for i, b in enumerate(cipher):
        # Assembly uses (r8d & 0x18) as shift count, with r8 += 8 each byte.
        seed_byte = (seed >> ((i * 8) & 0x18)) & 0xFF
        out.append(b ^ seed_byte ^ (add_key & 0xFF))
        add_key = (add_key + 0x11) & 0xFFFFFFFF

    return bytes(out)


def decrypt_flag_blob(blob: bytes) -> str:
    """Reverse the small XOR loop at 0x140001777."""
    if len(blob) != FLAG_BLOB_LEN:
        raise ValueError("unexpected flag blob length")

    out = bytearray()
    key = 0x26

    for i in range(0, FLAG_BLOB_LEN, 2):
        out.append(blob[i] ^ ((key - 0x0D) & 0xFF))
        out.append(blob[i + 1] ^ key)
        key = (key + 0x1A) & 0xFF

    return out.decode("ascii")


def main() -> None:
    pe = EXE_PATH.read_bytes()
    pcap = PCAP_PATH.read_bytes()

    hello = re.search(rb"BFHELLO\s+([0-9a-fA-F]{8})", pcap)
    bf2 = re.search(rb"BF2:([0-9a-fA-F]+)", pcap)
    if not hello or not bf2:
        raise RuntimeError("BFHELLO/BF2 transcript not found in pcap")

    seed = int(hello.group(1), 16)
    config = decrypt_bf2(bf2.group(1).decode("ascii"), seed)

    print(f"[+] seed from BFHELLO: 0x{seed:08x}")
    print(f"[+] decoded BF2 config: {config.decode('ascii')}")

    missing = [m for m in REQUIRED_MARKERS if m not in config]
    if missing:
        raise RuntimeError(f"decoded config is missing marker(s): {missing!r}")

    flag_off = rva_to_offset(pe, FLAG_BLOB_RVA)
    flag_blob = pe[flag_off:flag_off + FLAG_BLOB_LEN]
    flag = decrypt_flag_blob(flag_blob)

    print(f"[+] flag blob file offset: 0x{flag_off:x}")
    print(f"[+] flag: {flag}")


if __name__ == "__main__":
    main()
