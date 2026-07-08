#!/usr/bin/env python3
"""Extract the anti-screenshot WinAPI import from a PE executable."""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


class PEError(Exception):
    pass


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


class PEImports:
    def __init__(self, data: bytes):
        self.data = data
        self.sections: list[Section] = []
        self.is_pe64 = False
        self.import_rva = 0
        self._parse_headers()

    def u16(self, off: int) -> int:
        return struct.unpack_from("<H", self.data, off)[0]

    def u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, off)[0]

    def u64(self, off: int) -> int:
        return struct.unpack_from("<Q", self.data, off)[0]

    def cstring(self, off: int) -> str:
        end = self.data.find(b"\x00", off)
        if end < 0:
            raise PEError("unterminated string")
        return self.data[off:end].decode("ascii", errors="replace")

    def _parse_headers(self) -> None:
        if len(self.data) < 0x40 or self.data[:2] != b"MZ":
            raise PEError("not an MZ executable")

        pe_off = self.u32(0x3C)
        if self.data[pe_off : pe_off + 4] != b"PE\x00\x00":
            raise PEError("invalid PE signature")

        coff = pe_off + 4
        section_count = self.u16(coff + 2)
        optional_size = self.u16(coff + 16)
        optional = coff + 20
        magic = self.u16(optional)

        if magic == 0x20B:  # PE32+
            self.is_pe64 = True
            data_directory = optional + 112
        elif magic == 0x10B:  # PE32
            self.is_pe64 = False
            data_directory = optional + 96
        else:
            raise PEError(f"unsupported optional-header magic: 0x{magic:x}")

        # IMAGE_DIRECTORY_ENTRY_IMPORT = 1
        self.import_rva = self.u32(data_directory + 8)
        section_table = optional + optional_size

        for index in range(section_count):
            off = section_table + index * 40
            raw_name = self.data[off : off + 8].split(b"\x00", 1)[0]
            self.sections.append(
                Section(
                    name=raw_name.decode("ascii", errors="replace"),
                    virtual_size=self.u32(off + 8),
                    virtual_address=self.u32(off + 12),
                    raw_size=self.u32(off + 16),
                    raw_offset=self.u32(off + 20),
                )
            )

    def rva_to_offset(self, rva: int) -> int:
        for section in self.sections:
            span = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + span:
                return section.raw_offset + (rva - section.virtual_address)
        raise PEError(f"RVA 0x{rva:x} is outside mapped sections")

    def imports(self) -> dict[str, list[str]]:
        if self.import_rva == 0:
            return {}

        result: dict[str, list[str]] = {}
        descriptor = self.rva_to_offset(self.import_rva)
        thunk_size = 8 if self.is_pe64 else 4
        ordinal_mask = 1 << (63 if self.is_pe64 else 31)

        while True:
            original_first_thunk = self.u32(descriptor)
            name_rva = self.u32(descriptor + 12)
            first_thunk = self.u32(descriptor + 16)
            if original_first_thunk == name_rva == first_thunk == 0:
                break

            dll = self.cstring(self.rva_to_offset(name_rva)).lower()
            thunk_rva = original_first_thunk or first_thunk
            thunk = self.rva_to_offset(thunk_rva)
            names: list[str] = []

            while True:
                value = self.u64(thunk) if self.is_pe64 else self.u32(thunk)
                if value == 0:
                    break
                if not value & ordinal_mask:
                    hint_name = self.rva_to_offset(value)
                    names.append(self.cstring(hint_name + 2))
                thunk += thunk_size

            result[dll] = names
            descriptor += 20

        return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", default="fuoverflow_learning.exe")
    args = parser.parse_args()

    path = Path(args.binary)
    if not path.is_file():
        print(f"[-] file not found: {path}", file=sys.stderr)
        return 1

    try:
        imported = PEImports(path.read_bytes()).imports()
    except (OSError, PEError, struct.error) as exc:
        print(f"[-] failed to parse PE: {exc}", file=sys.stderr)
        return 1

    candidates = {
        "setwindowdisplayaffinity": "SetWindowDisplayAffinity",
    }

    for dll, functions in imported.items():
        lowered = {name.lower(): name for name in functions}
        for normalized, canonical in candidates.items():
            if normalized in lowered:
                print(f"[+] DLL      : {dll}")
                print(f"[+] Function : {canonical}")
                print(f"[+] Flag     : LYKNCTF{{{normalized}}}")
                return 0

    print("[-] no known anti-screenshot API found", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
