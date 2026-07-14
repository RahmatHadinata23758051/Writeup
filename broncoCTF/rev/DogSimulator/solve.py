#!/usr/bin/env python3
from __future__ import annotations

import platform
import re
import struct
import subprocess
import sys
from pathlib import Path

FLAG_RE = re.compile(rb"bronco\{[^}\r\n]+\}")

# This 12-letter string is an FNV-1a preimage for 0x9f58d866.
# It completes the hidden Fetch -> Sit -> Bark -> Speak combo.
COMBO_COMMAND = b"aaaaeywnadhg"
SECOND_COMMAND = b"gremlin"

PAYLOAD = b"".join(
    [
        b"\n",          # Press Enter to begin
        b"2\n",         # Day 1: Fetch
        b"3\n",         # Day 2: Sit
        b"1\n",         # Day 3: Bark
        b"6\n",         # Day 4: Speak
        COMBO_COMMAND + b"\n",
        b"4\n",         # Day 5: Eat
        b"6\n",         # Day 6: Speak
        SECOND_COMMAND + b"\n",
    ]
)


def fnv1a_lower_alpha(data: bytes) -> int:
    value = 0x811C9DC5
    for byte in data:
        char = chr(byte)
        if char.isalpha():
            value ^= ord(char.lower())
            value = (value * 0x01000193) & 0xFFFFFFFF
    return value


def solve_native(binary: Path) -> bytes:
    binary.chmod(binary.stat().st_mode | 0o111)
    result = subprocess.run(
        [str(binary.resolve())],
        input=PAYLOAD,
        capture_output=True,
        timeout=10,
        check=False,
    )
    output = result.stdout + result.stderr
    match = FLAG_RE.search(output)
    if not match:
        raise RuntimeError(
            f"Flag tidak ditemukan. Exit code: {result.returncode}\n"
            + output.decode("utf-8", errors="replace")
        )
    return match.group(0)


def solve_with_unicorn(binary: Path) -> bytes:
    try:
        from unicorn import Uc, UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM
        from unicorn.arm64_const import (
            UC_ARM64_REG_PC,
            UC_ARM64_REG_SP,
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X1,
            UC_ARM64_REG_X2,
            UC_ARM64_REG_X30,
        )
    except ImportError as exc:
        raise SystemExit(
            "Unicorn belum terpasang. Jalankan: python3 -m pip install unicorn"
        ) from exc

    blob = binary.read_bytes()
    if blob[:4] != b"\xcf\xfa\xed\xfe":
        raise ValueError("File bukan Mach-O 64-bit little-endian")

    base = 0x100000000
    entry = 0x100000500
    stop_address = 0x100001310

    stack_base = 0x70000000
    stack_size = 0x200000
    stack_top = stack_base + stack_size - 0x100

    fake_base = 0x60000000

    stubs = {
        0x100001390: "maskrune",
        0x10000139C: "stackfail",
        0x1000013A8: "tolower",
        0x1000013B4: "atoi",
        0x1000013C0: "clearerr",
        0x1000013CC: "fflush",
        0x1000013D8: "fgets",
        0x1000013E4: "printf",
        0x1000013F0: "putchar",
        0x1000013FC: "puts",
        0x100001408: "snprintf",
        0x100001414: "strlen",
    }

    lines = iter(PAYLOAD.splitlines(keepends=True))
    output_lines: list[bytes] = []

    emulator = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    emulator.mem_map(base, 0x8000)
    emulator.mem_write(base, blob[:0x8000])
    emulator.mem_map(stack_base, stack_size)
    emulator.mem_map(fake_base, 0x20000)

    locale = fake_base + 0x1000
    guard = fake_base + 0x100
    stdin_pointer = fake_base + 0x200
    stdout_pointer = fake_base + 0x208

    emulator.mem_write(0x100004000, struct.pack("<Q", locale))
    emulator.mem_write(0x100004018, struct.pack("<Q", guard))
    emulator.mem_write(0x100004020, struct.pack("<Q", stdin_pointer))
    emulator.mem_write(0x100004028, struct.pack("<Q", stdout_pointer))

    emulator.mem_write(guard, struct.pack("<Q", 0x123456789ABCDEF0))
    emulator.mem_write(stdin_pointer, struct.pack("<Q", fake_base + 0x300))
    emulator.mem_write(stdout_pointer, struct.pack("<Q", fake_base + 0x308))

    # dyld normally rebases these local pointer tables.
    pointer_tables = {
        0x100004080: [
            0x1000018FD,
            0x10000191D,
            0x10000193C,
            0x100001958,
            0x10000197F,
            0x10000199E,
        ],
        0x1000040B0: [
            0x100001A4D,
            0x100001A61,
            0x100001A79,
            0x100001A9C,
        ],
        0x1000040D0: [
            0x100001B38,
            0x100001B3D,
            0x100001B43,
            0x100001B52,
        ],
    }
    for address, values in pointer_tables.items():
        emulator.mem_write(
            address,
            b"".join(struct.pack("<Q", value) for value in values),
        )

    # Minimal __DefaultRuneLocale table. Bit 0x100 marks alphabetic runes.
    for value in range(128):
        flags = 0x100 if chr(value).isalpha() else 0
        emulator.mem_write(locale + 0x3C + value * 4, struct.pack("<I", flags))

    emulator.reg_write(UC_ARM64_REG_SP, stack_top)
    emulator.reg_write(UC_ARM64_REG_X30, fake_base + 0x1F000)

    def read_c_string(address: int, limit: int = 4096) -> bytes:
        data = bytearray()
        for offset in range(limit):
            byte = emulator.mem_read(address + offset, 1)[0]
            if byte == 0:
                break
            data.append(byte)
        return bytes(data)

    def return_from_stub(value: int = 0) -> None:
        emulator.reg_write(UC_ARM64_REG_X0, value & 0xFFFFFFFFFFFFFFFF)
        emulator.reg_write(UC_ARM64_REG_PC, emulator.reg_read(UC_ARM64_REG_X30))

    def hook_code(uc: Uc, address: int, size: int, user_data: object) -> None:
        if address == stop_address:
            uc.emu_stop()
            return

        name = stubs.get(address)
        if name is None:
            return

        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)

        if name == "fgets":
            try:
                data = next(lines)
            except StopIteration:
                return_from_stub(0)
                return
            data = data[: max(0, x1 - 1)]
            uc.mem_write(x0, data + b"\0")
            return_from_stub(x0)
            return

        if name == "atoi":
            try:
                value = int(read_c_string(x0).strip() or b"0")
            except ValueError:
                value = 0
            return_from_stub(value)
            return

        if name == "strlen":
            return_from_stub(len(read_c_string(x0)))
            return

        if name == "tolower":
            value = x0 & 0xFF
            return_from_stub(ord(chr(value).lower()) if value < 128 else value)
            return

        if name == "maskrune":
            return_from_stub(0)
            return

        if name == "snprintf":
            stack_pointer = uc.reg_read(UC_ARM64_REG_SP)
            argument_pointer = struct.unpack(
                "<Q", uc.mem_read(stack_pointer, 8)
            )[0]
            format_string = read_c_string(x2)
            argument = read_c_string(argument_pointer)
            rendered = format_string.replace(b"%s", argument)[: max(0, x1 - 1)]
            uc.mem_write(x0, rendered + b"\0")
            return_from_stub(len(rendered))
            return

        if name == "puts":
            output_lines.append(read_c_string(x0))
            return_from_stub(0)
            return

        if name == "stackfail":
            raise RuntimeError("Stack canary failure during emulation")

        # printf, putchar, fflush, and clearerr do not affect the state machine.
        return_from_stub(0)

    emulator.hook_add(UC_HOOK_CODE, hook_code)
    emulator.emu_start(entry, fake_base + 0x1F000, count=1_000_000)

    output = b"\n".join(output_lines)
    match = FLAG_RE.search(output)
    if not match:
        raise RuntimeError(
            "Flag tidak ditemukan pada output emulasi:\n"
            + output.decode("utf-8", errors="replace")
        )
    return match.group(0)


def main() -> None:
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else "dog-sim-mac")
    if not binary.is_file():
        raise SystemExit(f"Binary tidak ditemukan: {binary}")

    if len(COMBO_COMMAND) != 12:
        raise AssertionError("Combo command harus berisi 12 huruf")
    if fnv1a_lower_alpha(COMBO_COMMAND) != 0x9F58D866:
        raise AssertionError("Combo command tidak memenuhi hash tersembunyi")

    if platform.system() == "Darwin":
        flag = solve_native(binary)
    else:
        flag = solve_with_unicorn(binary)

    print(flag.decode("ascii"))


if __name__ == "__main__":
    main()
