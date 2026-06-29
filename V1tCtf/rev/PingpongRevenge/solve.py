#!/usr/bin/env python3
"""Offline solver for V1T CTF 2026 - Ducks Ping-Pong.

The driver normally validates three FNV-1a hashes and returns key material to
Ducks_Ping-Pong.exe.  This solver reconstructs the successful driver state from
both PE files, then emulates only the final user-mode decode routine.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

try:
    import pefile
    from unicorn import Uc, UcError, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64
    from unicorn.x86_const import (
        UC_X86_REG_RAX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDX,
        UC_X86_REG_R8,
        UC_X86_REG_RIP,
        UC_X86_REG_RSP,
    )
except ImportError as exc:
    raise SystemExit(
        "Missing dependency. Run: python3 -m pip install pefile unicorn"
    ) from exc

MASK64 = (1 << 64) - 1


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def p32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def p64(value: int) -> bytes:
    return struct.pack("<Q", value & MASK64)


def mapped_image(path: Path) -> tuple[pefile.PE, bytearray]:
    pe = pefile.PE(str(path))
    size = (pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF
    image = bytearray(pe.get_memory_mapped_image())
    image.extend(b"\x00" * (size - len(image)))
    return pe, image


def extract_driver_material(driver: bytes) -> tuple[list[int], list[int], bytes]:
    # movabs immediates used by IOCTL 0x222000 to validate the three FNV hashes.
    expected_hashes = [
        u64(driver, 0x14D2),
        u64(driver, 0x14E3),
        u64(driver, 0x14F5),
    ]

    # .rdata table selected after a successful hash comparison.
    response_keys = [u64(driver, 0x32B0 + i * 8) for i in range(3)]

    # Extra 16-byte block returned only for stage 1.
    extra_block = bytes(driver[0x32A0:0x32B0])
    return expected_hashes, response_keys, extra_block


def emulate_final_decode(
    exe_pe: pefile.PE,
    exe_image: bytearray,
    stage_state: list[int],
    extra_block: bytes,
) -> bytes:
    base = exe_pe.OPTIONAL_HEADER.ImageBase
    image_size = len(exe_image)

    # The final routine calls the local printf wrapper and stack-cookie helper.
    # They are irrelevant to the flag transform, so replace both with RET.
    exe_image[0x1020] = 0xC3
    exe_image[0x2000] = 0xC3

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(base, image_size)
    uc.mem_write(base, bytes(exe_image))

    stub_base = 0x180000000
    stack_base = 0x200000000
    heap_base = 0x210000000
    stop_addr = stub_base + 0x1F0000

    uc.mem_map(stub_base, 0x200000)
    uc.mem_map(stack_base, 0x20000)
    uc.mem_map(heap_base, 0x1000)
    uc.mem_write(stop_addr, b"\x90")

    rsp = stack_base + 0x18000
    uc.mem_write(rsp, p64(stop_addr))
    uc.reg_write(UC_X86_REG_RSP, rsp)

    # Main decrypts a 16-byte heap key from RVA 0x34e0 with XOR 0x55.
    heap_key = bytes(byte ^ 0x55 for byte in exe_image[0x34E0:0x34F0])
    uc.mem_write(heap_base, heap_key)

    # Recreate globals that would exist after three successful IOCTL 0x222000 calls.
    for rva, value in zip((0x56F0, 0x56F8, 0x5700), stage_state):
        uc.mem_write(base + rva, p64(value))

    uc.mem_write(base + 0x5758, extra_block)
    uc.mem_write(base + 0x5708, p32(3))       # local VEH stage counter
    uc.mem_write(base + 0x56E8, p64(1))       # fake VEH handle
    uc.mem_write(base + 0x5778, p64(heap_base))
    uc.mem_write(base + 0x5078, p64(3))       # fake device handle
    uc.mem_write(base + 0x5768, p64(0x4444555566667777))

    imports: dict[int, str] = {}
    stub_index = 0
    for descriptor in exe_pe.DIRECTORY_ENTRY_IMPORT:
        for imp in descriptor.imports:
            name = imp.name.decode() if imp.name else f"ord_{imp.ordinal}"
            stub = stub_base + stub_index * 0x100
            stub_index += 1
            uc.mem_write(stub, b"\xC3")
            uc.mem_write(imp.address, p64(stub))
            imports[stub] = name

    output = bytearray()

    def emulate_return(value: int = 0) -> None:
        current_rsp = uc.reg_read(UC_X86_REG_RSP)
        return_address = u64(bytes(uc.mem_read(current_rsp, 8)), 0)
        uc.reg_write(UC_X86_REG_RSP, current_rsp + 8)
        uc.reg_write(UC_X86_REG_RAX, value & MASK64)
        uc.reg_write(UC_X86_REG_RIP, return_address)

    def code_hook(machine: Uc, address: int, _size: int, _user_data: object) -> None:
        if address == stop_addr:
            machine.emu_stop()
            return

        name = imports.get(address)
        if name is None:
            return

        if name == "DeviceIoControl":
            current_rsp = machine.reg_read(UC_X86_REG_RSP)
            ioctl = machine.reg_read(UC_X86_REG_RDX)
            out_buffer = u64(bytes(machine.mem_read(current_rsp + 0x28, 8)), 0)
            bytes_returned = u64(bytes(machine.mem_read(current_rsp + 0x38, 8)), 0)

            if ioctl != 0x222008:
                emulate_return(0)
                return

            # Successful query: magic + completed stage count.
            machine.mem_write(out_buffer, p32(0xE7DE0322) + p32(3))
            if bytes_returned:
                machine.mem_write(bytes_returned, p32(8))
            emulate_return(1)
            return

        if name == "putchar":
            char = machine.reg_read(UC_X86_REG_RCX) & 0xFF
            output.append(char)
            emulate_return(char)
            return

        if name == "ExitProcess":
            machine.emu_stop()
            return

        if name == "GetProcessHeap":
            emulate_return(0x5555)
            return

        if name in {
            "HeapFree",
            "RemoveVectoredExceptionHandler",
            "CloseHandle",
        }:
            emulate_return(1)
            return

        if name == "getchar":
            emulate_return(10)
            return

        # No other imported function affects the final transform on this path.
        emulate_return(0)

    uc.hook_add(UC_HOOK_CODE, code_hook)

    try:
        uc.emu_start(base + 0x1570, stop_addr + 1)
    except UcError as exc:
        rip = uc.reg_read(UC_X86_REG_RIP)
        raise RuntimeError(f"emulation failed at {rip:#x}: {exc}") from exc

    return bytes(output)


def main() -> int:
    root = Path(__file__).resolve().parent
    exe_path = root / "Ducks_Ping-Pong.exe"
    driver_path = root / "DucksKD.sys"

    if not exe_path.is_file() or not driver_path.is_file():
        print("Place Ducks_Ping-Pong.exe and DucksKD.sys beside solve.py", file=sys.stderr)
        return 1

    exe_pe, exe_image = mapped_image(exe_path)
    _driver_pe, driver_image = mapped_image(driver_path)

    expected_hashes, response_keys, extra_block = extract_driver_material(driver_image)

    # User mode stores: FNV_target XOR driver_response_key.
    stage_state = [a ^ b for a, b in zip(expected_hashes, response_keys)]
    flag = emulate_final_decode(exe_pe, exe_image, stage_state, extra_block)

    try:
        decoded = flag.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"decoded output is not ASCII: {flag.hex()}") from exc

    if not (decoded.startswith("v1t{") and decoded.endswith("}")):
        raise SystemExit(f"unexpected output: {decoded!r}")

    print(decoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
