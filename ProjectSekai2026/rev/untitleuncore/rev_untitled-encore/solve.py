#!/usr/bin/env python3
from __future__ import annotations

import struct
import sys
from pathlib import Path
from typing import Iterable

try:
    import pefile
    from unicorn import (
        Uc,
        UcError,
        UC_ARCH_X86,
        UC_HOOK_CODE,
        UC_HOOK_MEM_INVALID,
        UC_MODE_64,
    )
    from unicorn.x86_const import (
        UC_X86_REG_R8,
        UC_X86_REG_RAX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDX,
        UC_X86_REG_RIP,
        UC_X86_REG_RSP,
    )
except ImportError as exc:
    raise SystemExit(
        "Dependency belum tersedia. Jalankan: pip install pefile unicorn"
    ) from exc

ROOT = Path(__file__).resolve().parent
EXE = ROOT / "untitled-encore.exe"

# RVA fungsi dan thunk yang dipakai jalur validasi.
RVA_CHECK_CHART = 0x9D30
RVA_THROW = 0x62A0
RVA_MALLOC = 0xC824
RVA_FREE = 0xC81E
RVA_MEMCPY = 0xC7F4
RVA_MEMMOVE = 0xC7FA
RVA_MEMSET = 0xC800
RVA_MEMCMP = 0xC7EE
RVA_STRLEN = 0xC818

TARGET_SUMMARY = (
    0xD75245E2,
    0x3BBE10E9,
    0x3C500F48,
    0x01EBD885,
    [56, 34, 54, 33, 65],
    [97, 73, 60],
)


def rol32(value: int, count: int) -> int:
    count &= 31
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def extract_elf_rodata(exe_data: bytes) -> bytes:
    """Cari ELF eBPF ter-embed dan ambil section .rodata tanpa pyelftools."""
    elf_off = exe_data.find(b"\x7fELF")
    if elf_off < 0:
        raise ValueError("ELF eBPF tidak ditemukan")

    elf = exe_data[elf_off:]
    if elf[4] != 2 or elf[5] != 1:
        raise ValueError("Format ELF bukan ELF64 little-endian")

    e_shoff = struct.unpack_from("<Q", elf, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", elf, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", elf, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", elf, 0x3E)[0]

    def section_header(index: int) -> tuple[int, int, int]:
        off = e_shoff + index * e_shentsize
        sh_name = struct.unpack_from("<I", elf, off)[0]
        sh_offset = struct.unpack_from("<Q", elf, off + 0x18)[0]
        sh_size = struct.unpack_from("<Q", elf, off + 0x20)[0]
        return sh_name, sh_offset, sh_size

    _, shstr_off, shstr_size = section_header(e_shstrndx)
    shstr = elf[shstr_off : shstr_off + shstr_size]

    for index in range(e_shnum):
        name_off, sec_off, sec_size = section_header(index)
        end = shstr.find(b"\0", name_off)
        name = shstr[name_off:end]
        if name == b".rodata":
            return elf[sec_off : sec_off + sec_size]

    raise ValueError("Section .rodata tidak ditemukan")


def unpack_program(rodata: bytes) -> bytes:
    """Buka container custom: magic[14], type, skip, uint16 length, payload."""
    if len(rodata) < 18 or rodata[14] != 2:
        raise ValueError("Header container .rodata tidak cocok")

    skip = rodata[15]
    payload_len = struct.unpack_from("<H", rodata, 16)[0]
    payload_off = 18 + skip
    payload = rodata[payload_off : payload_off + payload_len]
    if len(payload) != payload_len:
        raise ValueError("Payload eBPF terpotong")
    return payload


def decode_program(payload: bytes) -> list[tuple[int, int, int, int]]:
    ops: list[tuple[int, int, int, int]] = []
    for offset in range(0, len(payload) - 3, 4):
        raw = payload[offset : offset + 4]
        op = raw[0] ^ ((offset * 0x11 + 0xA3) & 0xFF)
        a = raw[1] ^ ((offset * 0x1D + 0x11) & 0xFF)
        b = raw[2] ^ ((offset * 0x1F + 0x7B) & 0xFF)
        c = raw[3] ^ ((offset * 0x25 + 0xC5) & 0xFF)
        ops.append((op, a, b, c))
        if op == 0xF0:
            break
    if not ops or ops[-1][0] != 0xF0:
        raise ValueError("Opcode terminator 0xf0 tidak ditemukan")
    return ops


def recover_chart(ops: Iterable[tuple[int, int, int, int]]) -> bytes:
    ops = list(ops)
    state = 0x31C3F00D

    # Dua belas opcode pertama mengikat 8-byte seed dan panjang chart (40).
    prefix = ops[:12]
    if len(prefix) != 12 or any(op != 0x21 for op, _, _, _ in prefix):
        raise ValueError("Prefix opcode 0x21 tidak sesuai")

    context = bytearray(12)
    for op, a, b, c in prefix:
        if a >= len(context):
            raise ValueError("Indeks context di luar batas")
        context[a] = b
        state = ((((state + b) & 0xFFFFFFFF) ^ c) * 33 + a) & 0xFFFFFFFF

    if struct.unpack_from("<I", context, 8)[0] != 40:
        raise ValueError("Panjang chart pada context bukan 40")

    note_ops = ops[12:32]
    if len(note_ops) != 20 or any(op != 0x44 for op, _, _, _ in note_ops):
        raise ValueError("Blok opcode 0x44 tidak lengkap")

    solutions: list[bytes] = []
    chart: list[tuple[int, int] | None] = [None] * 20

    def dfs(pos: int, current_state: int) -> None:
        if len(solutions) > 1:
            return
        if pos == len(note_ops):
            packed = bytes(v for note in chart for v in note)  # type: ignore[arg-type]
            if summarize_chart(packed) == TARGET_SUMMARY:
                solutions.append(packed)
            return

        _, note_index, expected_fold, expected_low = note_ops[pos]
        if note_index >= 20 or chart[note_index] is not None:
            return

        for lane in range(5):
            for kind in range(3):
                for flick in range(2):
                    parity = (lane - note_index) & 1
                    packed_note = lane | (kind << 3) | (flick << 5) | (parity << 6)
                    for delta in range(3, 17):
                        mixed = (
                            packed_note * 17
                            + delta * 31
                            + current_state
                            + note_index * 73
                        ) & 0xFFFF
                        folded = ((mixed >> 8) ^ mixed) & 0xFF
                        if folded != expected_fold:
                            continue

                        next_state = (
                            (current_state ^ mixed)
                            + ((packed_note << 8) | delta)
                            + expected_fold
                        ) & 0xFFFFFFFF
                        next_state = rol32(next_state, (note_index & 7) + 1)
                        if (next_state & 0xFF) != expected_low:
                            continue

                        chart[note_index] = (packed_note, delta)
                        dfs(pos + 1, next_state)
                        chart[note_index] = None

    dfs(0, state)
    if len(solutions) != 1:
        raise ValueError(f"Chart valid tidak unik: {len(solutions)} solusi")
    return solutions[0]


def summarize_chart(chart: bytes) -> tuple[int, int, int, int, list[int], list[int]]:
    if len(chart) != 40:
        raise ValueError("Chart harus tepat 40 byte")

    s0 = 0x6D697275
    s1 = 0x6E656E65
    s2 = 0x6B616E61
    bitset = 0
    previous = 0
    lane_sum = [0] * 5
    kind_sum = [0] * 3

    for index in range(20):
        packed_note = chart[index * 2]
        delta = chart[index * 2 + 1]
        lane = packed_note & 7
        kind = (packed_note >> 3) & 3
        flick = (packed_note >> 5) & 1
        parity = (packed_note >> 6) & 1

        if lane > 4 or kind > 2 or not 3 <= delta <= 16:
            raise ValueError("Field note di luar rentang")
        if parity != ((lane - index) & 1):
            raise ValueError("Parity note salah")

        value = delta * 120 + previous + ((index ^ lane) & 3)
        s0 = rol32(
            (
                s0
                + delta * 0x119DE1F3
                + (lane + 1) * 0x045D9F3B
                + index
            )
            & 0xFFFFFFFF,
            (kind + 1) * 3 + flick,
        )

        packed = ((((delta << 8) | packed_note) << 16) | (value & 0xFFFF))
        s1 ^= rol32(packed & 0xFFFFFFFF, lane + index)
        s2 = (s2 + (s1 ^ s0) + (kind + 17) * (flick + 3)) & 0xFFFFFFFF

        position = (5 * lane + kind + value // 120) % 25
        bitset |= 1 << position
        lane_sum[lane] += 5 * flick + 3 * kind + parity + delta
        kind_sum[kind] += (index & 3) + lane + delta
        previous = value

    return s0, s1, s2, bitset, lane_sum, kind_sum


def emulate_verifier(exe_path: Path, chart: bytes) -> bytes:
    """Jalankan fungsi check_chart asli dengan Unicorn dan stub CRT minimum."""
    pe = pefile.PE(str(exe_path))
    base = pe.OPTIONAL_HEADER.ImageBase
    image = pe.get_memory_mapped_image()
    image_size = (len(image) + 0xFFF) & ~0xFFF

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(base, image_size)
    uc.mem_write(base, image)

    heap_base, heap_size = 0x20000000, 0x02000000
    stack_base, stack_size = 0x30000000, 0x00400000
    object_base = 0x40000000
    uc.mem_map(heap_base, heap_size)
    uc.mem_map(stack_base, stack_size)
    uc.mem_map(object_base, 0x10000)

    heap_ptr = heap_base + 0x1000
    sentinel = base + 0x100
    chart_data = object_base + 0x1000
    chart_vector = object_base + 0x100
    output_vector = object_base + 0x200

    uc.mem_write(chart_data, chart)
    uc.mem_write(
        chart_vector,
        struct.pack("<QQQ", chart_data, chart_data + len(chart), chart_data + len(chart)),
    )
    uc.mem_write(output_vector, b"\0" * 0x100)

    hooks = {
        base + RVA_MALLOC: "malloc",
        base + RVA_FREE: "free",
        base + RVA_MEMCPY: "memcpy",
        base + RVA_MEMMOVE: "memmove",
        base + RVA_MEMSET: "memset",
        base + RVA_MEMCMP: "memcmp",
        base + RVA_STRLEN: "strlen",
    }
    failure: list[str] = []

    def reg(register: int) -> int:
        return uc.reg_read(register)

    def function_return(value: int | None = None) -> None:
        rsp = reg(UC_X86_REG_RSP)
        return_address = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
        if value is not None:
            uc.reg_write(UC_X86_REG_RAX, value & 0xFFFFFFFFFFFFFFFF)
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, return_address)

    def code_hook(machine: Uc, address: int, size: int, user_data: object) -> None:
        nonlocal heap_ptr
        if address == sentinel:
            machine.emu_stop()
            return
        if address == base + RVA_THROW:
            failure.append("Verifier melempar exception")
            machine.emu_stop()
            return

        name = hooks.get(address)
        if name is None:
            return

        if name == "malloc":
            requested = reg(UC_X86_REG_RCX)
            allocation_size = max((requested + 15) & ~15, 16)
            result = heap_ptr
            heap_ptr += allocation_size
            if heap_ptr >= heap_base + heap_size:
                failure.append("Heap emulasi habis")
                machine.emu_stop()
                return
            machine.mem_write(result, b"\0" * allocation_size)
            function_return(result)
        elif name == "free":
            function_return(0)
        elif name in ("memcpy", "memmove"):
            destination = reg(UC_X86_REG_RCX)
            source = reg(UC_X86_REG_RDX)
            length = reg(UC_X86_REG_R8)
            if length:
                machine.mem_write(destination, bytes(machine.mem_read(source, length)))
            function_return(destination)
        elif name == "memset":
            destination = reg(UC_X86_REG_RCX)
            value = reg(UC_X86_REG_RDX) & 0xFF
            length = reg(UC_X86_REG_R8)
            if length:
                machine.mem_write(destination, bytes([value]) * length)
            function_return(destination)
        elif name == "memcmp":
            left = bytes(machine.mem_read(reg(UC_X86_REG_RCX), reg(UC_X86_REG_R8)))
            right = bytes(machine.mem_read(reg(UC_X86_REG_RDX), reg(UC_X86_REG_R8)))
            result = (left > right) - (left < right)
            function_return(result & 0xFFFFFFFF)
        elif name == "strlen":
            pointer = reg(UC_X86_REG_RCX)
            length = 0
            while machine.mem_read(pointer + length, 1)[0] != 0:
                length += 1
            function_return(length)

    def invalid_memory_hook(
        machine: Uc,
        access: int,
        address: int,
        size: int,
        value: int,
        user_data: object,
    ) -> bool:
        failure.append(
            f"Akses memori invalid di 0x{address:x}, RIP=0x{reg(UC_X86_REG_RIP):x}"
        )
        return False

    uc.hook_add(UC_HOOK_CODE, code_hook)
    uc.hook_add(UC_HOOK_MEM_INVALID, invalid_memory_hook)

    rsp = (stack_base + stack_size - 0x1000) & ~0xF
    rsp -= 8
    uc.mem_write(rsp, struct.pack("<Q", sentinel))
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.reg_write(UC_X86_REG_RCX, output_vector)
    uc.reg_write(UC_X86_REG_RDX, chart_vector)

    try:
        uc.emu_start(base + RVA_CHECK_CHART, sentinel, count=100_000_000)
    except UcError as exc:
        details = failure[-1] if failure else str(exc)
        raise RuntimeError(f"Emulasi verifier gagal: {details}") from exc

    if failure:
        raise RuntimeError(failure[-1])

    begin, end, capacity = struct.unpack("<QQQ", uc.mem_read(output_vector, 24))
    if not (begin <= end <= capacity) or end - begin > 0x1000:
        raise RuntimeError("Objek output verifier tidak valid")
    return bytes(uc.mem_read(begin, end - begin))


def main() -> None:
    if not EXE.is_file():
        raise SystemExit(f"File tidak ditemukan: {EXE}")

    exe_data = EXE.read_bytes()
    rodata = extract_elf_rodata(exe_data)
    payload = unpack_program(rodata)
    ops = decode_program(payload)
    chart = recover_chart(ops)
    flag = emulate_verifier(EXE, chart)

    try:
        flag_text = flag.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"Output verifier bukan ASCII: {flag.hex()}") from exc

    print(f"chart = {chart.hex()}")
    print(f"flag  = {flag_text}")


if __name__ == "__main__":
    main()
