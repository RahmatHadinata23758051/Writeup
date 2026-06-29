#!/usr/bin/env python3
"""Solver for V1T CTF 2026 - Herd Mentality.

The script reads Herd.exe and Orchestrator.exe directly from the supplied ZIP,
recreates the shared-memory pond, synthesizes the required event history, and
executes the original validation/decryption routines with Unicorn.
"""

from __future__ import annotations

import argparse
import struct
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Iterable

try:
    import pefile
    from unicorn import (
        Uc,
        UC_ARCH_X86,
        UC_HOOK_CODE,
        UC_HOOK_MEM_INVALID,
        UC_MODE_64,
        UC_PROT_ALL,
    )
    from unicorn.x86_const import (
        UC_X86_REG_GS_BASE,
        UC_X86_REG_R8,
        UC_X86_REG_R9,
        UC_X86_REG_RAX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDX,
        UC_X86_REG_RIP,
        UC_X86_REG_RSP,
    )
except ImportError as exc:
    raise SystemExit(
        "Missing dependency. Install with: pip install pefile unicorn"
    ) from exc

IMAGE_BASE = 0x140000000
SHARED_BASE = 0x20000000
STACK_BASE = 0x30000000
STUB_BASE = 0x50000000
GS_BASE = 0x60000000
MASK32 = 0xFFFFFFFF

# Relevant function/global VAs in the two challenge binaries.
ORCH_SELECT_CANDIDATES = 0x140001520
ORCH_PROMOTE = 0x140002530
ORCH_SHARED_PTR = 0x140027CF0
ORCH_MUTEX = 0x140027CD8
ORCH_UNUSED_HANDLE = 0x140026A80

HERD_BUILD_PACKET = 0x140001680
HERD_DECRYPT_SHARD = 0x1400022F0
HERD_TOKEN = 0x140003120
HERD_SLOT_INDEX = 0x140025A74
HERD_PID = 0x140026CA0
HERD_SHARED_PTR = 0x140026CC0
HERD_MUTEX = 0x140026CB0

PACKET_ADDR = SHARED_BASE + 0x4000
PROMOTE_OUT_ADDR = SHARED_BASE + 0x5000

STEP_TABLE = [3, 7, 9, 11, 13, 17, 19, 21, 23, 27, 29, 31, 33, 37, 39, 41, 43, 47, 49]
RELATION_SET_SIZES = [10, 15, 20]

# (event_type, required_role, required_count)
STAGE_PATTERNS = [
    [],
    [(1, 2, 1)],
    [(2, 3, 2)],
    [(3, 5, 1)],
    [(2, 4, 1), (1, 3, 1)],
    [(3, 2, 1), (1, 5, 1)],
]


def u32(value: int) -> int:
    return value & MASK32


def mix(value: int) -> int:
    value = u32(value)
    value ^= value >> 16
    value = u32(value * 0x7FEB352D)
    value ^= value >> 15
    value = u32(value * 0x846CA68B)
    value ^= value >> 16
    return u32(value)


def read_u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def write_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, u32(value))


def load_challenge(path: Path) -> tuple[bytes, bytes]:
    """Return (Herd.exe, Orchestrator.exe) without extracting the archive."""
    if path.is_dir():
        herd_path = next(path.rglob("Herd.exe"), None)
        orch_path = next(path.rglob("Orchestrator.exe"), None)
        if herd_path is None or orch_path is None:
            raise FileNotFoundError("Herd.exe or Orchestrator.exe not found")
        return herd_path.read_bytes(), orch_path.read_bytes()

    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        herd_name = next((name for name in names if Path(name).name.lower() == "herd.exe"), None)
        orch_name = next(
            (name for name in names if Path(name).name.lower() == "orchestrator.exe"),
            None,
        )
        if herd_name is None or orch_name is None:
            raise FileNotFoundError("ZIP does not contain Herd.exe and Orchestrator.exe")
        return archive.read(herd_name), archive.read(orch_name)


class PEEmulator:
    """Small Windows x64 PE harness for the challenge's internal functions."""

    def __init__(self, image: bytes, name: str):
        self.name = name
        self.pe = pefile.PE(data=image)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        image_size = (self.pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF

        self.uc.mem_map(IMAGE_BASE, image_size, UC_PROT_ALL)
        mapped = self.pe.get_memory_mapped_image()[: self.pe.OPTIONAL_HEADER.SizeOfImage]
        self.uc.mem_write(IMAGE_BASE, mapped)
        self.uc.mem_map(SHARED_BASE, 0x10000, UC_PROT_ALL)
        self.uc.mem_map(STACK_BASE, 0x40000, UC_PROT_ALL)
        self.uc.mem_map(STUB_BASE, 0x10000, UC_PROT_ALL)
        self.uc.mem_map(GS_BASE, 0x3000, UC_PROT_ALL)

        self.uc.reg_write(UC_X86_REG_GS_BASE, GS_BASE)
        self.write_u64(GS_BASE + 0x60, GS_BASE + 0x1000)
        self.uc.mem_write(GS_BASE + 0x1000 + 0xBC, b"\x00")

        self.tick_count = 1000
        self.stop_address: int | None = None
        self.stub_names: dict[int, str] = {}
        self._install_import_stubs()
        self.uc.hook_add(UC_HOOK_CODE, self._code_hook)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self._invalid_memory)

    def _install_import_stubs(self) -> None:
        imports: dict[str, int] = {}
        for entry in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []):
            for symbol in entry.imports:
                if symbol.name:
                    imports[symbol.name.decode()] = symbol.address

        names = [
            "WaitForSingleObject",
            "ReleaseMutex",
            "Sleep",
            "GetTickCount",
            "IsDebuggerPresent",
            "GetCurrentProcess",
            "CheckRemoteDebuggerPresent",
            "GetTempPathA",
            "CreateFileA",
            "WriteFile",
            "ReadFile",
            "CloseHandle",
        ]
        for index, name in enumerate(names):
            if name not in imports:
                continue
            stub = STUB_BASE + index * 0x20
            self.stub_names[stub] = name
            self.write_u64(imports[name], stub)
            self.uc.mem_write(stub, b"\xC3")

    def _invalid_memory(self, uc: Uc, access: int, address: int, size: int, value: int, _user: object) -> bool:
        rip = uc.reg_read(UC_X86_REG_RIP)
        raise RuntimeError(
            f"{self.name}: invalid memory access at {address:#x}, size={size}, rip={rip:#x}"
        )

    def _return_from_stub(self, value: int = 0) -> None:
        rsp = self.uc.reg_read(UC_X86_REG_RSP)
        return_address = self.read_u64(rsp)
        self.uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        self.uc.reg_write(UC_X86_REG_RAX, value & 0xFFFFFFFFFFFFFFFF)
        self.uc.reg_write(UC_X86_REG_RIP, return_address)

    def _code_hook(self, uc: Uc, address: int, _size: int, _user: object) -> None:
        if self.stop_address is not None and address == self.stop_address:
            uc.emu_stop()
            return

        name = self.stub_names.get(address)
        if name is None:
            return

        if name in {"WaitForSingleObject", "Sleep"}:
            self._return_from_stub(0)
        elif name == "ReleaseMutex":
            self._return_from_stub(1)
        elif name == "GetTickCount":
            self._return_from_stub(self.tick_count)
        elif name == "IsDebuggerPresent":
            self._return_from_stub(0)
        elif name == "GetCurrentProcess":
            self._return_from_stub(0xFFFFFFFFFFFFFFFF)
        elif name == "CheckRemoteDebuggerPresent":
            output = uc.reg_read(UC_X86_REG_RDX)
            self.write_u32(output, 0)
            self._return_from_stub(1)
        elif name == "GetTempPathA":
            output = uc.reg_read(UC_X86_REG_RDX)
            temp_path = b"C:\\Temp\\\x00"
            uc.mem_write(output, temp_path)
            self._return_from_stub(len(temp_path) - 1)
        elif name == "CreateFileA":
            self._return_from_stub(0xFFFFFFFFFFFFFFFF)
        elif name in {"WriteFile", "ReadFile"}:
            written = uc.reg_read(UC_X86_REG_R9)
            if written:
                self.write_u32(written, 0)
            self._return_from_stub(0)
        elif name == "CloseHandle":
            self._return_from_stub(1)

    def write_u32(self, address: int, value: int) -> None:
        self.uc.mem_write(address, struct.pack("<I", u32(value)))

    def write_u64(self, address: int, value: int) -> None:
        self.uc.mem_write(address, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))

    def read_u32(self, address: int) -> int:
        return struct.unpack("<I", self.uc.mem_read(address, 4))[0]

    def read_u64(self, address: int) -> int:
        return struct.unpack("<Q", self.uc.mem_read(address, 8))[0]

    def set_shared(self, data: bytes | bytearray) -> None:
        self.uc.mem_write(SHARED_BASE, bytes(data))

    def get_shared(self) -> bytes:
        return bytes(self.uc.mem_read(SHARED_BASE, 0x2000))

    def call(self, address: int, *arguments: int, instruction_limit: int = 20_000_000) -> int:
        stack_pointer = (STACK_BASE + 0x3E000) & ~0xF
        stack_pointer -= 8
        stop = STUB_BASE + 0xFF00
        self.write_u64(stack_pointer, stop)
        self.uc.mem_write(stop, b"\x90")
        self.uc.reg_write(UC_X86_REG_RSP, stack_pointer)

        registers = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
        for register, value in zip(registers, arguments):
            self.uc.reg_write(register, value)

        self.stop_address = stop
        self.uc.emu_start(address, stop, count=instruction_limit)
        self.stop_address = None
        return self.uc.reg_read(UC_X86_REG_RAX)


class HerdSolver:
    def __init__(self, herd_image: bytes, orchestrator_image: bytes):
        self.herd = PEEmulator(herd_image, "Herd.exe")
        self.orchestrator = PEEmulator(orchestrator_image, "Orchestrator.exe")

        self.orchestrator.write_u64(ORCH_SHARED_PTR, SHARED_BASE)
        self.orchestrator.write_u64(ORCH_MUTEX, 1)
        self.orchestrator.write_u64(ORCH_UNUSED_HANDLE, 0xFFFFFFFFFFFFFFFF)
        self.herd.write_u64(HERD_SHARED_PTR, SHARED_BASE)
        self.herd.write_u64(HERD_MUTEX, 1)

        self.seed = 0x12345678
        self.shared = self._initial_shared_state()

    def _initial_shared_state(self) -> bytearray:
        shared = bytearray(0x2000)
        state = mix(self.seed ^ 0xC0A1C0DE)
        secondary = u32(mix(self.seed ^ state ^ 0x6D2B79F5) ^ state ^ 0x9C3E7A11)

        write_u32(shared, 0x00, 0x48443256)
        write_u32(shared, 0x04, self.seed)
        write_u32(shared, 0x08, state)
        write_u32(shared, 0x0C, secondary)
        shared[0x36:0x3C] = b"\xFF" * 6
        shared[0x3C] = 0xFF

        for slot in range(100):
            offset = 0x238 + 24 * slot
            pid = 10000 + slot
            group = slot // 10
            write_u32(shared, offset + 0x00, pid)
            write_u32(shared, offset + 0x04, 0)
            write_u32(
                shared,
                offset + 0x08,
                mix(
                    self.seed
                    + state * 2
                    ^ group * 0x27D4EB2D
                    ^ slot * 0x045D9F3B
                    ^ pid
                ),
            )
            write_u32(shared, offset + 0x0C, mix(group * 0x9E3779B9 ^ self.seed))
            shared[offset + 0x10] = slot
            shared[offset + 0x11] = group
            write_u32(shared, offset + 0x12, 0x10000)

        self.orchestrator.set_shared(shared)
        self.orchestrator.call(ORCH_SELECT_CANDIDATES)
        return bytearray(self.orchestrator.get_shared())

    def _relation_sets(self) -> list[set[int]]:
        current = read_u32(self.shared, 0x1C)
        state = read_u32(self.shared, 0x08)
        candidates = set(self.shared[0x36:0x3C])
        result: list[set[int]] = []

        for depth in range(3):
            base = (
                u32(0x5803BBEC - depth * 0x37FEC15C)
                ^ u32((current + 1) * 0xA341316C)
                ^ state
                ^ self.seed
            )
            hashed = mix(base)
            cursor = hashed % 100
            step = STEP_TABLE[(hashed >> 8) % len(STEP_TABLE)]
            selected: list[int] = []

            for _ in range(400):
                if len(selected) >= RELATION_SET_SIZES[depth]:
                    break
                slot = cursor % 100
                slot_offset = 0x238 + 24 * slot
                valid = (
                    read_u32(self.shared, slot_offset) != 0
                    and slot not in candidates
                    and all(slot not in previous for previous in result)
                )
                if valid:
                    selected.append(slot)
                cursor = u32(cursor + step)

            if len(selected) != RELATION_SET_SIZES[depth]:
                raise RuntimeError(f"failed to generate relation set {depth}")
            result.append(set(selected))

        return result

    def _roles(self) -> list[int]:
        current = read_u32(self.shared, 0x1C)
        candidate = self.shared[0x36 + current] if current < 6 else 0xFF
        relation_sets = self._relation_sets()
        roles: list[int] = []

        for slot in range(100):
            offset = 0x238 + 24 * slot
            if read_u32(self.shared, offset) == 0 or self.shared[offset + 0x12] & 4:
                role = 0
            elif slot == candidate:
                role = 1
            elif slot in relation_sets[0]:
                role = 5
            elif slot in relation_sets[1]:
                role = 2
            elif slot in relation_sets[2]:
                role = 3
            else:
                role = 4
            roles.append(role)

        return roles

    def _token_for(self, slot: int, role: int) -> int:
        self.herd.set_shared(self.shared)
        self.herd.write_u32(HERD_SLOT_INDEX, slot)
        self.herd.write_u32(HERD_PID, 10000 + slot)
        token = self.herd.call(HERD_TOKEN, role, instruction_limit=1_000_000) & MASK32
        write_u32(self.shared, 0x238 + 24 * slot + 0x08, token)
        return token

    def _append_event(self, slot: int, event_type: int) -> None:
        sequence = read_u32(self.shared, 0x14) + 1
        tick = read_u32(self.shared, 0x10)
        event_offset = 0xB98 + 20 * (sequence & 127)
        slot_offset = 0x238 + 24 * slot
        pid = read_u32(self.shared, slot_offset)
        token = read_u32(self.shared, slot_offset + 0x08)
        state = read_u32(self.shared, 0x08)

        write_u32(self.shared, event_offset + 0x00, sequence)
        write_u32(self.shared, event_offset + 0x04, tick)
        write_u32(self.shared, event_offset + 0x08, mix(pid ^ self.seed ^ sequence))
        write_u32(self.shared, event_offset + 0x0C, mix(token ^ state ^ event_type))
        self.shared[event_offset + 0x10] = slot
        self.shared[event_offset + 0x11] = event_type
        self.shared[event_offset + 0x12 : event_offset + 0x14] = b"\x00\x00"
        write_u32(self.shared, 0x14, sequence)

        if event_type == 1:
            self.shared[slot_offset + 0x12] |= 3
        elif event_type == 2:
            self.shared[slot_offset + 0x12] |= 4
            self.shared[slot_offset + 0x14] = 0
        elif event_type == 3:
            self.shared[slot_offset + 0x12] |= 8

    def _build_packet(self, stage: int) -> bytes:
        self.herd.set_shared(self.shared)
        self.herd.uc.mem_write(PACKET_ADDR, b"\x00" * 0x100)
        self.herd.call(HERD_BUILD_PACKET, stage, PACKET_ADDR, instruction_limit=15_000_000)
        packet = bytes(self.herd.uc.mem_read(PACKET_ADDR, 0x80))
        if packet[11] != 1 or packet[9] != 100:
            raise RuntimeError(
                f"stage {stage} packet is not satisfied: "
                f"relations={packet[6]}, counts={list(packet[7:9])}, confidence={packet[9]}"
            )
        return packet

    def _acquire_shard(self, stage: int, roles: Iterable[int], packet: bytes) -> bytes:
        self.herd.set_shared(self.shared)
        self.herd.uc.mem_write(PACKET_ADDR, packet)

        for slot, role in enumerate(roles):
            if role == 0:
                continue
            self.herd.write_u32(HERD_SLOT_INDEX, slot)
            self.herd.write_u32(HERD_PID, 10000 + slot)
            self.herd.call(
                HERD_DECRYPT_SHARD,
                stage,
                role,
                PACKET_ADDR,
                instruction_limit=8_000_000,
            )
            self.shared = bytearray(self.herd.get_shared())
            self.herd.set_shared(self.shared)
            self.herd.uc.mem_write(PACKET_ADDR, packet)

            record = 0x40 + 40 * stage
            if self.shared[record + 5] & 1:
                length = self.shared[record + 4]
                return bytes(self.shared[record + 8 : record + 8 + length])

        raise RuntimeError(f"unable to acquire both halves of shard {stage}")

    def _activate_after_first_shard(self) -> None:
        baseline = read_u32(self.shared, 0x14)
        old_state = read_u32(self.shared, 0x08)
        write_u32(self.shared, 0x18, baseline)
        self.shared[0x3D] = 0

        new_state = mix(baseline ^ old_state ^ 0xB16B00B5)
        new_secondary = u32(
            mix(new_state ^ self.seed ^ baseline ^ 0xDA56F3EA)
            ^ new_state
            ^ 0x274F91C5
        )
        write_u32(self.shared, 0x08, new_state)
        write_u32(self.shared, 0x0C, new_secondary)

    def _promote(self, expected_stage: int) -> None:
        self.orchestrator.set_shared(self.shared)
        self.orchestrator.write_u32(PROMOTE_OUT_ADDR, 0xDEADBEEF)
        promoted = self.orchestrator.call(
            ORCH_PROMOTE, PROMOTE_OUT_ADDR, instruction_limit=10_000_000
        )
        self.shared = bytearray(self.orchestrator.get_shared())
        promoted_stage = self.orchestrator.read_u32(PROMOTE_OUT_ADDR)
        if promoted != 1 or promoted_stage != expected_stage:
            raise RuntimeError(
                f"promotion failed: return={promoted}, stage={promoted_stage}, "
                f"expected={expected_stage}"
            )

    def solve(self) -> tuple[bytes, list[bytes]]:
        shards: list[bytes] = []

        roles = self._roles()
        packet = self._build_packet(0)
        shards.append(self._acquire_shard(0, roles, packet))
        self._activate_after_first_shard()

        for stage in range(1, 6):
            roles = self._roles()
            used_slots: set[int] = set()

            for event_type, required_role, count in STAGE_PATTERNS[stage]:
                choices = [
                    slot
                    for slot, role in enumerate(roles)
                    if role == required_role and slot not in used_slots
                ]
                if len(choices) < count:
                    raise RuntimeError(
                        f"stage {stage}: insufficient role {required_role}; "
                        f"roles={Counter(roles)}"
                    )

                for slot in choices[:count]:
                    self._token_for(slot, required_role)
                    self._append_event(slot, event_type)
                    used_slots.add(slot)

            packet = self._build_packet(stage)
            shards.append(self._acquire_shard(stage, roles, packet))

            if stage < 5:
                self._promote(stage)

        flag = b"".join(shards)
        if not (flag.startswith(b"v1t{") and flag.endswith(b"}")):
            raise RuntimeError(f"unexpected plaintext: {flag!r}")
        return flag, shards


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Solve Herd Mentality")
    parser.add_argument(
        "challenge",
        nargs="?",
        default="HerdMentality.zip",
        type=Path,
        help="path to HerdMentality.zip or an extracted challenge directory",
    )
    parser.add_argument(
        "--show-shards",
        action="store_true",
        help="print each recovered crown shard before the final flag",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        herd_image, orchestrator_image = load_challenge(args.challenge)
        flag, shards = HerdSolver(herd_image, orchestrator_image).solve()
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    if args.show_shards:
        for index, shard in enumerate(shards):
            print(f"stage {index}: {shard.decode('ascii')}")
    print(flag.decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
