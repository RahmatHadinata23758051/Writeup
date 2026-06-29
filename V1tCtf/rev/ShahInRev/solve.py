#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1
TARGET_HASH = 0x3A9B7BAA7C919EC8


def rol8(value: int, count: int) -> int:
    value &= 0xFF
    count &= 7
    if count == 0:
        return value
    return ((value << count) | (value >> (8 - count))) & 0xFF


def ror8(value: int, count: int) -> int:
    return rol8(value, -count)


def rol64(value: int, count: int) -> int:
    count &= 63
    return ((value << count) | (value >> (64 - count))) & MASK64


class ShahinVM:
    def __init__(self, binary_path: Path):
        self.binary_path = binary_path
        self.binary = binary_path.read_bytes()
        if len(self.binary) < 0x1088F:
            raise ValueError("binary terlalu kecil atau bukan file Shahinrev yang sesuai")
        self.seed, self.ops = self._decode_instruction_stream()

    def _decode_instruction_stream(self):
        blob = self.binary

        # Hash beberapa region binary. Byte rendah hasil hash dipakai sebagai seed.
        regions = [
            (0x9480, 0x3950),
            (0x5B00, 0x3950),
            (0x2180, 0x3950),
            (0x10880, 15),
            (0x10780, 256),
            (0x2140, 45),
            (0x2100, 45),
        ]
        h = 0x811C9DC5
        for offset, size in regions:
            for byte in blob[offset : offset + size]:
                h = ((h ^ byte) * 0x1000193) & MASK32
                h ^= h >> 13

        seed = h & 0xFF
        seed32 = (seed * 5 + 0x1337) & MASK32

        # Tabel 15 byte ini memetakan byte opcode terenkripsi ke nomor opcode VM.
        opcode_map = {
            encoded: opcode
            for opcode, encoded in enumerate(blob[0x10880:0x1088F])
        }

        operations = []
        state = 0xCA
        carry_r14, carry_r15, carry_dl = 0x62, 0x12, 0xE2

        for iteration in range(100_000):
            r8 = state
            esi = (r8 * 8) & MASK32
            r9 = (r8 * 56 + 12) & MASK32
            ebp = (r8 * 248 + 109) & MASK32
            ebx = (r8 * 37 + seed + 17 * iteration) & MASK32
            r11 = (r8 * 1096 + 208) & MASK32
            r12 = (iteration + r8 + seed) & MASK32
            r10 = (r8 * 152 + 30) & MASK32
            r13 = (r8 * 104) & MASK32

            instruction = []
            r14, r15, dl = carry_r14, carry_r15, carry_dl

            for byte_index in range(8):
                al = rol8(((r13 & 0xFF) ^ 0xA7) + (ebx & 0xFF), r12)
                cl = ((esi >> 2) ^ ebp) ^ 0xB7
                decoded = (
                    al
                    ^ (cl & 0xFF)
                    ^ rol8(blob[0x9480 + esi], esi + 3)
                    ^ r14
                    ^ r15
                    ^ dl
                ) & 0xFF
                instruction.append(decoded)

                r13 = (r13 + 13) & MASK32
                r12 = (r12 + 1) & MASK32
                ebx = (ebx + 29) & MASK32
                ebp = (ebp + 31) & MASK32
                esi = (esi + 1) & MASK32

                if byte_index != 7:
                    r14 = blob[0xCE00 + (r11 % 0x3950)]
                    r15 = blob[0x5B00 + (r10 % 0x3950)]
                    dl = blob[0x2180 + (r9 % 0x3950)]
                    r11 = (r11 + 0x89) & MASK32
                    r10 = (r10 + 0x13) & MASK32
                    r9 = (r9 + 7) & MASK32

            checksum = (13 * iteration + seed + 7 * state) & 0xFF
            checksum ^= (
                instruction[0]
                ^ instruction[4]
                ^ instruction[6]
                ^ rol8(instruction[1], 1)
                ^ rol8(instruction[2], 2)
                ^ rol8(instruction[3], 3)
                ^ rol8(instruction[7], 4)
                ^ 0xA5
            )
            if checksum != instruction[5]:
                raise ValueError(f"checksum instruction gagal pada iterasi {iteration}")

            opcode = opcode_map[instruction[0]]
            base = (19 * state + 45 + 7 * iteration) % 53
            a = (instruction[1] + base) % 53
            b = (instruction[2] + base) % 53
            immediate = instruction[4]
            auxiliary = instruction[3]

            operations.append(
                (opcode, a, b, immediate, auxiliary, base, iteration)
            )

            if opcode == 14:  # HALT
                break

            next_mask = ((r8 * 17 + seed32 + 9 * iteration) ^ (r8 >> 3)) & 0xFFFF
            state = ((instruction[6] | (instruction[7] << 8)) ^ next_mask) & MASK32

            carry_r14 = blob[0xCE00 + ((state * 1096 + 0x47) % 0x3950)]
            carry_r15 = blob[0x5B00 + ((state * 152 + 0x0B) % 0x3950)]
            carry_dl = blob[0x2180 + ((state * 56 + 5) % 0x3950)]
        else:
            raise ValueError("opcode HALT tidak ditemukan")

        return seed, operations

    def _initial_tape(self, input_bytes: bytes | bytearray):
        if len(input_bytes) != 8:
            raise ValueError("VM membutuhkan tepat 8 byte")

        tape = list(input_bytes) + [0] * 45
        tape[8] = 0x80

        edi = 0x20
        r8 = 0xFFFFFFA0
        for index in range(9, 53):
            tape[index] = (
                self.binary[0x20F8 + index]
                ^ self.binary[0x2138 + index]
                ^ (r8 & 0xFF)
                ^ rol8(self.binary[0x10780 + (edi & 0xFF)], index)
            ) & 0xFF
            edi = (edi + 0x17) & MASK32
            r8 = (r8 + 0x29) & MASK32

        return tape

    def run(self, input_bytes: bytes | bytearray, stop_after=None, enforce=False):
        tape = self._initial_tape(input_bytes)
        hash_state = 0xCBF29CE484222325
        assertions_ok = True
        halted = False

        for op_index, (opcode, a, b, imm, aux, base, _iteration) in enumerate(self.ops):
            if stop_after is not None and op_index > stop_after:
                break

            if opcode == 0:       # NOP
                pass
            elif opcode == 1:     # XOR tape[a], tape[b]
                tape[a] ^= tape[b]
            elif opcode == 2:     # ADD tape[a], tape[b]
                tape[a] = (tape[a] + tape[b]) & 0xFF
            elif opcode == 3:     # SUB tape[a], tape[b]
                tape[a] = (tape[a] - tape[b]) & 0xFF
            elif opcode == 4:     # XOR immediate
                tape[a] ^= imm
            elif opcode == 5:     # ADD immediate
                tape[a] = (tape[a] + imm) & 0xFF
            elif opcode == 6:     # ROL
                tape[a] = rol8(tape[a], imm)
            elif opcode == 7:     # ROR
                tape[a] = ror8(tape[a], imm)
            elif opcode == 8:     # MUL odd immediate
                tape[a] = (tape[a] * (imm | 1)) & 0xFF
            elif opcode == 9:     # S-box
                tape[a] = self.binary[0x10780 + tape[a]]
            elif opcode == 10:    # SWAP
                tape[a], tape[b] = tape[b], tape[a]
            elif opcode == 11:    # mixed XOR/ADD/ROL
                shift = (((aux + base) % 53) ^ imm) & 7
                tape[a] ^= rol8((tape[b] + imm) & 0xFF, shift)
            elif opcode == 12:    # ASSERT tape[a] == immediate
                assertions_ok &= tape[a] == imm
                if enforce and not assertions_ok:
                    return tape, hash_state, False
            elif opcode == 13:    # hash byte
                value = (tape[a] + imm) & 0xFF
                mixed = (value * 0x100000001B3) & MASK64
                mixed = rol64(mixed ^ hash_state, 13)
                hash_state = (
                    mixed * 0xBF58476D1CE4E5B9 + 0x94D049BB133111EB
                ) & MASK64
            elif opcode == 14:    # HALT
                halted = True
                break
            else:
                raise ValueError(f"opcode VM tidak dikenal: {opcode}")

        valid = assertions_ok and halted and hash_state == TARGET_HASH
        return tape, hash_state, valid

    def recover(self) -> bytes:
        recovered = bytearray(8)

        # Setiap tuple: (posisi input, indeks opcode, sel tape, nilai ASSERT).
        # Urutannya dipilih agar dependency byte sebelumnya sudah diketahui.
        recovery_plan = [
            (6, 363, 39, 0x9B),
            (7, 364, 33, 0x33),
            (3, 366, 19, 0x82),
            (2, 368, 24, 0xCE),
            (4, 361, 15, 0x3E),
            (0, 730, 38, 0x26),
            (1, 1107, 51, 0x28),
            (5, 733, 19, 0xCE),
        ]

        for position, op_index, tape_index, expected in recovery_plan:
            matches = []
            for candidate in range(256):
                trial = bytearray(recovered)
                trial[position] = candidate
                tape, _, _ = self.run(trial, stop_after=op_index, enforce=False)
                if tape[tape_index] == expected:
                    matches.append(candidate)

            if len(matches) != 1:
                raise RuntimeError(
                    f"byte {position} tidak unik: {[hex(x) for x in matches]}"
                )

            recovered[position] = matches[0]
            print(f"[+] byte[{position}] = 0x{matches[0]:02x}")

        return bytes(recovered)


def main():
    binary_path = Path(sys.argv[1] if len(sys.argv) > 1 else "Shahinrev")
    if not binary_path.is_file():
        raise SystemExit(f"[-] binary tidak ditemukan: {binary_path}")

    vm = ShahinVM(binary_path)
    print(f"[*] seed VM       : 0x{vm.seed:02x}")
    print(f"[*] jumlah opcode : {len(vm.ops)}")

    raw = vm.recover()
    _, final_hash, valid = vm.run(raw, enforce=True)
    if not valid:
        raise SystemExit(f"[-] kandidat gagal, hash akhir 0x{final_hash:016x}")

    flag = f"V1t{{{raw.hex()}}}"
    print(f"[+] hash akhir    : 0x{final_hash:016x}")
    print(f"[+] flag          : {flag}")

    # Validasi tambahan menggunakan binary asli bila executable.
    if binary_path.stat().st_mode & 0o111:
        result = subprocess.run(
            [str(binary_path.resolve()), flag],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        output = (result.stdout + result.stderr).strip()
        print(f"[+] binary output : {output}")
        if result.returncode != 0 or "accepted" not in output:
            raise SystemExit("[-] binary asli menolak kandidat")


if __name__ == "__main__":
    main()
