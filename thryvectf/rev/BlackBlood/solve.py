#!/usr/bin/env python3
from pathlib import Path
import lzma
import os
import re
import stat
import subprocess

MASK = (1 << 64) - 1
M1 = 0xbf58476d1ce4e5b9
M2 = 0x94d049bb133111eb
C_A = 0xa0761d6478bd642f
C_B = 0x8ebc6af09c88c6e3
C_C = 0xd6e8feb86659fd93
GOLD = 0x9e3779b97f4a7c15
CONST_FLAG = 1 << 104          # bit konstanta untuk persamaan GF(2)
N_BITS = 104                   # 13 byte input per ronde


def u64(x: int) -> int:
    return x & MASK


def rol(x: int, r: int) -> int:
    r &= 63
    return u64((x << r) | (x >> (64 - r)))


def ror(x: int, r: int) -> int:
    r &= 63
    return u64((x >> r) | (x << (64 - r)))


def splitmix(x: int) -> int:
    x = u64(x)
    x = u64((x ^ (x >> 30)) * M1)
    x = u64((x ^ (x >> 27)) * M2)
    return u64(x ^ (x >> 31))


def splitmix_no_first_xor(x: int) -> int:
    # Handler VM op 0x19 dan 0x6e mulai dari perkalian M1,
    # bukan dari tahap xor >> 30.
    x = u64(x * M1)
    x = u64((x ^ (x >> 27)) * M2)
    return u64(x ^ (x >> 31))


def parity64(x: int) -> int:
    return x.bit_count() & 1


def parity_mask_expr(mask: int, bit_offset: int) -> int:
    """Koefisien linear untuk parity(input_bits & mask)."""
    row = 0
    for bit in range(64):
        if (mask >> bit) & 1:
            row ^= 1 << (bit_offset + bit)
    return row


def solve_gf2(rows, n=N_BITS):
    """Solve persamaan linear GF(2). Bit ke-n adalah konstanta."""
    pivots = {}
    for row in rows:
        row &= (1 << (n + 1)) - 1
        while row:
            coeff = row & ((1 << n) - 1)
            if coeff == 0:
                if (row >> n) & 1:
                    raise ValueError("constraint inconsistent")
                break
            pivot = coeff.bit_length() - 1
            if pivot in pivots:
                row ^= pivots[pivot]
            else:
                pivots[pivot] = row
                break

    # Semua free variable dibuat 0. Di challenge ini rank = 104, jadi unik.
    sol = 0
    for pivot, row in sorted(pivots.items()):
        others = row & ((1 << n) - 1) & ~(1 << pivot)
        val = ((row >> n) & 1) ^ parity64(others & sol)
        if val:
            sol |= 1 << pivot
    return sol, len(pivots), n - len(pivots)


def extract_payload_from_7z(archive_path: Path, out_path: Path) -> bytes:
    """Extractor minimal untuk arsip 7z challenge ini.

    File 7z menyimpan ELF sebagai LZMA1 raw stream mulai offset 0x20.
    Kita tidak butuh 7z eksternal; cukup pakai modul lzma bawaan Python.
    """
    data = archive_path.read_bytes()
    if not data.startswith(b"7z\xbc\xaf\x27\x1c"):
        raise ValueError("not a 7z archive")

    next_header_offset = int.from_bytes(data[12:20], "little")
    compressed_area = data[32:32 + next_header_offset]
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 23, "lc": 3, "lp": 0, "pb": 2}]

    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
    payload = dec.decompress(compressed_area)
    if not payload.startswith(b"\x7fELF"):
        raise ValueError("decompressed data is not ELF")

    out_path.write_bytes(payload)
    out_path.chmod(out_path.stat().st_mode | stat.S_IXUSR)
    return payload


def get64(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 8], "little")


def get32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 4], "little")


def get16(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 2], "little")


def initial_globals(b: bytes):
    # Nilai awal ada di LOAD writable. Constructor .init_array memutasi dua qword ini.
    g10 = get64(b, 0x14010)
    g18 = get64(b, 0x14018)

    # init 0x21c0
    g18 = u64(rol(g18 ^ 0xf071dd5262dca406, 17) + 0x2bdf4d1ae947bb7c)
    g10 = u64(g10 ^ splitmix(g18))

    # init 0x2240
    g18 = u64(rol(g18 + 0xa450ffb79267f445, 29) ^ 0xcda2cc6ad9b3512a)
    g10 = u64(g10 + rol(g18, 7))

    # init 0x2290
    g18 = u64(splitmix(g18 ^ 0x339d7d9bd931bad2) + 0x8ab94c26a88c6e2b)
    g10 = u64(g10 ^ ror(g18, 23))
    return g10, g18


def decode_instr(b: bytes, round_idx: int, ip: int, seed: int, start: int):
    enc = get64(b, 0x6810 + (start + ip) * 8)
    mask = splitmix(u64((ip + 1) * C_B ^ seed ^ 0x589965cc75374cc3))
    instr = u64(enc ^ mask)
    low48 = instr & 0x0000ffffffffffff
    got = (instr >> 48) & 0xffff
    want = splitmix(u64((ip + 1) * C_C ^ seed ^ low48)) & 0xffff
    if got != want:
        raise ValueError(f"VM decode failed at round={round_idx} ip={ip}")
    return instr


def solve_round(b: bytes, round_idx: int, prev_state: int, g18: int):
    q = get64(b, 0x63c0 + round_idx * 8)
    t = get64(b, 0x6340 + round_idx * 8)
    length = get16(b, 0x62d0 + round_idx * 2)
    start = get32(b, 0x6300 + round_idx * 4)

    seed = splitmix(u64(g18 ^ prev_state ^ q ^ u64((round_idx + 1) * C_A)))
    rcx = splitmix(u64(0xe7037ed1a0b428db ^ (t ^ seed)))

    # State VM hanya memengaruhi out8. Constraint inputnya tetap linear di GF(2).
    slots = [0] * 8
    slots[0] = splitmix(seed)
    slots[1] = splitmix(rcx)
    slots[2] = splitmix(prev_state)
    slots[3] = splitmix(t)

    flags_expr = 0
    ebp_expr = 0
    mask30 = 0
    mask40 = 0
    rows = []

    ip = 0
    steps = 1
    while ip < length and steps != 0x2711:
        instr = decode_instr(b, round_idx, ip, seed, start)
        op = instr & 0xff
        f8 = (instr >> 8) & 0xff
        f16 = (instr >> 16) & 0xffff
        f32 = (instr >> 32) & 0xffff
        idx = f8 & 7
        next_ip = ip + 1

        if op == 0x07:
            h1 = splitmix(u64((f8 + 1) * GOLD ^ t ^ 0x243f6a8885a308d3))
            mask30 = h1
            mask40 = splitmix(u64((f8 + 1) * 0xd1b54a32d192ed03 ^ t ^ 0x13198a2e03707344)) & 0xffffffffff
            slots[idx] = u64(slots[idx] ^ splitmix(u64(f32 ^ h1 ^ mask40)))

        elif op == 0x19:
            # Membuat satu bit constraint: parity(qword awal) XOR parity(5 byte akhir).
            ebp_expr = parity_mask_expr(mask30, 0) ^ parity_mask_expr(mask40, 64)
            slots[idx] = u64(slots[idx] + splitmix_no_first_xor(u64(f32 + f16)))

        elif op == 0x6e:
            byte_index = f8 >> 3
            bit_index = f8 & 7
            h = splitmix(u64((byte_index + 1) * C_A ^ rcx ^ 0xe7037ed1a0b428db)) & 0xff
            table_byte = b[0x6760 + round_idx * 13 + byte_index]
            forced_bit = ((h ^ table_byte) >> bit_index) & 1
            if forced_bit:
                ebp_expr ^= CONST_FLAG
            slots[(f8 + 3) & 7] ^= splitmix_no_first_xor(u64(f32))

        elif op == 0x33:
            if ebp_expr:
                rows.append(ebp_expr)   # flag VM harus tetap 0
            ebp_expr = 0
            slots[idx] = rol(u64(f32 ^ flags_expr ^ slots[idx]), f16 + 1)

        elif op == 0x01:
            src = f16 & 7
            imm = instr & 0xffff00000000
            slots[idx] = u64(slots[src] ^ slots[idx] ^ imm)

        elif op == 0x29:
            imm = instr & 0xffff0000
            slots[idx] = splitmix(u64(f32 ^ (imm ^ ip) ^ slots[idx]))

        elif op == 0x40:
            slots[idx] = u64(rol(slots[idx], f16 + 1) ^ f32)

        elif op == 0xdf:
            off = f16 if f16 < 0x8000 else f16 - 0x10000
            next_ip = ip + off

        elif op == 0x55:
            break

        else:
            raise ValueError(f"unexpected VM opcode {op:#x} at round={round_idx} ip={ip}")

        ip = next_ip
        steps += 1

    sol, rank, free = solve_gf2(rows)
    if rank != N_BITS or free != 0:
        raise ValueError(f"round {round_idx}: expected unique 104-bit solution, rank={rank}, free={free}")

    answer = bytes((sol >> (8 * i)) & 0xff for i in range(13))

    first8 = int.from_bytes(answer[:8], "little")
    last5 = int.from_bytes(answer[8:13] + b"\0\0\0", "little")
    inner = splitmix(u64(rol(last5, 17) ^ first8 ^ 0x6a09e667f3bcc909))
    out8 = splitmix(u64((t ^ seed) ^ (q ^ inner)))
    return answer, out8


def solve_answers(payload: bytes):
    _, g18 = initial_globals(payload)
    prev_state = 0x5075fcdbf977489a
    k = GOLD
    answers = []
    for round_idx in range(13):
        ans, out8 = solve_round(payload, round_idx, prev_state, g18)
        answers.append(ans)
        q = get64(payload, 0x63c0 + round_idx * 8)
        prev_state = splitmix(u64(prev_state ^ out8 ^ q ^ k))
        k = u64(k + GOLD)
    return answers


def main():
    here = Path(__file__).resolve().parent
    os.chdir(here)
    archive = here / "pekaboo.7z"
    payload_path = here / "payload.bin"

    if payload_path.exists() and payload_path.read_bytes().startswith(b"\x7fELF"):
        payload = payload_path.read_bytes()
    else:
        payload = extract_payload_from_7z(archive, payload_path)

    answers = solve_answers(payload)
    answer_blob = b"\n".join(answers) + b"\n"
    (here / "answer.txt").write_bytes(answer_blob)

    print("Recovered 13 answers:")
    for i, ans in enumerate(answers, 1):
        print(f"{i:02d}: {ans.decode('latin1')}")

    print("\nRunning binary with recovered answers...\n")
    payload_path.chmod(payload_path.stat().st_mode | stat.S_IXUSR)
    proc = subprocess.run([str(payload_path)], input=answer_blob, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = proc.stdout.decode("latin1", errors="replace")
    print(output)

    m = re.search(r"Thryve\{[^}\n]+\}", output)
    if m:
        raw = m.group(0)
        # Binary memakai prefix legacy Thryve{}, sedangkan soal memberi format ThryveCTF{}.
        normalized = raw.replace("Thryve{", "ThryveCTF{", 1)
        print("Binary output flag:", raw)
        print("Challenge-format flag:", normalized)


if __name__ == "__main__":
    main()
