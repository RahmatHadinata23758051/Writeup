#!/usr/bin/env python3
from pathlib import Path


ROM_PATH = Path(__file__).with_name("main.bin")


def load_memory():
    rom = ROM_PATH.read_bytes()
    mem = bytearray(4096)
    mem[0x200 : 0x200 + len(rom)] = rom
    return mem


def solve():
    mem = load_memory()

    def step_state(a, b):
        old_a, old_b = a, b

        v0 = mem[0x800 + b] ^ b
        v0 ^= {
            0x00: 0xA9,
            0x40: 0x5C,
            0x80: 0xD3,
            0xC0: 0x76,
        }[b & 0xC0]

        s = b + v0
        b = s & 0xFF
        carry = 1 if s > 0xFF else 0
        a = (a + carry) & 0xFF

        # The rotate/mix part uses the original VA/VB saved in V2/V3.
        v2, v3 = old_a, old_b
        for _ in range(5):
            s = v3 + v3
            v3 = s & 0xFF
            c3 = 1 if s > 0xFF else 0

            s = v2 + v2
            v2 = s & 0xFF
            c2 = 1 if s > 0xFF else 0

            v2 |= c3
            v3 |= c2

        a ^= v2
        b ^= v3

        # The CHIP-8 routine stores VA/VB here after each PRNG step.
        mem[0x58B] = a
        mem[0x58C] = b
        return a, b

    cycle_cache = {}

    def advance(a, b, n):
        key = (a, b)
        if key not in cycle_cache:
            seen = {}
            states = []
            aa, bb = a, b
            while (aa, bb) not in seen:
                seen[(aa, bb)] = len(states)
                states.append((aa, bb))
                aa, bb = step_state(aa, bb)
            cycle_cache[key] = (seen[(aa, bb)], states)

        cycle_start, states = cycle_cache[key]
        if n < len(states):
            return states[n]

        period = len(states) - cycle_start
        return states[cycle_start + (n - cycle_start) % period]

    def counter_value(v9, vc, vd, ve):
        return v9 + 256 * vc + 65536 * vd + 16777216 * ve

    def table_base(a):
        return [0x400, 0x460, 0x4C0, 0x520, 0x600, 0x660, 0x6C0, 0x720][a & 7]

    a, b = 0xA7, 0xC3
    pc = 0x916
    out = []

    while pc < 0xDB6:
        if mem[pc : pc + 4] == bytes.fromhex("65ff22ac"):
            # CALL 0x2ac repeats 0xffffffff PRNG steps 0xff times.
            a, b = advance(a, b, 0xFFFFFFFF * 0xFF)
            pc += 4
        else:
            assert mem[pc] == 0x69
            assert mem[pc + 2] == 0x6C
            assert mem[pc + 4] == 0x6D
            assert mem[pc + 6] == 0x6E
            assert mem[pc + 8 : pc + 10] == b"\x22\x82"

            n = counter_value(mem[pc + 1], mem[pc + 3], mem[pc + 5], mem[pc + 7])
            a, b = advance(a, b, n)
            pc += 10

        assert mem[pc : pc + 8] == bytes.fromhex("80a0610780122322")
        offset = mem[pc + 9]
        addr = table_base(a) + offset
        ch = mem[addr] ^ a ^ b
        out.append(ch)

        # The ROM mutates this lookup byte after decoding the character.
        mem[addr] = b

        assert mem[pc + 28 : pc + 30] == b"\x2d\xd2"
        pc += 30

    return bytes(out).decode()


if __name__ == "__main__":
    print(solve())
