#!/usr/bin/env python3
"""
Solver for scriptCTF REV challenge "F**K" / funk.

The file is a Brainfuck program.  It validates the flag with a timing/step-count
side channel: for every correct byte, fewer Brainfuck instructions are executed.
This solver interprets the program and brute-forces each printable byte by
choosing the candidate with the lowest instruction count.
"""

import argparse
import string
from pathlib import Path
from typing import Dict, List, Tuple

Instruction = Tuple[str, int, int]  # op, argument, original source offset


def compile_brainfuck(src: str) -> Tuple[List[Instruction], Dict[int, int]]:
    """Compress Brainfuck source and build jump table over compressed ops."""
    ops: List[Instruction] = []
    i = 0

    while i < len(src):
        c = src[i]

        if c in "+-":
            start = i
            delta = 0
            while i < len(src) and src[i] in "+-":
                delta += 1 if src[i] == "+" else -1
                i += 1
            delta %= 256
            if delta:
                ops.append(("add", delta, start))
            continue

        if c in "<>":
            start = i
            delta = 0
            while i < len(src) and src[i] in "<>":
                delta += 1 if src[i] == ">" else -1
                i += 1
            if delta:
                ops.append(("mov", delta, start))
            continue

        if c in "[],.":
            ops.append((c, 0, i))
        i += 1

    stack: List[int] = []
    jump: Dict[int, int] = {}
    for idx, (op, _, _) in enumerate(ops):
        if op == "[":
            stack.append(idx)
        elif op == "]":
            if not stack:
                raise ValueError("unmatched ']' in Brainfuck program")
            j = stack.pop()
            jump[idx] = j
            jump[j] = idx
    if stack:
        raise ValueError("unmatched '[' in Brainfuck program")

    return ops, jump


class BFRunner:
    def __init__(self, ops: List[Instruction], jump: Dict[int, int]):
        self.ops = ops
        self.jump = jump

    def run(self, data: bytes, max_steps: int = 5_000_000) -> Tuple[int, int]:
        """
        Return (executed_steps, number_of_input_reads).

        The challenge ends with a deliberate infinite empty loop.  For scoring,
        stop when such a trap is reached, because every tested candidate reaches
        the same trap and the interesting signal is the step count before it.
        """
        tape = [0] * 4096
        ptr = 0
        pc = 0
        ip = 0
        steps = 0

        while pc < len(self.ops) and steps < max_steps:
            op, arg, _src_off = self.ops[pc]
            steps += 1

            if op == "add":
                tape[ptr] = (tape[ptr] + arg) & 0xFF
            elif op == "mov":
                ptr += arg
                if ptr < 0:
                    raise RuntimeError("tape pointer moved below zero")
                if ptr >= len(tape):
                    tape.extend([0] * len(tape))
            elif op == ".":
                pass
            elif op == ",":
                tape[ptr] = data[ip] if ip < len(data) else 0
                ip += 1
            elif op == "[":
                # Empty [] with non-zero current cell is an intentional hang.
                if tape[ptr] != 0 and self.jump[pc] == pc + 1:
                    break
                if tape[ptr] == 0:
                    pc = self.jump[pc]
            elif op == "]":
                if tape[ptr] != 0:
                    pc = self.jump[pc]

            pc += 1

        return steps, ip


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve the funk Brainfuck challenge")
    parser.add_argument("program", nargs="?", default="funk", help="path to Brainfuck program")
    parser.add_argument(
        "--charset",
        default=string.printable[:-6],  # ASCII 0x20..0x7e
        help="candidate characters to try",
    )
    args = parser.parse_args()

    src = Path(args.program).read_text(errors="ignore")
    ops, jump = compile_brainfuck(src)
    runner = BFRunner(ops, jump)

    # Discover how many input bytes are actually consumed before the final trap.
    _, flag_len = runner.run(b"A" * 128)
    print(f"[+] compiled ops : {len(ops)}")
    print(f"[+] input length : {flag_len}")

    # Use a neutral printable base.  In this challenge the cost is separable per
    # byte, so the minimum score for each position reveals the expected char.
    flag = bytearray(b"?" * flag_len)
    charset = args.charset.encode()

    for pos in range(flag_len):
        best_ch = None
        best_steps = None

        for ch in charset:
            trial = bytearray(flag)
            trial[pos] = ch
            steps, _ = runner.run(bytes(trial))

            if best_steps is None or steps < best_steps:
                best_steps = steps
                best_ch = ch

        assert best_ch is not None
        flag[pos] = best_ch
        print(f"[+] pos {pos:02d}: {chr(best_ch)!r}  steps={best_steps}  current={flag.decode()}")

    print(f"\nFLAG: {flag.decode()}")


if __name__ == "__main__":
    main()
