#!/usr/bin/env python3
import argparse
import re
from pathlib import Path

MONTHS = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
]
DAYS = [
    "Monday", "Tuesday", "Wednesday", "Thursday",
    "Friday", "Saturday", "Sunday",
]
AREAS = ["Asia", "Africa", "the Americas", "Europe", "Australia"]

LINE_RE = re.compile(
    r"I see it now: you were born in "
    r"(January|February|March|April|May|June|July|August|September|October|November|December)"
    r"\.\.\. on a "
    r"(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), in "
    r"(Asia|Africa|the Americas|Europe|Australia)"
)
FLAG_RE = re.compile(rb"bronco\{[^}\r\n]+\}")


def recover_output_byte(month: str, day: str, area: str) -> int:
    """Recover guess in [0, 255] from its residues modulo 12, 7, and 5."""
    residues = (MONTHS.index(month), DAYS.index(day), AREAS.index(area))
    matches = [
        value
        for value in range(256)
        if value % 12 == residues[0]
        and value % 7 == residues[1]
        and value % 5 == residues[2]
    ]
    if len(matches) != 1:
        raise ValueError(
            f"oracle tuple is not unique: {(month, day, area)!r} -> {matches}"
        )
    return matches[0]


def parse_outputs(text: str) -> list[int]:
    observations = LINE_RE.findall(text)
    if not observations:
        raise ValueError("no oracle output lines were found")
    return [recover_output_byte(*observation) for observation in observations]


def infer_state_length(outputs: list[int]) -> int:
    """
    After one full schedule cycle of length n:
        a[t+n+1] = 2*a[t+n] - a[t] (mod 256)
    """
    candidates = []
    for n in range(1, len(outputs) // 2 + 1):
        checks = len(outputs) - n - 1
        if checks < n:
            continue
        if all(
            outputs[t + n + 1] == (2 * outputs[t + n] - outputs[t]) % 256
            for t in range(checks)
        ):
            candidates.append(n)

    if len(candidates) != 1:
        raise ValueError(f"could not uniquely infer state length: {candidates}")
    return candidates[0]


def recover_schedule_order_bytes(outputs: list[int], n: int) -> bytes:
    """
    Let a[t] be the sum before update t and x[t] the overwritten old byte.
    Since a[t+1] = 2*a[t] - x[t] mod 256:
        x[t] = 2*a[t] - a[t+1] mod 256
    The first n overwritten bytes are the original state in schedule order.
    """
    return bytes((2 * outputs[t] - outputs[t + 1]) % 256 for t in range(n))


def rebuild_states(schedule_bytes: bytes):
    """Try every allowed rotation and optional schedule reversal."""
    n = len(schedule_bytes)
    for shift in range(n):
        schedule = list(range(n))
        schedule = schedule[shift:] + schedule[:shift]

        for reversed_schedule in (False, True):
            current_schedule = schedule[::-1] if reversed_schedule else schedule
            state = bytearray(n)
            for value, index in zip(schedule_bytes, current_schedule):
                state[index] = value
            yield shift, reversed_schedule, bytes(state)


def solve(text: str) -> tuple[str, int, int, bool]:
    outputs = parse_outputs(text)
    n = infer_state_length(outputs)
    schedule_bytes = recover_schedule_order_bytes(outputs, n)

    matches = []
    for shift, reversed_schedule, state in rebuild_states(schedule_bytes):
        match = FLAG_RE.search(state)
        if match:
            matches.append(
                (match.group().decode("ascii"), shift, reversed_schedule, state)
            )

    unique_flags = {item[0] for item in matches}
    if len(unique_flags) != 1:
        raise ValueError(f"flag recovery was ambiguous: {sorted(unique_flags)}")

    flag = unique_flags.pop()
    exact = next(item for item in matches if item[3].startswith(flag.encode()))
    return flag, n, exact[1], exact[2]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recover the flag from the birthday-oracle transcript"
    )
    parser.add_argument("transcript", type=Path, help="path to result.txt/transcript")
    args = parser.parse_args()

    text = args.transcript.read_text(encoding="utf-8", errors="replace")
    flag, state_length, shift, reversed_schedule = solve(text)

    print(f"[+] outputs parsed : {len(parse_outputs(text))}")
    print(f"[+] state length   : {state_length}")
    print(f"[+] schedule shift : {shift}")
    print(f"[+] reversed       : {reversed_schedule}")
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
