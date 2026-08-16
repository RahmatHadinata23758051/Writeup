#!/usr/bin/env python3
"""Recover the deleted FLAGMESSAGE values from C++ template constraints."""

import re
from pathlib import Path

import numpy as np


SOURCE = Path(__file__).with_name("out.cpp")
COUNT = 214


def equations(source: str) -> np.ndarray:
    """Convert every Equ<c1,c2,t1,v1,v2,v3,v4,v5> into one row of Ax=0."""
    pattern = re.compile(
        r"using Constraint_\d+ = Equ<\s*(-?\d+),\s*(-?\d+),\s*(-?\d+),\s*"
        r"FlagValue<(\d+)>::Value,\s*FlagValue<(\d+)>::Value,\s*"
        r"FlagValue<(\d+)>::Value,\s*FlagValue<(\d+)>::Value,\s*"
        r"FlagValue<(\d+)>::Value\s*>;"
    )
    rows = []
    for c1, c2, t1, v1, v2, v3, v4, v5 in pattern.findall(source):
        row = np.zeros(COUNT)
        for index, coefficient in zip(
            (v1, v2, v3, v4, v5), (c1, c2, t1, "-1", "-1")
        ):
            row[int(index)] += int(coefficient)
        rows.append(row)
    if len(rows) != 700:
        raise ValueError(f"expected 700 Equ constraints, found {len(rows)}")
    return np.array(rows)


def check_constraints(source: str, values: np.ndarray) -> None:
    """Evaluate every original constraint after substituting recovered values."""
    pattern = re.compile(r"using Constraint_(\d+) = (\w+)<(.+)>;")
    for number, kind, arguments in pattern.findall(source):
        args = re.sub(r"FlagValue<(\d+)>::Value", r"values[\1]", arguments)
        parts = [eval(part, {"values": values}) for part in args.split(", ")]
        if kind == "Equ":
            valid = parts[0] * parts[3] + parts[1] * parts[4] + parts[2] * parts[5] == parts[6] + parts[7]
        elif kind == "Divides":
            valid = parts[0] % parts[1] == 0
        else:
            left, right = parts
            valid = {"Lt": left < right, "Lteq": left <= right,
                     "Gt": left > right, "Gteq": left >= right}[kind]
        if not valid:
            raise ValueError(f"Constraint_{number} ({kind}) failed")


def main() -> None:
    source = SOURCE.read_text()
    # The 700 homogeneous equations have rank 213, so SVD gives their one-dimensional
    # nullspace.  Try possible integer scale factors and retain the one satisfying all
    # inequality and divisibility constraints.
    _, _, right_vectors = np.linalg.svd(equations(source), full_matrices=False)
    direction = right_vectors[-1] / right_vectors[-1][0]
    for scale in range(1, 256):
        candidate = np.rint(direction * scale).astype(int)
        if not np.allclose(direction * scale, candidate, atol=1e-6):
            continue
        try:
            check_constraints(source, candidate)
        except ValueError:
            continue
        message = "".join(map(chr, candidate))
        flag = re.search(r"\b\w+\{[^}]+\}", message)
        if not flag:
            raise ValueError("valid message did not contain a flag")
        print(message)
        print(flag.group())
        return
    raise ValueError("no integer scale satisfied all constraints")


if __name__ == "__main__":
    main()
