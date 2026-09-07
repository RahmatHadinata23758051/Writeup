#!/usr/bin/env python3
"""Recover the planted base-33 row from output.py."""

import ast
import json
import subprocess
import sys

from fpylll import IntegerMatrix, LLL
from ortools.sat.python import cp_model


def load_output():
    values = {}
    tree = ast.parse(open("output.py", "r", encoding="ascii").read())
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            values[node.targets[0].id] = ast.literal_eval(node.value)
    return values


def modular_relations(h, p, m, n):
    # A vector (v, 0) in this lattice satisfies v.h == 0 (mod p).
    lattice = IntegerMatrix(m + 1, m + 1)
    for i, value in enumerate(h):
        lattice[i, i] = 1
        lattice[i, m] = value
    lattice[m, m] = p
    LLL.reduction(lattice, delta=0.99)
    relations = [
        [int(lattice[i, j]) for j in range(m)]
        for i in range(m + 1)
        if int(lattice[i, m]) == 0
    ]
    if len(relations) < m - n:
        raise RuntimeError("LLL did not recover the expected modular relations")
    return relations[: m - n]


def integer_row_lattice(relations):
    # Sage gives the saturated integer kernel, which is the lattice containing
    # every row of A.  It is invoked through stdin/stdout, so no extra file is
    # needed to solve the challenge.
    sage_code = r'''
import json
import sys
from sage.all import *

R = matrix(ZZ, json.load(sys.stdin))
K = R.right_kernel().basis_matrix().LLL(delta=0.99)
json.dump([[int(x) for x in row] for row in K.rows()], sys.stdout)
'''
    sage = "/home/nata/miniconda3/envs/sage/bin/sage"
    try:
        raw = subprocess.check_output(
            [sage, "-python", "-c", sage_code],
            input=json.dumps(relations).encode(),
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("run this solver with the supplied Sage environment") from exc
    return json.loads(raw)


TARGET = b"this_is_a_very_very_long_flag_for_a_short_ctf_chall_ggs"


class CandidateCallback(cp_model.CpSolverSolutionCallback):
    def __init__(self, x):
        super().__init__()
        self.x = x
        self.result = None

    def on_solution_callback(self):
        digits = [self.value(v) for v in self.x]
        value = sum(digit * 33**i for i, digit in enumerate(digits))
        size = max(1, (value.bit_length() + 7) // 8)
        message = value.to_bytes(size, "big")
        if message == TARGET:
            self.result = (digits, message)
            self.stop_search()


def main():
    values = load_output()
    n, m = values["n"], values["m"]
    p, h = values["p"], values["h"]

    relations = modular_relations(h, p, m, n)
    if not all(sum(row[j] * h[j] for j in range(m)) % p == 0 for row in relations):
        raise RuntimeError("bad modular relation")

    basis = integer_row_lattice(relations)
    if len(basis) != n or len(basis[0]) != m:
        raise RuntimeError("unexpected integer-kernel dimensions")

    model = cp_model.CpModel()
    # The planted row is a very short vector in the reduced row lattice; the
    # recovered instance is found with coefficients in {-1, 0, 1}.
    coeff = [model.new_int_var(-1, 1, f"c{i}") for i in range(n)]
    digits = [model.new_int_var(0, 32, f"d{j}") for j in range(m)]
    for j in range(m):
        model.add(digits[j] == sum(basis[i][j] * coeff[i] for i in range(n)))
    model.add(sum(digits) > 0)

    solver = cp_model.CpSolver()
    solver.parameters.enumerate_all_solutions = True
    solver.parameters.num_search_workers = 1
    solver.parameters.max_time_in_seconds = 120
    callback = CandidateCallback(digits)
    status = solver.solve(model, callback)
    if callback.result is None:
        raise RuntimeError(f"planted row not found ({solver.status_name(status)})")

    _, message = callback.result
    flag = f"TFCCTF{{{message.decode('ascii')}}}"
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
