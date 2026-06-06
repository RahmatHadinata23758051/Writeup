#!/usr/bin/env python3
from pathlib import Path
import subprocess
import os

ROOT = Path(__file__).resolve().parent
BIN = ROOT / "my-favorite-ingredient"
ORACLE = ROOT / ".mfi_oracle"

# Patch verify_flag right after matvec_mul_vectorized returns.
# Original code compares the 64-byte output on stack with ~target.
# This patch writes those 64 bytes to stdout, then returns success.
def build_oracle():
    data = bytearray(BIN.read_bytes())
    patch = bytes.fromhex(
        "b801000000"      # mov eax, 1        ; sys_write
        "bf01000000"      # mov edi, 1        ; stdout
        "4889e6"          # mov rsi, rsp      ; output buffer
        "ba40000000"      # mov edx, 64
        "0f05"            # syscall
        "4881c480000000"  # add rsp, 0x80
        "5b"              # pop rbx
        "c3"              # ret
    )
    off = 0x1209
    data[off:off + len(patch)] = patch
    ORACLE.write_bytes(data)
    ORACLE.chmod(0o755)


def oracle(arg: bytes) -> bytes:
    return subprocess.check_output([bytes(ORACLE), arg])[:64]


def solve_mod_256(A, b):
    n = len(b)
    M = [A[i][:] + [b[i]] for i in range(n)]
    where = [-1] * n
    row = 0

    for col in range(n):
        pivot = None
        for r in range(row, n):
            # Only odd values are invertible modulo 256.
            if M[r][col] & 1:
                pivot = r
                break
        if pivot is None:
            continue

        M[row], M[pivot] = M[pivot], M[row]
        inv = pow(M[row][col], -1, 256)
        M[row] = [(v * inv) & 0xff for v in M[row]]

        for r in range(n):
            if r != row and M[r][col]:
                factor = M[r][col]
                M[r] = [(M[r][c] - factor * M[row][c]) & 0xff for c in range(n + 1)]

        where[col] = row
        row += 1

    if row != n:
        raise RuntimeError(f"matrix is not fully invertible modulo 256, rank={row}")

    x = [0] * n
    for col, r in enumerate(where):
        x[col] = M[r][n]
    return x


def main():
    build_oracle()

    raw = BIN.read_bytes()
    target = bytes((~x) & 0xff for x in raw[0x32170:0x32170 + 64])

    # Use a printable non-zero base so it can be passed as argv.
    base = bytearray([0x41] * 64)
    y0 = oracle(bytes(base))

    # The verifier is affine over Z/256Z:
    #   y = y0 + A * (x - base) mod 256
    cols = []
    for j in range(64):
        test = base.copy()
        test[j] = (test[j] + 1) & 0xff
        y = oracle(bytes(test))
        cols.append([(y[i] - y0[i]) & 0xff for i in range(64)])

    A = [[cols[j][i] for j in range(64)] for i in range(64)]
    rhs = [(target[i] - y0[i]) & 0xff for i in range(64)]
    delta = solve_mod_256(A, rhs)

    flag = bytearray(base)
    for i, d in enumerate(delta):
        flag[i] = (flag[i] + d) & 0xff

    flag = bytes(flag)
    check = subprocess.check_output([bytes(BIN), flag]).decode(errors="replace").strip()
    if check != "Correct flag!":
        raise RuntimeError(f"verification failed: {check}")

    print(flag.decode())


if __name__ == "__main__":
    main()
