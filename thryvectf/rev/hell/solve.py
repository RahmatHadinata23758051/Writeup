#!/usr/bin/env python3

# rev_hell stores 12 target bytes in .data at VA 0x4038.
# The checker validates the 12 chars inside Thryve{...} with:
#   3 * ((s[i] ^ s[(i+1) % 12]) + s[(i+2) % 12]) mod 256 == target[i]
# Because 3 is invertible modulo 256, target can be divided by 3 using inv3 = 171.

import string

TARGET = bytes.fromhex("67 f8 71 ec 32 37 3a b7 70 19 47 f6")
INV3 = pow(3, -1, 256)
D = [(b * INV3) & 0xff for b in TARGET]

# Flag body is expected to be printable CTF-style text. The recurrence only needs
# the first two chars; the next 10 chars are forced by the equations.
CHARSET = [ord(c) for c in string.ascii_letters + string.digits + "_{}-!@#$%^&*+=:;,.?"]


def valid(body: list[int]) -> bool:
    n = 12
    return all((((body[i] ^ body[(i + 1) % n]) + body[(i + 2) % n]) & 0xff) == D[i] for i in range(n))


def main() -> None:
    solutions: list[bytes] = []

    for x0 in CHARSET:
        for x1 in CHARSET:
            body = [x0, x1]
            ok = True

            # From equation i:
            #   s[i+2] = D[i] - (s[i] ^ s[i+1]) mod 256
            for i in range(10):
                nxt = (D[i] - (body[i] ^ body[i + 1])) & 0xff
                if nxt not in CHARSET:
                    ok = False
                    break
                body.append(nxt)

            if ok and valid(body):
                solutions.append(bytes(body))

    if len(solutions) != 1:
        raise SystemExit(f"expected 1 solution, got {len(solutions)}: {solutions!r}")

    print(f"Thryve{{{solutions[0].decode()}}}")


if __name__ == "__main__":
    main()
