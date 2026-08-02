# Immiscible

**Category:** Cryptography

## Challenge Description

The challenge provides a public multivariate quadratic system over the finite field GF(79). A secret signature is evaluated through this public system, and the resulting vector is published together with an AES-encrypted flag.

The provided parameters are:

```python
P = 79
V = 4
O = 4
M = 9
N = V + O
```

The public file contains:

- `target` — evaluation of the secret signature
- `polynomials` — public quadratic polynomial system
- `encrypted_flag` — AES-ECB encrypted flag

The objective is to recover the secret signature, derive the AES key, and decrypt the flag.

---

## Source Analysis

Each public polynomial is generated as follows:

```python
for i in range(V):
    for j in range(i, V):
        poly["quad"].append([i, j, random.randrange(P)])

for i in range(V):
    for j in range(V, N):
        poly["quad"].append([i, j, random.randrange(P)])
```

Quadratic terms are generated only for:

- vinegar-vinegar variables
- vinegar-oil variables

Notably, **no oil-oil quadratic terms are present**.

The variables are therefore divided into two groups:

```
x0 x1 x2 x3  -> Vinegar variables
x4 x5 x6 x7  -> Oil variables
```

This structure matches the classic **Oil and Vinegar** multivariate signature scheme.

---

## Vulnerability

Because there are no quadratic terms involving two oil variables, fixing the vinegar variables transforms every quadratic equation into a linear equation in the oil variables.

For a chosen vinegar assignment:

```
(x0, x1, x2, x3)
```

each polynomial becomes:

```
a0*x4 + a1*x5 + a2*x6 + a3*x7 = b  (mod 79)
```

This produces a linear system:

```
A · oils = b  (mod 79)
```

which can be solved using Gaussian elimination over GF(79).

---

## Exploitation Strategy

The attack proceeds as follows:

1. Enumerate every possible assignment of the four vinegar variables.
2. Substitute the vinegar values into every public polynomial.
3. Construct the resulting linear system for the oil variables.
4. Solve the system using Gaussian elimination modulo 79.
5. Verify the recovered signature against all public equations.
6. Derive the AES key as:

```python
key = sha256(bytes(signature)).digest()
```

7. Decrypt the ciphertext using AES-ECB.
8. Remove PKCS#7 padding to recover the flag.

Since there are only:

```
79^4 = 38,950,081
```

possible vinegar assignments, the search is feasible.

---

## Recovered Signature

The recovered signature is:

```text
[23, 7, 73, 60, 34, 54, 53, 7]
```

---

## Solver

```python
#!/usr/bin/env python3
import json
import hashlib
from itertools import product, combinations
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

P = 79
V = 4
O = 4
N = V + O


def inv(a):
    return pow(a % P, -1, P)


def eval_poly(poly, x):
    total = poly["const"]

    for i, c in enumerate(poly["linear"]):
        total += c * x[i]

    for i, j, c in poly["quad"]:
        total += c * x[i] * x[j]

    return total % P


def eval_public(polys, x):
    return [eval_poly(poly, x) for poly in polys]


def solve_linear(A, b):
    m = len(A)
    n = len(A[0])

    aug = [row[:] + [rhs % P] for row, rhs in zip(A, b)]

    row = 0
    pivots = []

    for col in range(n):
        pivot = None

        for r in range(row, m):
            if aug[r][col] % P != 0:
                pivot = r
                break

        if pivot is None:
            continue

        aug[row], aug[pivot] = aug[pivot], aug[row]

        scale = inv(aug[row][col])

        for c in range(col, n + 1):
            aug[row][c] = (aug[row][c] * scale) % P

        for r in range(m):
            if r != row and aug[r][col] % P != 0:
                factor = aug[r][col]

                for c in range(col, n + 1):
                    aug[r][c] = (aug[r][c] - factor * aug[row][c]) % P

        pivots.append(col)
        row += 1

        if row == n:
            break

    for r in range(row, m):
        if all(aug[r][c] % P == 0 for c in range(n)) and aug[r][n] % P != 0:
            return None

    if len(pivots) < n:
        return None

    x = [0] * n

    for r, col in enumerate(pivots):
        x[col] = aug[r][n] % P

    return x


def build_linear_system(polys, target, vinegar):
    A = []
    b = []

    for poly, t in zip(polys, target):
        value = poly["const"]

        for i in range(V):
            value += poly["linear"][i] * vinegar[i]

        row = [poly["linear"][V + k] for k in range(O)]

        for i, j, c in poly["quad"]:
            if i < V and j < V:
                value += c * vinegar[i] * vinegar[j]
            elif i < V and j >= V:
                oil_index = j - V
                row[oil_index] += c * vinegar[i]
            else:
                raise ValueError("Unexpected oil-oil term")

        A.append([x % P for x in row])
        b.append((t - value) % P)

    return A, b


def recover_signature(public):
    polys = public["polynomials"]
    target = public["target"]

    row_choices = list(combinations(range(len(polys)), O))

    for vinegar in product(range(P), repeat=V):
        A, b = build_linear_system(polys, target, vinegar)

        for rows in row_choices:
            sub_A = [A[i] for i in rows]
            sub_b = [b[i] for i in rows]

            oils = solve_linear(sub_A, sub_b)

            if oils is None:
                continue

            signature = list(vinegar) + oils

            if eval_public(polys, signature) == target:
                return signature

    return None


def decrypt_flag(encrypted_flag, signature):
    key = hashlib.sha256(bytes(signature)).digest()

    cipher = AES.new(key, AES.MODE_ECB)

    ciphertext = bytes.fromhex(encrypted_flag)

    plaintext = cipher.decrypt(ciphertext)

    return unpad(plaintext, 16)


def main():
    with open("public.json") as f:
        public = json.load(f)

    signature = recover_signature(public)

    if signature is None:
        print("[-] Signature not found")
        return

    print("[+] Signature:", signature)

    flag = decrypt_flag(public["encrypted_flag"], signature)

    print("[+] Flag:", flag.decode())


if __name__ == "__main__":
    main()
```

---

## Execution

```text
$ python3 solve.py

[+] Signature: [23, 7, 73, 60, 34, 54, 53, 7]
[+] Flag: L3AK{Oil_4ND_v1N3g4r_WitH0ut_Mix1nG_Sp1LL5_eV3rYth1ng}
```

---

## Flag

```text
L3AK{Oil_4ND_v1N3g4r_WitH0ut_Mix1nG_Sp1LL5_eV3rYth1ng}
```
