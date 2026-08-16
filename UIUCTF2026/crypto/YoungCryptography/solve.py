#!/usr/bin/env python3

import ast
import sys

from bisect import bisect_right

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad


# ============================================================
# Challenge constants
# ============================================================

N = 64


# ============================================================
# Exact local rule from challenge
# ============================================================

def f(a, b, c, x):
    n = len(a)

    return (
        max(b[0], c[0]) + x,
    ) + tuple(
        min(b[k - 1], c[k - 1])
        + max(b[k], c[k])
        - a[k - 1]
        for k in range(1, n)
    )


# ============================================================
# Apply one matrix row to a boundary
#
# r:
#   boundary before processing row
#
# x:
#   one matrix row
#
# returns:
#   boundary after processing row
# ============================================================

def apply_one_row(r, x):
    n = len(x)

    z = (0,) * n

    s = [z]

    for j, xv in enumerate(x, 1):

        s.append(
            f(
                r[j - 1],
                r[j],
                s[-1],
                xv
            )
        )

    return tuple(s)


# ============================================================
# Matrix -> bottom boundary
# ============================================================

def bottom_boundary(M):
    n = len(M)

    z = (0,) * n

    r = tuple(
        [z] * (n + 1)
    )

    for row in M:
        r = apply_one_row(
            r,
            row
        )

    return r


# ============================================================
# Boundary sanity
# ============================================================

def is_partition(p):
    if any(x < 0 for x in p):
        return False

    for i in range(len(p) - 1):

        if p[i] < p[i + 1]:
            return False

    return True


def interlaces(a, b):
    """
    a = shape for letters <= j-1
    b = shape for letters <= j

    Need:

        b0 >= a0 >= b1 >= a1 >= b2 ...

    i.e. b/a is a horizontal strip.
    """

    n = len(a)

    for k in range(n):

        if b[k] < a[k]:
            return False

        if k > 0:

            if b[k] > a[k - 1]:
                return False

    return True


def valid_boundary(r):
    if not r:
        return False

    n = len(r[0])

    z = (0,) * n

    if r[0] != z:
        return False

    for p in r:

        if len(p) != n:
            return False

        if not is_partition(p):
            return False

    for j in range(1, len(r)):

        if not interlaces(
            r[j - 1],
            r[j]
        ):
            return False

    return True


# ============================================================
# Direct inverse of ONE matrix row
#
#
# Forward local rule:
#
#     d = f(a,b,c,x)
#
# where:
#
#     a = old boundary at j-1
#     b = old boundary at j
#     c = new boundary at j-1
#     d = new boundary at j
#
#
# We know:
#
#     a, c, d, x
#
# and solve for:
#
#     b
#
#
# From challenge:
#
# d[0] = max(b[0],c[0]) + x
#
# so:
#
# M0 = d[0] - x
#    = max(b[0],c[0])
#
#
# For k>=1:
#
# d[k]
# =
# min(a[k-1],c[k-1])
# +
# max(b[k],c[k])
# -
# a[k-1]
#
#
# therefore:
#
# Mk
# =
# d[k]
# - min(a[k-1],c[k-1])
# + a[k-1]
#
# =
# max(b[k],c[k])
#
#
# If M > c:
#     b = M
#
# If M == c:
#     b may be <= c.
#
# We choose a canonical residual:
#
#     MIN mode:
#         b[k] = a[k]
#
# or fallback:
#
#     MAX mode.
# ============================================================

def reverse_one_row(s, x, mode="min"):
    """
    Reverse exactly ONE known matrix row.

    We know:

        a = previous boundary at j-1
        c = current/new boundary at j-1
        d = current/new boundary at j
        x = known matrix entry

    and solve for:

        b = previous boundary at j

    Forward local rule is:

        d[0] = max(b[0], c[0]) + x

        d[k] =
            min(b[k-1], c[k-1])
            + max(b[k], c[k])
            - a[k-1]

    IMPORTANT:
        the min() uses b[k-1], NOT a[k-1].
    """

    n = len(x)

    z = (0,) * n

    if len(s) != n + 1:
        return None

    if s[0] != z:
        return None

    r = [z]

    # --------------------------------------------------------
    # Recover previous boundary column by column
    # --------------------------------------------------------

    for j in range(1, n + 1):

        a = r[j - 1]
        c = s[j - 1]
        d = s[j]

        xv = x[j - 1]

        b = [0] * n

        # ====================================================
        # k = 0
        #
        # d0 = max(b0, c0) + x
        # ====================================================

        u = d[0] - xv

        if u < c[0]:
            return None

        if u > c[0]:

            # forced
            b[0] = u

        else:

            # u == c[0]
            # so b0 may be <= c0

            lo = a[0]

            hi = c[0]

            if lo > hi:
                return None

            if mode == "min":
                b[0] = lo

            elif mode == "max":
                b[0] = hi

            else:
                raise ValueError(
                    f"unknown mode {mode}"
                )

        # basic lower bound
        if b[0] < a[0]:
            return None

        # ====================================================
        # k >= 1
        #
        # THIS IS THE PART THAT WAS WRONG BEFORE
        #
        # d[k]
        # =
        # min(b[k-1], c[k-1])
        # +
        # max(b[k], c[k])
        # -
        # a[k-1]
        #
        # therefore:
        #
        # max(b[k], c[k])
        # =
        # d[k]
        # - min(b[k-1], c[k-1])
        # + a[k-1]
        # ====================================================

        for k in range(1, n):

            u = (
                d[k]
                - min(
                    b[k - 1],
                    c[k - 1]
                )
                + a[k - 1]
            )

            if u < c[k]:
                return None

            if u > c[k]:

                # forced
                bk = u

            else:

                # u == c[k]
                #
                # therefore b[k] <= c[k]
                #
                # but b must interlace a:
                #
                #     a[k] <= b[k] <= a[k-1]
                #
                # and must remain a partition:
                #
                #     b[k] <= b[k-1]

                lo = a[k]

                hi = min(
                    c[k],
                    a[k - 1],
                    b[k - 1]
                )

                if lo > hi:
                    return None

                if mode == "min":

                    bk = lo

                elif mode == "max":

                    bk = hi

                else:

                    raise ValueError(
                        f"unknown mode {mode}"
                    )

            b[k] = bk

            # ----------------------------------------------
            # partition check
            # ----------------------------------------------

            if b[k] > b[k - 1]:
                return None

            # ----------------------------------------------
            # interlacing with a
            # ----------------------------------------------

            if b[k] < a[k]:
                return None

            if b[k] > a[k - 1]:
                return None

        b = tuple(b)

        # ====================================================
        # Full validity
        # ====================================================

        if not is_partition(b):
            return None

        if not interlaces(
            a,
            b
        ):
            return None

        # ====================================================
        # Replay exact challenge local rule
        # ====================================================

        check = f(
            a,
            b,
            c,
            xv
        )

        if check != d:

            return None

        r.append(b)

    r = tuple(r)

    # ========================================================
    # Boundary validity
    # ========================================================

    if not valid_boundary(r):
        return None

    # ========================================================
    # Full row replay
    # ========================================================

    replay = apply_one_row(
        r,
        x
    )

    if replay != s:

        return None

    return r

# ============================================================
# Remove complete known matrix rows
#
# final_boundary is boundary after:
#
#       UNKNOWN + KNOWN
#
# We remove KNOWN rows from bottom to top.
# ============================================================

def reverse_known_matrix_rows(
    final_boundary,
    KNOWN,
    mode="min"
):

    cur = final_boundary

    total_rows = len(KNOWN)

    print(
        f"[*] reverse rows mode={mode}"
    )

    for ii, row_index in enumerate(
        range(
            total_rows - 1,
            -1,
            -1
        ),
        1
    ):

        row = KNOWN[row_index]

        prev = reverse_one_row(
            cur,
            row,
            mode=mode
        )

        if prev is None:

            print(
                f"[-] inverse failed at "
                f"matrix row {row_index}"
            )

            return None

        cur = prev

        if (
            ii % 8 == 0
            or ii == total_rows
        ):

            print(
                f"[*] reversed "
                f"{ii}/{total_rows} rows"
            )

    return cur


# ============================================================
# Boundary -> tableau
# ============================================================

def boundary_to_tableau(r):
    n = len(r) - 1

    T = []

    for row_idx in range(n):

        row = []

        for j in range(
            1,
            n + 1
        ):

            cnt = (
                r[j][row_idx]
                - r[j - 1][row_idx]
            )

            if cnt < 0:

                raise ValueError(
                    "invalid boundary"
                )

            row.extend(
                [j] * cnt
            )

        if row:

            T.append(
                tuple(row)
            )

    return tuple(T)


# ============================================================
# Tableau -> boundary
# ============================================================

def tableau_to_boundary(T, n=N):
    r = []

    for j in range(n + 1):

        p = []

        for i in range(n):

            if i < len(T):

                p.append(
                    bisect_right(
                        T[i],
                        j
                    )
                )

            else:

                p.append(0)

        r.append(
            tuple(p)
        )

    return tuple(r)


# ============================================================
# Tableau -> symmetric matrix
#
# Exact second half of challenge my_prod()
# ============================================================

def tableau_to_symmetric_matrix(
    T,
    n=N
):

    r = tableau_to_boundary(
        T,
        n
    )

    p = [
        [None] * (n + 1)
        for _ in range(n + 1)
    ]

    for i in range(n + 1):
        p[i][n] = r[i]

    C = [
        [0] * n
        for _ in range(n)
    ]

    for i in range(
        n - 1,
        -1,
        -1
    ):

        for j in range(
            n - 1,
            i - 1,
            -1
        ):

            b = p[i][j + 1]

            c = (
                p[i + 1][j]
                if i < j
                else b
            )

            d = p[i + 1][j + 1]

            C[i][j] = (
                C[j][i]
            ) = (
                d[0]
                - max(
                    b[0],
                    c[0]
                )
            )

            p[i][j] = tuple(

                min(
                    b[k],
                    c[k]
                )
                +
                (
                    max(
                        b[k + 1],
                        c[k + 1]
                    )
                    - d[k + 1]

                    if k + 1 < n

                    else 0
                )

                for k in range(n)
            )

    return C


# ============================================================
# Exact challenge my_prod()
# ============================================================

def my_prod(A, B):
    n = len(A)

    z = (0,) * n

    def ff(a, b, c, x):

        return (
            max(
                b[0],
                c[0]
            )
            + x,
        ) + tuple(

            min(
                b[k - 1],
                c[k - 1]
            )
            +
            max(
                b[k],
                c[k]
            )
            -
            a[k - 1]

            for k in range(
                1,
                n
            )
        )

    # --------------------------------------------------------
    # forward growth
    # --------------------------------------------------------

    r = [z] * (n + 1)

    for row in A + B:

        s = [z]

        for j, x in enumerate(
            row,
            1
        ):

            s.append(
                ff(
                    r[j - 1],
                    r[j],
                    s[-1],
                    x
                )
            )

        r = s

    # --------------------------------------------------------
    # symmetric reconstruction
    # --------------------------------------------------------

    p = [
        [None] * (n + 1)
        for _ in range(n + 1)
    ]

    for i in range(n + 1):

        p[i][n] = r[i]

    C = [
        [0] * n
        for _ in range(n)
    ]

    for i in range(
        n - 1,
        -1,
        -1
    ):

        for j in range(
            n - 1,
            i - 1,
            -1
        ):

            b = p[i][j + 1]

            c = (
                p[i + 1][j]
                if i < j
                else b
            )

            d = p[i + 1][j + 1]

            C[i][j] = (
                C[j][i]
            ) = (
                d[0]
                - max(
                    b[0],
                    c[0]
                )
            )

            p[i][j] = tuple(

                min(
                    b[k],
                    c[k]
                )
                +
                (
                    max(
                        b[k + 1],
                        c[k + 1]
                    )
                    - d[k + 1]

                    if k + 1 < n

                    else 0
                )

                for k in range(n)
            )

    return C


# ============================================================
# Helpers
# ============================================================

def matrix_weight(M):

    return sum(
        sum(row)
        for row in M
    )


def tableau_size(T):

    return sum(
        len(row)
        for row in T
    )


def is_symmetric(M):
    n = len(M)

    for i in range(n):

        for j in range(n):

            if M[i][j] != M[j][i]:
                return False

    return True


def is_nonnegative_matrix(M):

    return all(
        x >= 0
        for row in M
        for x in row
    )


# ============================================================
# Parse challenge output
# ============================================================

def load_out(path):
    vals = []

    with open(
        path,
        "r"
    ) as fh:

        for line in fh:

            line = line.strip()

            if not line:
                continue

            try:

                vals.append(
                    ast.literal_eval(
                        line
                    )
                )

            except Exception:
                pass

    if len(vals) < 5:

        raise ValueError(
            f"expected at least 5 values, "
            f"got {len(vals)}"
        )

    G = vals[0]

    AG = vals[1]

    GB = vals[2]

    ct = vals[3]

    iv = vals[4]

    return (
        G,
        AG,
        GB,
        ct,
        iv
    )


# ============================================================
# Recover a left quotient A_candidate
#
# We try deterministic residuals only.
#
# NO DFS.
# NO millions of states.
# ============================================================

def recover_A_candidate(
    G,
    AG
):

    final_boundary = bottom_boundary(
        AG
    )

    print(
        "[+] final AG boundary size =",
        sum(final_boundary[-1])
    )

    # --------------------------------------------------------
    # Try minimal inverse first
    # --------------------------------------------------------

    for mode in (
        "min",
        "max",
    ):

        print()
        print(
            "=" * 70
        )

        print(
            f"[*] trying direct inverse: "
            f"{mode}"
        )

        recovered_boundary = (
            reverse_known_matrix_rows(
                final_boundary,
                G,
                mode=mode
            )
        )

        if recovered_boundary is None:

            print(
                f"[-] {mode} inverse failed"
            )

            continue

        print(
            "[+] recovered boundary"
        )

        print(
            "[+] recovered boundary size =",
            sum(
                recovered_boundary[-1]
            )
        )

        # random A has weight 256
        if sum(
            recovered_boundary[-1]
        ) != 256:

            print(
                "[-] unexpected quotient weight"
            )

            continue

        # ----------------------------------------------------
        # Convert recovered boundary -> tableau
        # ----------------------------------------------------

        try:

            T_A = boundary_to_tableau(
                recovered_boundary
            )

        except Exception as e:

            print(
                "[-] boundary -> tableau failed:",
                e
            )

            continue

        print(
            "[+] quotient tableau size =",
            tableau_size(T_A)
        )

        print(
            "[+] quotient shape =",
            [
                len(row)
                for row in T_A
            ]
        )

        # ----------------------------------------------------
        # Tableau -> symmetric matrix
        # ----------------------------------------------------

        try:

            A_candidate = (
                tableau_to_symmetric_matrix(
                    T_A
                )
            )

        except Exception as e:

            print(
                "[-] tableau -> matrix failed:",
                e
            )

            continue

        if not is_symmetric(
            A_candidate
        ):

            print(
                "[-] recovered matrix "
                "not symmetric"
            )

            continue

        if not is_nonnegative_matrix(
            A_candidate
        ):

            print(
                "[-] recovered matrix has "
                "negative entries"
            )

            continue

        print(
            "[+] A_candidate weight =",
            matrix_weight(
                A_candidate
            )
        )

        # ----------------------------------------------------
        # Exact challenge validation
        #
        # This is the important test.
        # ----------------------------------------------------

        print(
            "[*] validating:"
        )

        print(
            "[*] my_prod(A_candidate, G) == AG ?"
        )

        test_AG = my_prod(
            A_candidate,
            G
        )

        if test_AG != AG:

            print(
                f"[-] {mode} candidate "
                f"DOES NOT validate"
            )

            continue

        print(
            "[+] EXACT VALIDATION PASSED!"
        )

        print(
            "[+] my_prod(A_candidate, G) == AG"
        )

        return A_candidate

    return None


# ============================================================
# Main
# ============================================================

def main():

    if len(sys.argv) != 2:

        print(
            f"usage: "
            f"{sys.argv[0]} out"
        )

        sys.exit(1)

    path = sys.argv[1]

    # --------------------------------------------------------
    # Parse
    # --------------------------------------------------------

    (
        G,
        AG,
        GB,
        ct,
        iv
    ) = load_out(
        path
    )

    print(
        "[+] parsed"
    )

    print(
        "[+] weights:"
    )

    print(
        "    G  =",
        matrix_weight(G)
    )

    print(
        "    AG =",
        matrix_weight(AG)
    )

    print(
        "    GB =",
        matrix_weight(GB)
    )

    print(
        "[+] dimensions:"
    )

    print(
        "    G  =",
        len(G),
        "x",
        len(G[0])
    )

    print(
        "    AG =",
        len(AG),
        "x",
        len(AG[0])
    )

    print(
        "    GB =",
        len(GB),
        "x",
        len(GB[0])
    )

    # --------------------------------------------------------
    # Basic sanity
    # --------------------------------------------------------

    if len(G) != N:

        print(
            "[-] unexpected N"
        )

        sys.exit(1)

    if not is_symmetric(G):

        print(
            "[-] G not symmetric"
        )

        sys.exit(1)

    if not is_symmetric(AG):

        print(
            "[-] AG not symmetric"
        )

        sys.exit(1)

    if not is_symmetric(GB):

        print(
            "[-] GB not symmetric"
        )

        sys.exit(1)

    print(
        "[+] symmetric sanity passed"
    )

    # --------------------------------------------------------
    # Boundary roundtrip sanity
    # --------------------------------------------------------

    print(
        "[*] checking public boundary roundtrips"
    )

    for name, M in (
        ("G", G),
        ("AG", AG),
        ("GB", GB),
    ):

        rb = bottom_boundary(
            M
        )

        if not valid_boundary(
            rb
        ):

            print(
                f"[-] invalid boundary for {name}"
            )

            sys.exit(1)

        T = boundary_to_tableau(
            rb
        )

        M2 = tableau_to_symmetric_matrix(
            T
        )

        if M2 != M:

            print(
                f"[-] roundtrip failed for {name}"
            )

            sys.exit(1)

        print(
            f"[+] {name} roundtrip OK"
        )

    # --------------------------------------------------------
    # Recover ANY A_candidate satisfying:
    #
    #       A_candidate * G = AG
    #
    # --------------------------------------------------------

    print()
    print(
        "[*] recovering left quotient"
    )

    A_candidate = recover_A_candidate(
        G,
        AG
    )

    if A_candidate is None:

        print()
        print(
            "[-] deterministic inversion failed"
        )

        print(
            "[-] IMPORTANT:"
        )

        print(
            "[-] don't run DFS again yet"
        )

        print(
            "[-] send me the output lines around:"
        )

        print(
            "    inverse failed at matrix row ..."
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Build shared secret
    #
    # candidate satisfies:
    #
    #       candidate * G = A * G
    #
    # and:
    #
    #       GB = G * B
    #
    # so by associativity:
    #
    #       candidate * GB
    #       =
    #       candidate * G * B
    #       =
    #       A * G * B
    #
    # --------------------------------------------------------

    print()
    print(
        "[*] computing shared matrix"
    )

    AGB = my_prod(
        A_candidate,
        GB
    )

    print(
        "[+] AGB weight =",
        matrix_weight(
            AGB
        )
    )

    # Expected:
    #
    # A + G + B
    # 256 + 256 + 256
    # =
    # 768
    #
    if matrix_weight(
        AGB
    ) != 768:

        print(
            "[!] warning: "
            "unexpected AGB weight"
        )

    # --------------------------------------------------------
    # Exact challenge key
    # --------------------------------------------------------

    key = SHA256.new(
        str(
            AGB
        ).encode()
    ).digest()[:128]

    print(
        "[+] key length =",
        len(key)
    )

    print(
        "[+] AES key =",
        key.hex()
    )

    # --------------------------------------------------------
    # AES CBC
    # --------------------------------------------------------

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv
    )

    raw = cipher.decrypt(
        ct
    )

    print(
        "[+] raw decrypt =",
        repr(raw)
    )

    # --------------------------------------------------------
    # PKCS7 unpad
    # --------------------------------------------------------

    try:

        pt = unpad(
            raw,
            16
        )

    except Exception as e:

        print()
        print(
            "[-] unpad failed:"
        )

        print(
            e
        )

        print()
        print(
            "[-] This means the quotient "
            "validated AG but did not give "
            "the intended shared secret."
        )

        print(
            "[-] Send me:"
        )

        print(
            "    [+] EXACT VALIDATION PASSED!"
        )

        print(
            "    [+] AES key = ..."
        )

        print(
            "    [+] raw decrypt = ..."
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Print result
    # --------------------------------------------------------

    print()
    print(
        "=" * 70
    )

    print(
        "[+] PLAINTEXT =",
        repr(pt)
    )

    try:

        print(
            "[+] FLAG =",
            pt.decode()
        )

    except Exception:

        print(
            "[!] plaintext is not UTF-8"
        )

    print(
        "=" * 70
    )


if __name__ == "__main__":
    main()
