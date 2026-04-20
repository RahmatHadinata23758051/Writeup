#!/usr/bin/env python3
import re
import subprocess

ALPHABET = "BCDFGHJKLMNPQRST"
OBS_STRESS = [2, 5, 11, 10, 5, 1, 13, 4, 3, 3, 14]
OBS_SHEAR = [5, 5, 15, 8, 5, 6, 7, 4, 5, 5]
OBS_GRAIN = [3, 11, 3, 4, 14, 4, 5, 6, 1]
TARGET_LOAD = 93
TARGET_SEAL = 9


def run_cmd(args):
    return subprocess.check_output(args, text=True).strip()


def find_profile_vals():
    # Dari shear: a[i+2] = a[i] ^ OBS_SHEAR[i], jadi cukup brute-force a0 dan a1.
    for a0 in range(16):
        for a1 in range(16):
            a = [0] * 12
            a[0], a[1] = a0, a1

            for i in range(10):
                a[i + 2] = a[i] ^ OBS_SHEAR[i]

            ok = True

            # stress[i] = (2*a[i] + 3*a[i+1]) & 0xf
            for i in range(11):
                if ((2 * a[i] + 3 * a[i + 1]) & 0xF) != OBS_STRESS[i]:
                    ok = False
                    break
            if not ok:
                continue

            # grain[i] = (a[i] + a[i+3] - a[i+1]) & 0xf
            for i in range(9):
                if ((a[i] + a[i + 3] - a[i + 1]) & 0xF) != OBS_GRAIN[i]:
                    ok = False
                    break
            if not ok:
                continue

            if sum(a) != TARGET_LOAD:
                continue

            seal = sum((i + 5) * a[i] for i in range(12)) & 0xF
            if seal != TARGET_SEAL:
                continue

            return a

    raise RuntimeError("Profile tidak ditemukan")


def vals_to_profile(vals):
    return "".join(ALPHABET[v] for v in vals)


def main():
    vals = find_profile_vals()
    profile = vals_to_profile(vals)

    score_out = run_cmd(["./faultline", "score", profile])
    token = run_cmd(["./faultline", "token", profile])
    submit_out = run_cmd(["./faultline", "submit", profile, token])

    m = re.search(r"CIT\{[^}]+\}", submit_out)

    print(f"[+] profile : {profile}")
    print(f"[+] score   : {score_out}")
    print(f"[+] token   : {token}")
    print(f"[+] submit  : {submit_out}")

    if m:
        print(f"[+] flag    : {m.group(0)}")
    else:
        raise RuntimeError("Flag tidak ditemukan di output submit")


if __name__ == "__main__":
    main()
