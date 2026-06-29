#!/usr/bin/env python3
"""Solver for V1T CTF 2026 - Slop Anti or Anti SLop."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import mpmath as mp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def parse_output(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")

    def get(name: str) -> str:
        match = re.search(rf"^{re.escape(name)} = (.+)$", text, re.MULTILINE)
        if not match:
            raise ValueError(f"field {name!r} not found in {path}")
        return match.group(1).strip()

    observations = re.findall(r"^o\d+: ([^,]+), (.+)$", text, re.MULTILINE)
    if not observations:
        raise ValueError("polynomial observations were not found")

    return {
        "cup": base64.b64decode(get("c")),
        "aad": get("a").encode(),
        "modulus": int(get("n")),
        "seed": int(get("r")),
        "rounds": int(get("z")),
        "field_modulus": int(get("m")),
        "vector": [int(value) for value in get("v").split(",")],
        "degree": int(get("d")),
        "observations": observations,
    }


def recover_coffee(observation: tuple[str, str], degree: int) -> list[int]:
    """Recover integer polynomial coefficients from one high-precision sample."""
    x_text, y_text = observation
    mp.mp.dps = max(len(x_text), len(y_text)) + 100

    x = mp.mpf(x_text)
    y = mp.mpf(y_text)

    relation_input = [mp.mpf(1)]
    for _ in range(degree):
        relation_input.append(relation_input[-1] * x)
    relation_input.append(y)

    relation = mp.pslq(
        mp.matrix(relation_input),
        tol=mp.mpf("1e-750"),
        maxcoeff=10**30,
        maxsteps=50_000,
    )
    if relation is None or abs(int(relation[-1])) != 1:
        raise RuntimeError("PSLQ failed to recover coffee coefficients")

    y_coefficient = int(relation[-1])
    return [-int(coefficient) * y_coefficient for coefficient in relation[:-1]]


def interpolate_at_zero(points: list[tuple[int, int]], modulus: int) -> int:
    """Same operation as I(v, m) in challenge.py."""
    result = 0
    for i, (x_i, y_i) in enumerate(points):
        numerator = 1
        denominator = 1
        for j, (x_j, _) in enumerate(points):
            if i == j:
                continue
            numerator = numerator * (-x_j) % modulus
            denominator = denominator * (x_i - x_j) % modulus
        result = (
            result
            + y_i * numerator * pow(denominator, -1, modulus)
        ) % modulus
    return result


def recover_cream(coffee: list[int], vector: list[int], modulus: int) -> int:
    multiplier = vector[10]
    generated_points = [
        (x, (multiplier * coffee[index] + bias) % modulus)
        for x, index, bias in zip(
            vector[4:7],
            vector[7:10],
            vector[11:14],
        )
    ]
    points = [
        (vector[0], vector[1]),
        (vector[2], vector[3]),
        *generated_points,
    ]
    return interpolate_at_zero(points, modulus)


def compile_vdf_helper(workdir: Path) -> Path:
    helper = workdir / f".vdf_helper_{os.getpid()}"
    source = r"""
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 4) return 2;

    mpz_t value, modulus;
    mpz_inits(value, modulus, NULL);

    if (mpz_set_str(value, argv[1], 10) != 0) return 3;
    if (mpz_set_str(modulus, argv[2], 10) != 0) return 4;

    unsigned long rounds = strtoul(argv[3], NULL, 10);
    for (unsigned long i = 0; i < rounds; i++) {
        mpz_mul(value, value, value);
        mpz_mod(value, value, modulus);
    }

    mpz_out_str(stdout, 10, value);
    putchar('\n');
    mpz_clears(value, modulus, NULL);
    return 0;
}
"""

    command = [
        "gcc",
        "-O3",
        "-march=native",
        "-x",
        "c",
        "-",
        "-o",
        str(helper),
        "-lgmp",
    ]
    try:
        subprocess.run(command, input=source, text=True, check=True)
    except FileNotFoundError as exc:
        raise RuntimeError("gcc was not found") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("failed to compile GMP VDF helper; install libgmp-dev") from exc

    return helper


def checkpoint_identity(seed: int, modulus: int, rounds: int) -> str:
    material = f"{seed}:{modulus}:{rounds}".encode()
    return hashlib.sha256(material).hexdigest()


def repeated_squaring_chunked(
    seed: int,
    rounds: int,
    modulus: int,
    workdir: Path,
    checkpoint: Path,
    chunk_size: int,
) -> int:
    identity = checkpoint_identity(seed, modulus, rounds)
    completed = 0
    value = seed

    if checkpoint.exists():
        saved = json.loads(checkpoint.read_text(encoding="utf-8"))
        if saved.get("identity") == identity:
            completed = int(saved["completed"])
            value = int(saved["value"])
            if not 0 <= completed <= rounds:
                raise ValueError("invalid VDF checkpoint")
            print(f"[+] resumed VDF checkpoint at {completed}/{rounds}")
        else:
            print("[!] checkpoint belongs to different parameters; ignoring it")

    if completed == rounds:
        return value

    helper = compile_vdf_helper(workdir)
    try:
        while completed < rounds:
            current_rounds = min(chunk_size, rounds - completed)
            process = subprocess.run(
                [str(helper), str(value), str(modulus), str(current_rounds)],
                text=True,
                capture_output=True,
                check=True,
            )
            value = int(process.stdout.strip())
            completed += current_rounds

            checkpoint.write_text(
                json.dumps(
                    {
                        "identity": identity,
                        "completed": completed,
                        "value": str(value),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            print(f"[+] VDF progress: {completed}/{rounds}", flush=True)
    finally:
        helper.unlink(missing_ok=True)

    return value


def derive_key(coffee: list[int], cream: int, sugar: int) -> bytes:
    encoded_coffee = ",".join(map(str, coffee)).encode()
    return hashlib.sha256(
        b"coffee"
        + sha256(encoded_coffee)
        + b"cream"
        + sha256(str(cream).encode())
        + b"sugar"
        + sha256(str(sugar).encode())
    ).digest()


def expected_nonce(coffee: list[int], cream: int) -> bytes:
    encoded_coffee = ",".join(map(str, coffee)).encode()
    return sha256(
        b"drip"
        + sha256(encoded_coffee)
        + b"cream"
        + sha256(str(cream).encode())
    )[:12]


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve Slop Anti or Anti SLop")
    parser.add_argument(
        "output",
        nargs="?",
        type=Path,
        default=Path("output.txt"),
        help="challenge output file (default: output.txt)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=5_000_000,
        help="VDF rounds per helper process",
    )
    parser.add_argument(
        "--checkpoint",
        type=Path,
        help="checkpoint path (default: next to output.txt)",
    )
    parser.add_argument(
        "--sugar",
        type=int,
        help="skip the VDF and use a previously recovered sugar value",
    )
    args = parser.parse_args()

    output_path = args.output.resolve()
    if not output_path.is_file():
        raise SystemExit(f"output file not found: {output_path}")
    if args.chunk_size <= 0:
        raise SystemExit("chunk size must be positive")

    data = parse_output(output_path)
    coffee = recover_coffee(data["observations"][0], data["degree"])
    cream = recover_cream(coffee, data["vector"], data["field_modulus"])

    nonce = data["cup"][:12]
    calculated_nonce = expected_nonce(coffee, cream)
    if nonce != calculated_nonce:
        raise RuntimeError("coffee/cream recovery failed nonce validation")

    print(f"[+] coffee = {coffee}")
    print(f"[+] cream  = {cream}")
    print(f"[+] nonce  = {nonce.hex()} (valid)")

    if args.sugar is not None:
        sugar = args.sugar
    else:
        checkpoint = (
            args.checkpoint.resolve()
            if args.checkpoint
            else output_path.with_name(".slop-vdf-checkpoint.json")
        )
        sugar = repeated_squaring_chunked(
            seed=data["seed"],
            rounds=data["rounds"],
            modulus=data["modulus"],
            workdir=output_path.parent,
            checkpoint=checkpoint,
            chunk_size=args.chunk_size,
        )

    print(f"[+] sugar  = {sugar}")

    plaintext = AESGCM(derive_key(coffee, cream, sugar)).decrypt(
        nonce,
        data["cup"][12:],
        data["aad"],
    )
    flag = plaintext.decode("utf-8")
    if not re.fullmatch(r"v1t\{[^\r\n]+\}", flag):
        raise RuntimeError(f"unexpected plaintext: {flag!r}")

    print(f"[+] flag   = {flag}")


if __name__ == "__main__":
    main()
