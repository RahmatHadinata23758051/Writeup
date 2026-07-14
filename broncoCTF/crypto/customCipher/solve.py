#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


def divide_monic(numerator: list[int], denominator: list[int]) -> list[int]:
    """Exact polynomial division for ascending coefficients and monic denominator."""
    if not denominator or denominator[-1] != 1:
        raise ValueError("Denominator must be monic")

    if len(numerator) < len(denominator):
        raise ValueError("Numerator degree is smaller than denominator degree")

    remainder = numerator[:]
    quotient = [0] * (len(numerator) - len(denominator) + 1)
    denominator_degree = len(denominator) - 1

    for shift in range(len(quotient) - 1, -1, -1):
        factor = remainder[denominator_degree + shift]
        quotient[shift] = factor

        for index, coefficient in enumerate(denominator):
            remainder[index + shift] -= factor * coefficient

    if any(remainder):
        raise ValueError("Ciphertext is not exactly divisible by the public key")

    return quotient


def evaluate(coefficients: list[int], value: int) -> int:
    """Evaluate ascending polynomial coefficients with Horner's method."""
    result = 0
    for coefficient in reversed(coefficients):
        result = result * value + coefficient
    return result


def divide_by_linear(coefficients: list[int], root: int) -> list[int]:
    """Divide an ascending polynomial by (x - root)."""
    degree = len(coefficients) - 1
    if degree < 1:
        raise ValueError("Polynomial is constant")

    quotient = [0] * degree
    quotient[-1] = coefficients[-1]

    for index in range(degree - 2, -1, -1):
        quotient[index] = coefficients[index + 1] + root * quotient[index + 1]

    remainder = coefficients[0] + root * quotient[0]
    if remainder != 0:
        raise ValueError(f"{root} is not a root")

    return quotient


def recover_roots(polynomial: list[int], count: int = 4) -> list[int]:
    """Recover byte-sized integer roots, including repeated roots."""
    current = polynomial[:]
    roots: list[int] = []

    for _ in range(count):
        root = next(
            (candidate for candidate in range(256) if evaluate(current, candidate) == 0),
            None,
        )
        if root is None:
            raise ValueError(f"Could not find a byte-sized root in {current}")

        roots.append(root)
        current = divide_by_linear(current, root)

    return sorted(roots)


def restore_order(sorted_values: list[int], encoded_order: int) -> bytes:
    """
    The challenge stores the original index of each sorted message byte
    in successive 2-bit fields.
    """
    output = [0] * len(sorted_values)

    for sorted_index, value in enumerate(sorted_values):
        original_index = (encoded_order >> (2 * sorted_index)) & 0b11
        output[original_index] = value

    return bytes(output)


def parse_challenge(path: Path) -> tuple[list[int], list[tuple[list[int], int]]]:
    text = path.read_text(encoding="utf-8")

    try:
        public_section, message_section = (
            text.split("====PUBLIC KEY====", 1)[1]
            .split("====MESSAGE====", 1)
        )
    except (IndexError, ValueError) as exc:
        raise ValueError("Invalid challenge file format") from exc

    # to_distrib_form() omits the final monic coefficient.
    public_key = [int(value) for value in public_section.split()] + [1]

    blocks: list[tuple[list[int], int]] = []
    for raw_block in message_section.strip().split("/"):
        values = [int(value) for value in raw_block.split()]
        if len(values) < 2:
            raise ValueError("Malformed ciphertext block")

        encoded_order = values[-1]
        ciphertext = values[:-1] + [1]
        blocks.append((ciphertext, encoded_order))

    return public_key, blocks


def solve(path: Path) -> bytes:
    public_key, blocks = parse_challenge(path)
    plaintext = bytearray()

    for ciphertext, encoded_order in blocks:
        # C(x) = P(x) * product(x - message_byte)
        message_polynomial = divide_monic(ciphertext, public_key)
        sorted_message_bytes = recover_roots(message_polynomial)
        plaintext.extend(restore_order(sorted_message_bytes, encoded_order))

    return bytes(plaintext).rstrip(b"\x00")


def main() -> None:
    input_path = Path(sys.argv[1] if len(sys.argv) > 1 else "enc.txt")
    plaintext = solve(input_path)

    try:
        print(plaintext.decode("ascii"))
    except UnicodeDecodeError:
        print(plaintext)


if __name__ == "__main__":
    main()
