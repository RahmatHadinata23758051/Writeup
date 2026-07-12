#!/usr/bin/env python3
import json
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization


def trim(poly, modulus):
    while len(poly) > 1 and poly[-1] % modulus == 0:
        poly.pop()
    return [value % modulus for value in poly]


def poly_sub(left, right, modulus):
    size = max(len(left), len(right))
    result = [0] * size

    for index in range(size):
        a = left[index] if index < len(left) else 0
        b = right[index] if index < len(right) else 0
        result[index] = (a - b) % modulus

    return trim(result, modulus)


def poly_mul_monomial(poly, coefficient, degree, modulus):
    return [0] * degree + [
        coefficient * value % modulus
        for value in poly
    ]


def poly_divmod(dividend, divisor, modulus):
    dividend = trim(dividend[:], modulus)
    divisor = trim(divisor[:], modulus)

    if len(divisor) == 1 and divisor[0] == 0:
        raise ZeroDivisionError("Polynomial division by zero")

    quotient = [0] * max(1, len(dividend) - len(divisor) + 1)
    inverse_lead = pow(divisor[-1], -1, modulus)

    while len(dividend) >= len(divisor):
        if len(dividend) == 1 and dividend[0] == 0:
            break

        degree = len(dividend) - len(divisor)
        coefficient = dividend[-1] * inverse_lead % modulus
        quotient[degree] = coefficient

        dividend = poly_sub(
            dividend,
            poly_mul_monomial(
                divisor,
                coefficient,
                degree,
                modulus,
            ),
            modulus,
        )

    return trim(quotient, modulus), trim(dividend, modulus)


def poly_gcd(left, right, modulus):
    left = trim(left, modulus)
    right = trim(right, modulus)

    while not (len(right) == 1 and right[0] == 0):
        _, remainder = poly_divmod(left, right, modulus)
        left, right = right, remainder

    inverse_lead = pow(left[-1], -1, modulus)
    return [
        coefficient * inverse_lead % modulus
        for coefficient in left
    ]


def int_to_bytes(value):
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def main():
    data = json.loads(
        Path("ciphertexts.json").read_text(encoding="utf-8")
    )

    public_key = serialization.load_pem_public_key(
        Path("public.pem").read_bytes()
    ).public_numbers()

    n = public_key.n
    e = public_key.e

    c1 = int(data["c1"])
    c2 = int(data["c2"])
    a = int(data["a"])
    b = int(data["b"])

    if e != 3:
        raise RuntimeError(
            f"Expected RSA exponent e=3, got e={e}"
        )

    # f(x) = x^3 - c1
    f = [
        -c1,
        0,
        0,
        1,
    ]

    # g(x) = (a*x + b)^3 - c2
    g = [
        pow(b, 3, n) - c2,
        3 * a * pow(b, 2, n),
        3 * pow(a, 2, n) * b,
        pow(a, 3, n),
    ]

    common = poly_gcd(f, g, n)

    if len(common) != 2 or common[1] != 1:
        raise RuntimeError(
            f"Unexpected polynomial GCD: {common}"
        )

    message_integer = (-common[0]) % n
    message = int_to_bytes(message_integer)

    if pow(message_integer, e, n) != c1:
        raise RuntimeError("Recovered message does not match c1")

    related_message = (a * message_integer + b) % n
    if pow(related_message, e, n) != c2:
        raise RuntimeError("Recovered message does not match c2")

    decoded = message.decode("utf-8")
    print(f"[+] RSA modulus bits : {n.bit_length()}")
    print(f"[+] Public exponent  : {e}")
    print(f"[+] Recovered message: {decoded}")

    match = re.search(r"grodno\{[^}\r\n]+\}", decoded)
    if not match:
        raise RuntimeError("Flag not found")

    print(f"[+] FLAG: {match.group(0)}")


if __name__ == "__main__":
    main()
