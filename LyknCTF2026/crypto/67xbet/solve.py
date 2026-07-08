#!/usr/bin/env python3
import json
import sys
import urllib.request
from typing import Any

from z3 import BitVec, Extract, LShR, Solver, sat


DEFAULT_BASE_URL = "http://6676e891-94f4-4542-86ba-67cde13e84c3.51.79.140.18.nip.io:8080"
MASK_52 = (1 << 52) - 1


def get_json(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode())


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode())


def xs128p(state0, state1):
    x = state0
    y = state1

    next_state0 = y
    x ^= x << 23
    x ^= LShR(x, 17)
    x ^= y
    x ^= LShR(y, 26)
    next_state1 = x

    return next_state0, next_state1


def float_to_mantissa(value: float) -> int:
    # Math.random() menghasilkan kelipatan tepat dari 2^-52.
    return int(value * (1 << 52)) & MASK_52


def mantissa_to_float(value: int) -> float:
    return value / float(1 << 52)


def predict_sixth(numbers: list[float]) -> float:
    if len(numbers) != 5:
        raise ValueError("Expected exactly five visible outputs")

    initial_state0 = BitVec("initial_state0", 64)
    initial_state1 = BitVec("initial_state1", 64)

    state0 = initial_state0
    state1 = initial_state1
    solver = Solver()

    # V8 mengisi cache secara maju, tetapi Math.random() mengeluarkannya
    # dari belakang. Karena itu urutan yang terlihat harus dibalik.
    for value in reversed(numbers):
        solver.add(Extract(63, 12, state1) == float_to_mantissa(value))
        state0, state1 = xs128p(state0, state1)

    if solver.check() != sat:
        raise RuntimeError("Failed to recover a compatible V8 PRNG state")

    model = solver.model()
    predicted_mantissa = model.eval(
        Extract(63, 12, initial_state0)
    ).as_long()

    # Pastikan prediksi upper 52-bit unik, bukan cuma salah satu model.
    solver.add(Extract(63, 12, initial_state0) != predicted_mantissa)
    if solver.check() == sat:
        raise RuntimeError("Prediction is ambiguous")

    return mantissa_to_float(predicted_mantissa)


def main() -> None:
    base_url = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else DEFAULT_BASE_URL

    instance = get_json(f"{base_url}/api/random")
    numbers = instance["numbers"]
    digest = instance["hash"]

    prediction = predict_sixth(numbers)

    print("[*] First five outputs:")
    for index, number in enumerate(numbers, 1):
        print(f"    {index}: {number!r}")

    print(f"[+] Predicted sixth: {prediction!r}")

    result = post_json(
        f"{base_url}/api/validate",
        {
            "numbers": numbers,
            "answer": prediction,
            "hash": digest,
        },
    )

    if "flag" not in result:
        raise RuntimeError(result.get("error", "Validation failed"))

    print(f"[+] Flag: {result['flag']}")


if __name__ == "__main__":
    main()
