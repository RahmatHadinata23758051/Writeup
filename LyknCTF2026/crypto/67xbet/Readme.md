# 67xbet

**Category:** Crypto  
**CTF:** LYKN CTF 2026  
**Flag:** `LYKNCTF{df2486288f1c41819341feb0d3bf7fa4}`

## Description

> Messi vs Ronaldo

Web app menampilkan lima angka acak dan menyembunyikan angka keenam. Server hanya memberikan flag kalau angka keenam bisa diprediksi dengan tepat.

## Recon

Endpoint utama:

```text
GET  /api/random
POST /api/validate
```

`/api/random` mengembalikan lima angka serta hash integritas:

```json
{
  "numbers": [
    0.2553032794822707,
    0.1104514716087448,
    0.24925486874785618,
    0.8602180479766215,
    0.1532126389221664
  ],
  "hash": "e78796d0d8414b882b4b2a9f075931c0"
}
```

Payload validasi berbentuk:

```json
{
  "numbers": ["lima angka asli"],
  "answer": 0.0,
  "hash": "hash dari server"
}
```

Hash tidak perlu dipalsukan. Solver tetap mengirim angka dan hash asli, lalu hanya mengganti `answer`.

## Identifikasi PRNG

Angka yang keluar cocok dengan implementasi `Math.random()` milik V8. Generator internalnya memakai state 128-bit dan transisi xorshift128+:

```python
def xs128p(state0, state1):
    x = state0
    y = state1

    next_state0 = y
    x ^= x << 23
    x ^= x >> 17
    x ^= y
    x ^= y >> 26
    next_state1 = x

    return next_state0, next_state1
```

V8 mengubah 52 bit atas state menjadi float:

```text
output = (state >> 12) / 2^52
```

Satu output membocorkan 52 bit state. Lima output memberi 260 bit constraint, lebih dari cukup untuk menentukan state 128-bit yang relevan.

## Cache V8 yang Terbalik

V8 tidak langsung mengembalikan output setiap kali generator dipanggil. Runtime mengisi cache angka secara maju, lalu mengeluarkan isi cache dari indeks belakang ke depan.

Akibatnya, lima angka yang terlihat harus diproses dalam urutan terbalik saat membangun constraint:

```python
for value in reversed(numbers):
    solver.add(Extract(63, 12, state1) == mantissa(value))
    state0, state1 = xs128p(state0, state1)
```

Setelah state awal ditemukan, 52 bit atas `initial_state0` adalah angka berikutnya yang akan keluar dari cache.

Untuk instance yang dipakai:

```text
visible:
0.2553032794822707
0.1104514716087448
0.24925486874785618
0.8602180479766215
0.1532126389221664

predicted:
0.8729714324958713
```

## Solver

```python
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

```

## Eksekusi

Install dependency:

```bash
source /home/nata/ctf_env/bin/activate
pip install z3-solver
```

Jalankan:

```bash
python3 solve.py
```

Solver mengambil instance baru, memulihkan state, memprediksi angka keenam, lalu langsung mengirim jawaban ke `/api/validate`.

Output instance solve:

```text
[+] Predicted sixth: 0.8729714324958713
[+] Flag: LYKNCTF{df2486288f1c41819341feb0d3bf7fa4}
```

## Kesimpulan

Masalahnya bukan menebak angka acak, tetapi memulihkan state PRNG yang deterministik. Lima output `Math.random()` membocorkan cukup banyak bit untuk menyelesaikan state xorshift128+ dengan Z3. Detail cache V8 yang dibaca secara terbalik menjadi bagian penting; tanpa membalik urutan output, constraint tidak konsisten.
