# Aperture Science: Neurotoxin Diagnostics

## Informasi

- **Kategori:** Crypto
- **Mode:** AES-CBC
- **Flag format:** `grodno{}`
- **File:** `metadata.json`, `packet.hex`, `timing_trace.json`

## Ringkasan

Ciphertext memakai AES-CBC dan tidak ada key yang diberikan. Celahnya ada pada telemetry waktu: setiap kombinasi `(block, pad, guess)` diuji tiga kali, lalu kandidat yang menghasilkan padding valid memakan waktu jauh lebih lama.

Median timing kandidat valid berada sekitar 2,5 ms. Kandidat salah umumnya hanya sekitar 1,1–1,5 ms. Dari sini setiap byte intermediate AES-CBC bisa direcover tanpa key.

## Struktur Packet

`metadata.json` menyebut mode `aes-cbc` dan block size 16 byte.

`packet.hex` berukuran 144 byte:

```text
144 / 16 = 9 blok
```

Pembagiannya:

```text
blok 0 = IV
blok 1..8 = ciphertext
```

IV-nya terlihat jelas:

```text
4e4555524f544f58494e5f5445535421
NEUROTOXIN_TEST!
```

## Pola Timing Trace

Jumlah entry:

```text
98304
```

Nilai itu cocok dengan seluruh ruang pencarian:

```text
8 target block × 16 padding byte × 256 guess × 3 trial
= 98304
```

Setiap record berbentuk:

```json
{
  "block": 4,
  "pad": 4,
  "guess": 190,
  "trial": 0,
  "elapsed_ns": 1275767
}
```

Karena setiap kandidat punya tiga pengukuran, median dipakai supaya spike acak tidak langsung dianggap sinyal.

Untuk setiap pasangan `(block, pad)`, script:

1. Mengumpulkan tiga timing untuk setiap `guess`.
2. Menghitung median.
3. Memilih guess dengan median tertinggi.
4. Mengubah guess tersebut menjadi intermediate byte.
5. Melakukan XOR dengan IV atau ciphertext block sebelumnya.

## Hubungan Padding Oracle dan CBC

Dekripsi CBC untuk satu block:

```text
P_i = D_K(C_i) XOR C_(i-1)
```

Definisikan intermediate state:

```text
I_i = D_K(C_i)
```

Maka:

```text
P_i = I_i XOR C_(i-1)
```

Trace menyimpan byte hasil modifikasi pada block sebelumnya. Agar byte plaintext hasil modifikasi sama dengan nilai padding `pad`:

```text
guess XOR intermediate = pad
```

Jadi:

```text
intermediate = guess XOR pad
```

Setelah intermediate byte ditemukan:

```text
plaintext = intermediate XOR original_previous_block
```

Posisi byte yang sedang dicari:

```text
position = 16 - pad
```

Proses dilakukan dari byte paling kanan ke kiri untuk semua delapan ciphertext block.

## Solver

```python
#!/usr/bin/env python3
import json
import re
import statistics
from collections import defaultdict
from pathlib import Path

BLOCK_SIZE = 16
FLAG_RE = re.compile(rb"grodno\{[^}\r\n]+\}")


def load_packet(path="packet.hex"):
    raw = "".join(Path(path).read_text().split())
    packet = bytes.fromhex(raw)

    if len(packet) % BLOCK_SIZE != 0:
        raise ValueError("Packet is not block aligned")

    return packet


def pkcs7_unpad(data):
    padding = data[-1]

    if padding < 1 or padding > BLOCK_SIZE:
        raise ValueError("Invalid PKCS#7 padding")

    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid PKCS#7 padding bytes")

    return data[:-padding]


def recover_plaintext(packet, trace):
    blocks = [
        packet[i:i + BLOCK_SIZE]
        for i in range(0, len(packet), BLOCK_SIZE)
    ]

    timings = defaultdict(list)

    for row in trace:
        key = (
            int(row["block"]),
            int(row["pad"]),
            int(row["guess"]),
        )
        timings[key].append(int(row["elapsed_ns"]))

    plaintext_blocks = []

    for block_number in range(1, len(blocks)):
        previous = blocks[block_number - 1]
        intermediate = bytearray(BLOCK_SIZE)

        for pad in range(1, BLOCK_SIZE + 1):
            position = BLOCK_SIZE - pad
            candidates = []

            for guess in range(256):
                samples = timings[(block_number, pad, guess)]
                score = statistics.median(samples)
                candidates.append((score, guess))

            candidates.sort(reverse=True)
            _, best_guess = candidates[0]

            intermediate[position] = best_guess ^ pad

        plaintext_blocks.append(
            bytes(
                intermediate[i] ^ previous[i]
                for i in range(BLOCK_SIZE)
            )
        )

    return b"".join(plaintext_blocks)


def main():
    metadata = json.loads(Path("metadata.json").read_text())

    if metadata["mode"] != "aes-cbc":
        raise RuntimeError("Unexpected cipher mode")

    packet = load_packet()
    trace = json.loads(Path("timing_trace.json").read_text())

    padded = recover_plaintext(packet, trace)
    plaintext = pkcs7_unpad(padded)

    print(plaintext.decode())

    match = FLAG_RE.search(plaintext)
    if not match:
        raise RuntimeError("Flag not found")

    flag = match.group().decode()
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
```

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

## Hasil

Plaintext yang direcover:

```text
diag=neurotoxin;status=stable;subject=chell;memo=grodno{n3ur070x1n_d14gn0571c5_l34k_7hr0ugh_71m1ng_4l0n3};closing=still_alive
```

Padding terakhir:

```text
03 03 03
```

Flag:

```text
grodno{n3ur070x1n_d14gn0571c5_l34k_7hr0ugh_71m1ng_4l0n3}
```
