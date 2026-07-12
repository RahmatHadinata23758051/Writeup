# Aperture Science: Weighted Companion Cube

## Informasi Challenge

- **Kategori:** Crypto
- **Kesulitan:** Hard
- **Flag format:** `grodno{}`
- **Judul:** Aperture Science: Weighted Companion Cube

## Deskripsi

Sebuah arsip Aperture Science ditemukan dalam kondisi terenkripsi. Beberapa arsip lain dari batch yang sama tersedia sebagai referensi melalui `known_archives.json`, sedangkan kemungkinan isi setiap field tersedia di `catalog.json`.

File yang diberikan:

```text
catalog.json
known_archives.json
metadata.json
secret_archive.hex
```

Tujuannya adalah memulihkan isi `secret_archive.hex`.

---

## Analisis Awal

Isi `metadata.json`:

```json
{
  "title": "Aperture Science AES: Weighted Companion Cube",
  "mode": "aperture-companion-stream-v2",
  "block_size": 16,
  "format": [
    "[Aperture Archive]",
    "item=18",
    "status=12",
    "sector=12",
    "memo=64"
  ],
  "note": "Every archive in this batch was encrypted under the same boot-state."
}
```

Ada dua petunjuk penting:

```text
mode = aperture-companion-stream-v2
Every archive in this batch was encrypted under the same boot-state.
```

Walaupun nama implementasinya tidak diberikan secara langsung, ciphertext memiliki panjang yang sama dengan plaintext dan tidak memiliki padding block tambahan.

Hal ini mengarah ke mode stream seperti:

```text
ciphertext = plaintext XOR keystream
```

Jika seluruh arsip dienkripsi menggunakan boot-state yang sama, maka keystream yang dipakai juga sama.

Untuk dua pesan:

```text
C1 = P1 XOR K
C2 = P2 XOR K
```

Maka:

```text
C1 XOR C2 = P1 XOR P2
```

Lebih penting lagi, jika salah satu plaintext berhasil diketahui:

```text
K = C1 XOR P1
```

Keystream tersebut dapat langsung digunakan untuk membuka arsip rahasia:

```text
Psecret = Csecret XOR K
```

Ini adalah kesalahan klasik **keystream reuse**, biasanya terjadi saat nonce atau counter pada stream cipher/CTR mode digunakan ulang.

---

## Struktur Plaintext

Berdasarkan `metadata.json`, setiap record memiliki format:

```text
[Aperture Archive]
item=<18 byte>
status=<12 byte>
sector=<12 byte>
memo=<64 byte>
```

Setiap nilai diisi menggunakan spasi hingga mencapai ukuran field, lalu diakhiri newline.

Secara Python, formatnya setara dengan:

```python
plaintext = (
    "[Aperture Archive]\n"
    f"item={item:<18}\n"
    f"status={status:<12}\n"
    f"sector={sector:<12}\n"
    f"memo={memo:<64}\n"
)
```

Semua kemungkinan nilai tersedia di `catalog.json`.

Contoh nilai field:

```json
{
  "item": [
    "cake voucher",
    "companion cube",
    "morality core",
    "neurotoxin rig",
    "portal device",
    "turret shell"
  ]
}
```

Karena ada enam ciphertext dikenal dan enam kandidat untuk setiap field, setiap record kemungkinan menggunakan salah satu nilai dari masing-masing daftar.

---

## Recover Isi Known Archive

Tidak perlu mencoba seluruh kombinasi global.

Untuk setiap field, misalnya `item`, lakukan langkah berikut:

1. Ambil segment ciphertext field `item` dari record pertama.
2. Coba setiap kandidat `item` dari `catalog.json`.
3. Hitung kandidat keystream:

```text
key_segment = ciphertext_segment XOR padded_candidate
```

4. Gunakan `key_segment` tersebut untuk mendekripsi segment field yang sama pada seluruh known archive.
5. Kandidat dianggap valid jika seluruh hasil decrypt terdapat dalam daftar `catalog.json`.

Konsepnya:

```python
for candidate in catalog["item"]:
    key_segment = known_ciphertexts[0][offset:end] ^ pad(candidate)

    decoded = []
    for ciphertext in known_ciphertexts:
        value = ciphertext[offset:end] ^ key_segment
        decoded.append(value.rstrip())

    if all(value in catalog["item"] for value in decoded):
        solution = decoded
```

Cara yang sama diterapkan pada:

```text
item
status
sector
memo
```

Setelah seluruh isi record pertama diketahui, plaintext lengkap record tersebut dapat dibangun ulang.

---

## Recover Keystream

Dengan plaintext known archive pertama:

```text
K = Cknown XOR Pknown
```

Karena seluruh record memiliki panjang dan format identik, keystream yang didapat mencakup seluruh ciphertext.

Implementasi:

```python
keystream = xor_bytes(
    known_ciphertexts[0],
    known_plaintext
)
```

Arsip rahasia kemudian dibuka menggunakan:

```python
secret_plaintext = xor_bytes(
    secret_ciphertext,
    keystream
)
```

---

## Solver Otomatis

Simpan script berikut sebagai `solve.py` pada direktori challenge:

```python
#!/usr/bin/env python3
import json
import re
from pathlib import Path


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def load_inputs():
    catalog = json.loads(
        Path("catalog.json").read_text(encoding="utf-8")
    )
    archives = json.loads(
        Path("known_archives.json").read_text(encoding="utf-8")
    )
    metadata = json.loads(
        Path("metadata.json").read_text(encoding="utf-8")
    )
    secret = bytes.fromhex(
        Path("secret_archive.hex").read_text().strip()
    )

    ciphertexts = [
        bytes.fromhex(entry["ciphertext_hex"])
        for entry in archives
    ]

    return catalog, ciphertexts, metadata, secret


def parse_format(metadata):
    format_spec = metadata["format"]
    header = format_spec[0]

    fields = []
    for entry in format_spec[1:]:
        name, width = entry.rsplit("=", 1)
        fields.append((name, int(width)))

    return header, fields


def build_layout(header, fields):
    offsets = {}
    cursor = len((header + "\n").encode())

    for name, width in fields:
        cursor += len((name + "=").encode())
        offsets[name] = (cursor, width)
        cursor += width + 1

    return offsets, cursor


def recover_record_values(catalog, ciphertexts, offsets):
    recovered = [dict() for _ in ciphertexts]

    for field, values in catalog.items():
        offset, width = offsets[field]
        allowed = set(values)
        solutions = []

        for first_value in values:
            first_plain = first_value.encode().ljust(width, b" ")

            key_segment = xor_bytes(
                ciphertexts[0][offset:offset + width],
                first_plain,
            )

            decoded_values = []
            valid = True

            for ciphertext in ciphertexts:
                plain_segment = xor_bytes(
                    ciphertext[offset:offset + width],
                    key_segment,
                )

                try:
                    value = plain_segment.decode().rstrip(" ")
                except UnicodeDecodeError:
                    valid = False
                    break

                if value not in allowed:
                    valid = False
                    break

                decoded_values.append(value)

            if valid:
                solutions.append(decoded_values)

        if len(solutions) != 1:
            raise RuntimeError(
                f"Field {field!r}: expected one solution, "
                f"found {len(solutions)}"
            )

        for index, value in enumerate(solutions[0]):
            recovered[index][field] = value

    return recovered


def render_record(header, fields, record):
    lines = [header]

    for name, width in fields:
        value = record[name]
        lines.append(f"{name}={value:<{width}}")

    return ("\n".join(lines) + "\n").encode()


def main():
    catalog, ciphertexts, metadata, secret = load_inputs()

    header, fields = parse_format(metadata)
    offsets, expected_length = build_layout(header, fields)

    lengths = {len(ciphertext) for ciphertext in ciphertexts}
    lengths.add(len(secret))

    if lengths != {expected_length}:
        raise RuntimeError(
            f"Unexpected ciphertext lengths: {sorted(lengths)}, "
            f"expected {expected_length}"
        )

    recovered_records = recover_record_values(
        catalog,
        ciphertexts,
        offsets,
    )

    known_plaintext = render_record(
        header,
        fields,
        recovered_records[0],
    )

    keystream = xor_bytes(
        ciphertexts[0],
        known_plaintext,
    )

    secret_plaintext = xor_bytes(
        secret,
        keystream,
    ).decode()

    print("[+] Recovered known records:")
    for index, record in enumerate(recovered_records):
        print(f"    record {index}: {record}")

    print("\n[+] Decrypted secret archive:")
    print(secret_plaintext, end="")

    match = re.search(
        r"grodno\{[^}\r\n]+\}",
        secret_plaintext,
    )

    if not match:
        raise RuntimeError("Flag not found")

    print(f"\n[+] FLAG: {match.group(0)}")


if __name__ == "__main__":
    main()
```

Jalankan:

```bash
python3 solve.py
```

---

## Hasil Decrypt

Isi `secret_archive.hex`:

```text
[Aperture Archive]
item=cake voucher
status=issued
sector=omega-01
memo=grodno{c0mp4n10n_cub3_7h15_15_57r1c7ly_4_m4ny_71m3_p4d}
```

Flag:

```text
grodno{c0mp4n10n_cub3_7h15_15_57r1c7ly_4_m4ny_71m3_p4d}
```

---
