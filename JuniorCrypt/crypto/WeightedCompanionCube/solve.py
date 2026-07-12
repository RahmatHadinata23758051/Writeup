#!/usr/bin/env python3
import json
import re
from pathlib import Path


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def load_inputs():
    catalog = json.loads(Path("catalog.json").read_text(encoding="utf-8"))
    archives = json.loads(Path("known_archives.json").read_text(encoding="utf-8"))
    metadata = json.loads(Path("metadata.json").read_text(encoding="utf-8"))
    secret = bytes.fromhex(Path("secret_archive.hex").read_text().strip())

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
    """
    Plaintext layout:
        [Aperture Archive]\n
        item=<fixed width>\n
        status=<fixed width>\n
        ...
    """
    offsets = {}
    cursor = len((header + "\n").encode())

    for name, width in fields:
        cursor += len((name + "=").encode())
        offsets[name] = (cursor, width)
        cursor += width + 1  # field data + newline

    return offsets, cursor


def recover_record_values(catalog, ciphertexts, offsets):
    """
    Cari assignment value untuk setiap known archive.

    Untuk setiap kandidat value pada record pertama:
      key_segment = ciphertext_segment XOR padded_plaintext

    Kandidat valid bila segment key tersebut mendekripsi semua record
    menjadi value yang memang ada di catalog.
    """
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
                    value = plain_segment.decode("utf-8").rstrip(" ")
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
                f"Field {field!r}: expected exactly one solution, "
                f"found {len(solutions)}"
            )

        for index, value in enumerate(solutions[0]):
            recovered[index][field] = value

    return recovered


def render_record(header, fields, record):
    lines = [header]

    for name, width in fields:
        value = record[name]
        if len(value.encode()) > width:
            raise ValueError(f"{name} value exceeds width {width}")
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

    keystream = xor_bytes(ciphertexts[0], known_plaintext)
    secret_plaintext = xor_bytes(secret, keystream).decode("utf-8")

    print("[+] Recovered known records:")
    for index, record in enumerate(recovered_records):
        print(f"    record {index}: {record}")

    print("\n[+] Decrypted secret archive:")
    print(secret_plaintext, end="")

    match = re.search(r"grodno\{[^}\r\n]+\}", secret_plaintext)
    if not match:
        raise RuntimeError("Flag not found in decrypted archive")

    print(f"\n[+] FLAG: {match.group(0)}")


if __name__ == "__main__":
    main()
