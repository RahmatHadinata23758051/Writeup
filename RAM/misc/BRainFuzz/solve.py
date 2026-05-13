#!/usr/bin/env python3
"""
Solve script for BrainFuzz.

Usage:
  python3 solve.py [output.bin] [generated_gibson.jpg]

The script decodes the passphrase from output.bin, extracts the steghide-style
payload from the JPEG DCT coefficients, decrypts it, and prints the flag.
"""
from __future__ import annotations

from array import array
import hashlib
import math
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import textwrap
import zlib


MAGIC = 0x73688D
LCG_A = 1367208549
LCG_C = 1
SAMPLES_PER_VERTEX_JPEG = 3


def bits_to_int_le(bits: list[int]) -> int:
    return sum((b & 1) << i for i, b in enumerate(bits))


def bytes_to_bits_le(data: bytes) -> list[int]:
    out: list[int] = []
    for byte in data:
        for i in range(8):
            out.append((byte >> i) & 1)
    return out


def bits_to_bytes_le(bits: list[int]) -> bytes:
    if len(bits) % 8:
        bits = bits + [0] * (8 - (len(bits) % 8))
    return bytes(bits_to_int_le(bits[i : i + 8]) for i in range(0, len(bits), 8))


def decode_passphrase(blob_path: Path) -> str:
    data = blob_path.read_bytes()
    if len(data) % 8 != 0:
        raise ValueError("output.bin length is not divisible into 8-byte blocks")

    bits = []
    for off in range(0, len(data), 8):
        chunk = data[off : off + 8]
        bits.append(0 if chunk == b"\xff" * 8 else 1)

    decoded = bits_to_bytes_msb(bits)
    printable_runs = re.findall(rb"[\x20-\x7e]{8,}", decoded)
    if not printable_runs:
        raise ValueError(f"no printable passphrase found in decoded blob: {decoded!r}")
    return max(printable_runs, key=len).decode("ascii")


def bits_to_bytes_msb(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i : i + 8]:
            byte = (byte << 1) | (bit & 1)
        out.append(byte)
    return bytes(out)


class SteghideSelector:
    """The steghide 0.5.x selector permutation."""

    def __init__(self, maximum: int, passphrase: str):
        self.maximum = maximum
        self.num_in_array = 0
        self.x: list[int] = []
        self.y: list[int] = []
        self.x_reversed: dict[int, int] = {}

        digest = hashlib.md5(passphrase.encode()).digest()
        seed = 0
        for i in range(4):
            # steghide stores hash bytes in a little-endian BitString.
            seed ^= int.from_bytes(digest[i * 4 : (i + 1) * 4], "little")
        self.prng_value = seed & 0xFFFFFFFF

    def random_value(self, n: int) -> int:
        self.prng_value = (LCG_A * self.prng_value + LCG_C) & 0xFFFFFFFF
        return int(float(n) * (float(self.prng_value) / 4294967296.0))

    def idx_x(self, value: int, limit: int) -> int | None:
        idx = self.x_reversed.get(value)
        if idx is not None and idx < limit:
            return idx
        return None

    def set_x(self, idx: int, value: int) -> None:
        self.x[idx] = value
        self.x_reversed[value] = idx

    def calculate(self, count: int) -> None:
        j = self.num_in_array
        if count > self.num_in_array:
            self.x.extend([0] * (count - self.num_in_array))
            self.y.extend([0] * (count - self.num_in_array))
            self.num_in_array = count

        while j < count:
            k = j + self.random_value(self.maximum - j)
            i = self.idx_x(k, j)
            if i is not None:
                self.set_x(j, self.y[i])
                if self.x[j] > j:
                    self.y[j] = j
                if self.x[i] > j:
                    self.y[i] = j
                    l = self.idx_x(self.y[i], j)
                    if l is not None:
                        self.y[i] = self.y[l]
            else:
                self.set_x(j, k)
                self.y[j] = j

            if self.x[j] > j:
                i = self.idx_x(self.y[j], j)
                if i is not None:
                    self.y[j] = self.y[i]
            j += 1

    def __getitem__(self, idx: int) -> int:
        if idx >= self.num_in_array:
            self.calculate(idx + 1)
        return self.x[idx]


def dump_jpeg_coefficients(jpeg_path: Path, workdir: Path) -> Path:
    helper_c = workdir / ".dump_coeffs_brainfuzz.c"
    helper_bin = workdir / ".dump_coeffs_brainfuzz"
    coeff_path = workdir / ".coeffs_brainfuzz_s16.bin"

    helper_c.write_text(
        r'''
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <jpeglib.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    FILE *infile = fopen(argv[1], "rb");
    if (!infile) return 3;
    FILE *outfile = fopen(argv[2], "wb");
    if (!outfile) return 4;

    struct jpeg_decompress_struct cinfo;
    struct jpeg_error_mgr jerr;
    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_decompress(&cinfo);
    jpeg_stdio_src(&cinfo, infile);
    jpeg_read_header(&cinfo, TRUE);
    jvirt_barray_ptr *coeffs = jpeg_read_coefficients(&cinfo);

    for (int ci = 0; ci < cinfo.num_components; ci++) {
        jpeg_component_info *comp = cinfo.comp_info + ci;
        for (JDIMENSION row = 0; row < comp->height_in_blocks; row++) {
            JBLOCKARRAY blocks = (*cinfo.mem->access_virt_barray)
                ((j_common_ptr)&cinfo, coeffs[ci], row, 1, FALSE);
            for (JDIMENSION block = 0; block < comp->width_in_blocks; block++) {
                for (int k = 0; k < DCTSIZE2; k++) {
                    int16_t v = (int16_t)blocks[0][block][k];
                    if (fwrite(&v, sizeof(v), 1, outfile) != 1) return 5;
                }
            }
        }
    }

    jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);
    fclose(infile);
    fclose(outfile);
    return 0;
}
'''.lstrip()
    )

    subprocess.run(
        ["gcc", str(helper_c), "-o", str(helper_bin), "-ljpeg"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        [str(helper_bin), str(jpeg_path), str(coeff_path)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return coeff_path


def load_nonzero_dct_samples(coeff_path: Path) -> list[int]:
    coeffs = array("h")
    coeffs.frombytes(coeff_path.read_bytes())
    if sys.byteorder != "little":
        coeffs.byteswap()
    return [int(c) for c in coeffs if c != 0]


def extract_stego_bits(samples: list[int], passphrase: str, count: int, selector_state: dict) -> list[int]:
    selector: SteghideSelector = selector_state["selector"]
    sample_idx: int = selector_state["sample_idx"]
    out: list[int] = []

    for _ in range(count):
        ev = 0
        for _ in range(SAMPLES_PER_VERTEX_JPEG):
            pos = selector[sample_idx]
            ev = (ev + (abs(samples[pos]) & 1)) & 1
            sample_idx += 1
        out.append(ev)

    selector_state["sample_idx"] = sample_idx
    return out


def mcrypt_md5_key(passphrase: str, key_size: int) -> bytes:
    password = passphrase.encode()
    key = b""
    while len(key) < key_size:
        h = hashlib.md5()
        h.update(password)
        if key:
            h.update(key)
        key += h.digest()
    return key[:key_size]


def aes_256_cbc_decrypt(ciphertext_with_iv: bytes, passphrase: str) -> bytes:
    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]
    key = mcrypt_md5_key(passphrase, 32)

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:
        # Fallback for lean CTF boxes that have openssl but not the Python package.
        proc = subprocess.run(
            [
                "openssl",
                "enc",
                "-aes-256-cbc",
                "-d",
                "-nopad",
                "-K",
                key.hex(),
                "-iv",
                iv.hex(),
            ],
            input=ciphertext,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return proc.stdout


def parse_embedded_plaintext(plaintext: bytes, nplain_bits: int) -> tuple[str, bytes]:
    bits = bytes_to_bits_le(plaintext)[:nplain_bits]
    pos = 0

    compressed = bits[pos]
    pos += 1
    if compressed:
        n_uncompressed_bits = bits_to_int_le(bits[pos : pos + 32])
        pos += 32
        compressed_bytes = bits_to_bytes_le(bits[pos:])
        uncompressed = zlib.decompress(compressed_bytes)
        bits = bytes_to_bits_le(uncompressed)[:n_uncompressed_bits]
        pos = 0

    has_checksum = bits[pos]
    pos += 1
    if has_checksum:
        # steghide stores an mhash CRC32 here. It is not needed to recover the flag.
        pos += 32

    name_bytes = bytearray()
    while True:
        ch = bits_to_int_le(bits[pos : pos + 8])
        pos += 8
        if ch == 0:
            break
        name_bytes.append(ch)

    data = bits_to_bytes_le(bits[pos:])
    return name_bytes.decode("utf-8", "replace"), data


def solve(blob_path: Path, jpeg_path: Path) -> str:
    passphrase = decode_passphrase(blob_path)
    coeff_path = dump_jpeg_coefficients(jpeg_path, blob_path.parent)
    samples = load_nonzero_dct_samples(coeff_path)

    state = {"selector": SteghideSelector(len(samples), passphrase), "sample_idx": 0}
    header = extract_stego_bits(samples, passphrase, 65, state)

    magic = bits_to_int_le(header[:24])
    if magic != MAGIC:
        raise ValueError(f"bad stego magic: {magic:#x}")
    if header[24] != 0:
        raise ValueError("unsupported stego version")

    algo = bits_to_int_le(header[25:30])
    mode = bits_to_int_le(header[30:33])
    nplain_bits = bits_to_int_le(header[33:65])

    if (algo, mode) != (2, 1):
        raise ValueError(f"unexpected encryption info: algo={algo}, mode={mode}")

    encrypted_bits_len = 128 + math.ceil(nplain_bits / 128) * 128
    encrypted_bits = extract_stego_bits(samples, passphrase, encrypted_bits_len, state)
    encrypted = bits_to_bytes_le(encrypted_bits)
    decrypted = aes_256_cbc_decrypt(encrypted, passphrase)
    embedded_name, embedded_data = parse_embedded_plaintext(decrypted, nplain_bits)

    match = re.search(rb"[A-Z][A-Z0-9_]*\{[^}\r\n]+\}", embedded_data)
    if not match:
        raise ValueError(f"flag not found in embedded file {embedded_name!r}: {embedded_data!r}")
    return match.group(0).decode()


def main() -> None:
    base = Path(__file__).resolve().parent
    blob_path = Path(sys.argv[1]) if len(sys.argv) > 1 else base / "output.bin"
    jpeg_path = Path(sys.argv[2]) if len(sys.argv) > 2 else base / "generated_gibson.jpg"
    flag = solve(blob_path, jpeg_path)
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
