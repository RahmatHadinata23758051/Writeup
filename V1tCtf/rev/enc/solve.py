#!/usr/bin/env python3
"""Solver for the NativeAOT reverse challenge `Enc`.

The program stores two hexadecimal strings in NativeAOT dehydrated data. This
solver reconstructs the hydrated region, derives the AES/ChaCha keys exactly as
Program.Main does, and decrypts flag.enc back into flag.png.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as exc:  # pragma: no cover - dependency error path
    raise SystemExit(
        "cryptography belum tersedia. Aktifkan venv challenge lalu install "
        "dengan: pip install cryptography"
    ) from exc


IMAGE_SHA256 = "9be021b3ac6c51f6a39d4f1ca86cfbf2ac5813eff2c0974d738ba0c21f8a149f"
CIPHERTEXT_SHA256 = "defacfe1305e04a92a4673a643b574034d16c8b858cfe9bd6d55410dd9e82b4b"
PLAINTEXT_SHA256 = "390c723f9788d6ecf69f87ee564e72994c4f3480e80faa31d52507b12e5febc1"
FLAG = "v1t{1_am_Gu1lty_0xf_Making.NetAOT:(!}"

# Addresses referenced directly by Program.Main in this challenge binary.
SEED_STRING_RVA = 0x290128
MATERIAL_STRING_RVA = 0x2A1768
R2R_DEHYDRATED_DATA = 207


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


class PEImage:
    def __init__(self, data: bytes):
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("enc.exe bukan PE yang valid")

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            raise ValueError("signature PE tidak ditemukan")

        coff = pe_offset + 4
        section_count = struct.unpack_from("<H", data, coff + 2)[0]
        optional_size = struct.unpack_from("<H", data, coff + 16)[0]
        optional = coff + 20
        magic = struct.unpack_from("<H", data, optional)[0]
        if magic != 0x20B:
            raise ValueError("solver mengharapkan PE32+ x64")

        self.image_base = struct.unpack_from("<Q", data, optional + 24)[0]
        section_table = optional + optional_size
        sections: list[Section] = []
        for index in range(section_count):
            off = section_table + index * 40
            name = data[off : off + 8].split(b"\x00", 1)[0].decode("ascii", "replace")
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", data, off + 8
            )
            sections.append(
                Section(name, virtual_address, virtual_size, raw_offset, raw_size)
            )
        self.sections = sections

    def section(self, name: str) -> Section:
        for section in self.sections:
            if section.name == name:
                return section
        raise ValueError(f"section {name!r} tidak ditemukan")

    def rva_to_offset(self, rva: int) -> int:
        for section in self.sections:
            span = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + span:
                delta = rva - section.virtual_address
                if delta >= section.raw_size:
                    raise ValueError(f"RVA {rva:#x} berada di bagian section tanpa raw data")
                return section.raw_offset + delta
        raise ValueError(f"RVA {rva:#x} tidak terpetakan")

    def read_rva(self, rva: int, size: int) -> bytes:
        off = self.rva_to_offset(rva)
        return self.data[off : off + size]

    def find_r2r_section(self, wanted_type: int) -> tuple[int, int]:
        """Return (start_rva, end_rva) for a ReadyToRun section."""
        pos = 0
        while True:
            pos = self.data.find(b"RTR\x00", pos)
            if pos < 0:
                break
            if pos + 16 > len(self.data):
                break

            major, minor = struct.unpack_from("<HH", self.data, pos + 4)
            count = struct.unpack_from("<H", self.data, pos + 12)[0]
            entry_size = self.data[pos + 14]
            if major < 1 or minor > 100 or not (1 <= count <= 512) or entry_size != 24:
                pos += 1
                continue

            table_end = pos + 16 + count * entry_size
            if table_end > len(self.data):
                pos += 1
                continue

            for index in range(count):
                entry = pos + 16 + index * entry_size
                section_type, _flags, start_va, end_va = struct.unpack_from(
                    "<IIQQ", self.data, entry
                )
                if section_type == wanted_type:
                    return start_va - self.image_base, end_va - self.image_base
            pos += 1
        raise ValueError(f"ReadyToRun section type {wanted_type} tidak ditemukan")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reconstruct_hydrated_data(pe: PEImage) -> tuple[int, bytes]:
    source_rva, source_end_rva = pe.find_r2r_section(R2R_DEHYDRATED_DATA)
    source = pe.read_rva(source_rva, source_end_rva - source_rva)
    if len(source) < 4:
        raise ValueError("DehydratedData terlalu pendek")

    destination_rva = source_rva + struct.unpack_from("<i", source, 0)[0]
    hydrated = pe.section("hydrated")
    if destination_rva != hydrated.virtual_address:
        raise ValueError(
            f"destination RehydrateData tidak cocok: {destination_rva:#x} != "
            f"{hydrated.virtual_address:#x}"
        )

    output = bytearray(hydrated.virtual_size)
    source_pos = 4
    destination_pos = 0

    def read_relptr32(rva: int) -> int:
        rel = struct.unpack("<i", pe.read_rva(rva, 4))[0]
        return rva + rel

    def ensure_output(size: int) -> None:
        if destination_pos + size > len(output):
            raise ValueError("stream RehydrateData menulis melewati section hydrated")

    while source_pos < len(source):
        command = source[source_pos]
        source_pos += 1
        kind = command & 7
        length = command >> 3

        # NativeAOT's compact integer form. Values 29, 30, and 31 mean that
        # one, two, or three little-endian bytes follow, plus the base value 28.
        if length > 28:
            extra_bytes = length - 28
            if source_pos + extra_bytes > len(source):
                raise ValueError("compact length terpotong")
            length = int.from_bytes(
                source[source_pos : source_pos + extra_bytes], "little"
            ) + 28
            source_pos += extra_bytes

        if kind == 0:  # literal bytes
            ensure_output(length)
            if source_pos + length > len(source):
                raise ValueError("literal RehydrateData terpotong")
            output[destination_pos : destination_pos + length] = source[
                source_pos : source_pos + length
            ]
            source_pos += length
            destination_pos += length

        elif kind == 1:  # zero-filled destination; bytearray is already zeroed
            ensure_output(length)
            destination_pos += length

        elif kind in (2, 3):
            # Reference into the fixup table immediately following the section.
            target_rva = read_relptr32(source_end_rva + length * 4)
            if kind == 2:
                ensure_output(4)
                current_rva = destination_rva + destination_pos
                struct.pack_into("<i", output, destination_pos, target_rva - current_rva)
                destination_pos += 4
            else:
                ensure_output(8)
                struct.pack_into(
                    "<Q", output, destination_pos, pe.image_base + target_rva
                )
                destination_pos += 8

        elif kind in (4, 5):
            # Inline sequences of relative pointers.
            for _ in range(length):
                target_rva = read_relptr32(source_rva + source_pos)
                source_pos += 4
                if kind == 4:
                    ensure_output(4)
                    current_rva = destination_rva + destination_pos
                    struct.pack_into(
                        "<i", output, destination_pos, target_rva - current_rva
                    )
                    destination_pos += 4
                else:
                    ensure_output(8)
                    struct.pack_into(
                        "<Q", output, destination_pos, pe.image_base + target_rva
                    )
                    destination_pos += 8
        else:
            raise ValueError(f"opcode RehydrateData tidak dikenal: {kind}")

    if source_pos != len(source) or destination_pos != len(output):
        raise ValueError(
            "RehydrateData tidak selesai tepat pada batas section: "
            f"source={source_pos:#x}/{len(source):#x}, "
            f"destination={destination_pos:#x}/{len(output):#x}"
        )
    return destination_rva, bytes(output)


def read_dotnet_string(hydrated_rva: int, hydrated: bytes, object_rva: int) -> str:
    offset = object_rva - hydrated_rva
    if not (0 <= offset <= len(hydrated) - 12):
        raise ValueError(f"RVA string {object_rva:#x} berada di luar hydrated data")
    length = struct.unpack_from("<I", hydrated, offset + 8)[0]
    end = offset + 12 + length * 2
    if length > 1_000_000 or end > len(hydrated):
        raise ValueError(f"layout System.String rusak pada RVA {object_rva:#x}")
    return hydrated[offset + 12 : end].decode("utf-16le")


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    amount = block_size - (len(data) % block_size)
    return data + bytes([amount]) * amount


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size:
        raise ValueError("plaintext AES tidak memiliki panjang block yang valid")
    amount = data[-1]
    if amount == 0 or amount > block_size or data[-amount:] != bytes([amount]) * amount:
        raise ValueError("padding PKCS#7 tidak valid")
    return data[:-amount]


def rotate_left(value: int, bits: int) -> int:
    return ((value << bits) & 0xFFFFFFFF) | (value >> (32 - bits))


def quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rotate_left(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotate_left(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rotate_left(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotate_left(state[b] ^ state[c], 7)


def chacha7539_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("ChaCha7539 membutuhkan key 32 byte dan nonce 12 byte")
    initial = (
        list(struct.unpack("<4I", b"expand 32-byte k"))
        + list(struct.unpack("<8I", key))
        + [counter]
        + list(struct.unpack("<3I", nonce))
    )
    state = initial.copy()
    for _ in range(10):
        quarter_round(state, 0, 4, 8, 12)
        quarter_round(state, 1, 5, 9, 13)
        quarter_round(state, 2, 6, 10, 14)
        quarter_round(state, 3, 7, 11, 15)
        quarter_round(state, 0, 5, 10, 15)
        quarter_round(state, 1, 6, 11, 12)
        quarter_round(state, 2, 7, 8, 13)
        quarter_round(state, 3, 4, 9, 14)
    return struct.pack(
        "<16I", *[(state[i] + initial[i]) & 0xFFFFFFFF for i in range(16)]
    )


def chacha7539_xor(data: bytes, key: bytes, nonce: bytes) -> bytes:
    output = bytearray(len(data))
    counter = 0
    for offset in range(0, len(data), 64):
        stream = chacha7539_block(key, counter, nonce)
        chunk = data[offset : offset + 64]
        output[offset : offset + len(chunk)] = bytes(
            left ^ right for left, right in zip(chunk, stream)
        )
        counter = (counter + 1) & 0xFFFFFFFF
    return bytes(output)


def derive_keys(pe: PEImage) -> tuple[bytes, bytes, bytes]:
    hydrated_rva, hydrated = reconstruct_hydrated_data(pe)
    seed_hex = read_dotnet_string(hydrated_rva, hydrated, SEED_STRING_RVA)
    material_hex = read_dotnet_string(hydrated_rva, hydrated, MATERIAL_STRING_RVA)

    seed = bytes.fromhex(seed_hex)
    material = bytes.fromhex(material_hex)
    if len(seed) != 48 or len(material) != 76:
        raise ValueError(
            f"panjang material tidak sesuai: seed={len(seed)}, material={len(material)}"
        )

    iv, derivation_key = seed[:16], seed[16:]
    encryptor = Cipher(
        algorithms.AES(derivation_key), modes.CBC(iv)
    ).encryptor()
    derived = encryptor.update(pkcs7_pad(material)) + encryptor.finalize()
    if len(derived) < 76:
        raise ValueError("hasil derivasi terlalu pendek")
    return derived[:32], derived[32:64], derived[64:76]


def decrypt_flag(executable: bytes, ciphertext: bytes) -> bytes:
    pe = PEImage(executable)
    aes_key, chacha_key, nonce = derive_keys(pe)
    aes_ciphertext = chacha7539_xor(ciphertext, chacha_key, nonce)
    decryptor = Cipher(algorithms.AES(aes_key), modes.ECB()).decryptor()
    padded = decryptor.update(aes_ciphertext) + decryptor.finalize()
    plaintext = pkcs7_unpad(padded)
    if not plaintext.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("hasil dekripsi bukan PNG")
    return plaintext


def find_required_files(root: Path) -> tuple[Path, Path]:
    executables = sorted(root.rglob("enc.exe"))
    ciphertexts = sorted(root.rglob("flag.enc"))
    if len(executables) != 1 or len(ciphertexts) != 1:
        raise ValueError(
            "arsip harus berisi tepat satu enc.exe dan satu flag.enc; "
            f"ditemukan {len(executables)} dan {len(ciphertexts)}"
        )
    return executables[0], ciphertexts[0]


def solve(input_path: Path, output_path: Path) -> None:
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        if input_path.is_dir():
            root = input_path
        elif zipfile.is_zipfile(input_path):
            temporary = tempfile.TemporaryDirectory(
                prefix=".enc_extract_", dir=str(output_path.parent.resolve())
            )
            root = Path(temporary.name)
            with zipfile.ZipFile(input_path) as archive:
                archive.extractall(root)
        else:
            raise ValueError("input harus berupa bin.zip atau direktori hasil ekstraksi")

        exe_path, enc_path = find_required_files(root)
        executable = exe_path.read_bytes()
        ciphertext = enc_path.read_bytes()

        exe_hash = sha256(executable)
        enc_hash = sha256(ciphertext)
        if exe_hash != IMAGE_SHA256:
            print(f"[!] SHA-256 enc.exe berbeda: {exe_hash}", file=sys.stderr)
        if enc_hash != CIPHERTEXT_SHA256:
            print(f"[!] SHA-256 flag.enc berbeda: {enc_hash}", file=sys.stderr)

        plaintext = decrypt_flag(executable, ciphertext)
        output_path.write_bytes(plaintext)
        digest = sha256(plaintext)
        print(f"[+] recovered PNG: {output_path}")
        print(f"[+] SHA-256: {digest}")

        # The flag is rasterized into the recovered image, not stored as PNG
        # metadata. Bind the transcription to the exact decrypted image digest.
        if digest != PLAINTEXT_SHA256:
            raise ValueError(
                "PNG berhasil dipulihkan, tetapi digest berbeda; flag tidak akan "
                "dicetak tanpa validasi visual yang sesuai"
            )
        print(f"<FLAG>{FLAG}</FLAG>")
    finally:
        if temporary is not None:
            temporary.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decrypt flag.enc from the NativeAOT Enc challenge"
    )
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        default=Path("bin.zip"),
        help="path ke bin.zip atau direktori hasil ekstraksi",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("flag.png"),
        help="lokasi PNG hasil dekripsi (default: flag.png)",
    )
    args = parser.parse_args()

    try:
        solve(args.input.resolve(), args.output.resolve())
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
