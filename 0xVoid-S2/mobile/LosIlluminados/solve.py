#!/usr/bin/env python3
import hashlib
import hmac
import json
import struct
import zipfile
from pathlib import Path

APK_PATH = Path(__file__).with_name("LosIlluminados.apk")
MAGIC = b"LOSIL"
EXPECTED_VERSION = 1


def u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def read_utf16_length(buf, off):
    """Android string-pool UTF-16 length. Handles the short and extended forms."""
    first = u16(buf, off)
    off += 2
    if first & 0x8000:
        second = u16(buf, off)
        off += 2
        length = ((first & 0x7FFF) << 16) | second
    else:
        length = first
    return length, off


def parse_manifest_package(manifest: bytes) -> str:
    """Minimal binary AndroidManifest parser: read string pool, then manifest tag attrs."""
    # AXML header: type/header_size/chunk_size, then the string pool chunk starts.
    string_pool_off = 8
    if u16(manifest, string_pool_off) != 0x0001:
        raise ValueError("String pool chunk not found in AndroidManifest.xml")

    sp_header_size = u16(manifest, string_pool_off + 2)
    sp_size = u32(manifest, string_pool_off + 4)
    string_count = u32(manifest, string_pool_off + 8)
    flags = u32(manifest, string_pool_off + 16)
    strings_start = u32(manifest, string_pool_off + 20)
    is_utf8 = bool(flags & 0x00000100)
    if is_utf8:
        raise ValueError("This solve parser expects UTF-16 manifest strings")

    offsets_base = string_pool_off + sp_header_size
    strings_base = string_pool_off + strings_start
    strings = []
    for i in range(string_count):
        rel = u32(manifest, offsets_base + i * 4)
        pos = strings_base + rel
        length, pos = read_utf16_length(manifest, pos)
        raw = manifest[pos : pos + length * 2]
        strings.append(raw.decode("utf-16le"))

    off = string_pool_off + sp_size
    while off + 8 <= len(manifest):
        chunk_type = u16(manifest, off)
        chunk_size = u32(manifest, off + 4)
        if chunk_type == 0x0102:  # RES_XML_START_ELEMENT_TYPE
            name_idx = u32(manifest, off + 20)
            tag_name = strings[name_idx]
            attr_start = u16(manifest, off + 24)
            attr_size = u16(manifest, off + 26)
            attr_count = u16(manifest, off + 28)
            attrs_base = off + 16 + attr_start
            if tag_name == "manifest":
                for j in range(attr_count):
                    a = attrs_base + j * attr_size
                    attr_name = strings[u32(manifest, a + 4)]
                    raw_value_idx = u32(manifest, a + 8)
                    value_type = manifest[a + 15]
                    value_data = u32(manifest, a + 16)
                    if attr_name == "package":
                        if raw_value_idx != 0xFFFFFFFF:
                            return strings[raw_value_idx]
                        if value_type == 0x03:  # TYPE_STRING
                            return strings[value_data]
        if chunk_size <= 0:
            break
        off += chunk_size
    raise ValueError("package attribute not found")


def derive_key(package_name: str) -> bytes:
    # From IlluminadosDecoder.deriveKey():
    # key material = "com.los." + "illuminados." + "RECEIVE"
    # message      = packageName + "|Illuminados" + "Receiver"
    hmac_key = b"com.los.illuminados.RECEIVE"
    message = f"{package_name}|IlluminadosReceiver".encode()
    return hmac.new(hmac_key, message, hashlib.sha256).digest()


def decrypt_bundle(ciphertext: bytes, key: bytes) -> bytes:
    # From IlluminadosDecoder.decryptBundle(): pair-swap first, then XOR with key stream.
    swapped = bytearray(len(ciphertext))
    for i in range(0, len(ciphertext) - 1, 2):
        swapped[i] = ciphertext[i + 1]
        swapped[i + 1] = ciphertext[i]
    if len(ciphertext) % 2:
        swapped[-1] = ciphertext[-1]

    return bytes(b ^ key[i % len(key)] for i, b in enumerate(swapped))


def main():
    with zipfile.ZipFile(APK_PATH) as apk:
        manifest = apk.read("AndroidManifest.xml")
        signal = apk.read("assets/illuminados_signal.bin")

    package_name = parse_manifest_package(manifest)

    if signal[:5] != MAGIC:
        raise ValueError("Bad signal magic")
    if signal[5] != EXPECTED_VERSION:
        raise ValueError(f"Unsupported signal version: {signal[5]}")

    ciphertext = signal[7:]
    plaintext = decrypt_bundle(ciphertext, derive_key(package_name))
    decoded = json.loads(plaintext.decode())

    print(plaintext.decode())
    print(decoded["flag"])


if __name__ == "__main__":
    main()
