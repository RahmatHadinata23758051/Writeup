#!/usr/bin/env python3
import base64
import io
import sys
import zipfile
from pathlib import Path

ZIP_PASSWORD = b"0b8b243ed6ee2fdd"
FLAG_KEY = bytes.fromhex(ZIP_PASSWORD.decode())


def mp4_payload_offset(blob: bytes) -> int:
    """Return the offset where valid top-level MP4 boxes stop."""
    off = 0
    size = len(blob)
    while off + 8 <= size:
        box_size = int.from_bytes(blob[off:off + 4], "big")
        box_type = blob[off + 4:off + 8]

        if box_size == 1:
            if off + 16 > size:
                break
            box_size = int.from_bytes(blob[off + 8:off + 16], "big")
        elif box_size == 0:
            return size

        if box_size < 8 or off + box_size > size:
            break

        # Stop after the real MP4 structure. The next bytes are the hidden ZIP.
        off += box_size
        if box_type == b"moov":
            return off

    marker = blob.find(b"PK\x03\x04")
    if marker == -1:
        raise RuntimeError("Hidden ZIP local header not found")
    return marker


def decode_flag(flag_enc: bytes) -> str:
    encrypted = base64.b64decode(flag_enc.strip())
    plain = bytes(b ^ FLAG_KEY[i % len(FLAG_KEY)] for i, b in enumerate(encrypted))[::-1]
    return plain.decode()


def main() -> None:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("challenge.mp4")
    blob = target.read_bytes()

    zip_offset = mp4_payload_offset(blob)
    hidden_zip = blob[zip_offset:]

    with zipfile.ZipFile(io.BytesIO(hidden_zip)) as zf:
        flag_enc = zf.read("flag.enc", pwd=ZIP_PASSWORD)

    flag = decode_flag(flag_enc)
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
