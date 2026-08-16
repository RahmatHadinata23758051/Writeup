#!/usr/bin/env python3
from pathlib import Path
from PIL import Image
import ctypes
import re
import sys

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def extract_png_from_pe(exe_path: Path, out_path: Path) -> Path:
    """Extract embedded PNG resource by locating PNG signature and IEND chunk."""
    data = exe_path.read_bytes()
    start = data.find(PNG_SIG)
    if start < 0:
        raise RuntimeError("PNG signature not found in executable")

    # PNG ends at: length(4) + type IEND(4) + crc(4)
    iend_type = data.find(b"IEND", start)
    if iend_type < 0:
        raise RuntimeError("IEND chunk not found")
    end = iend_type + 8  # after type + CRC; IEND length field is the 4 bytes before type
    png = data[start:end]
    out_path.write_bytes(png)
    return out_path


def decode_pdf417_with_zxing(image_path: Path) -> str:
    """Decode PDF417 barcode using the local libZXing C API."""
    lib = ctypes.CDLL("/lib/x86_64-linux-gnu/libZXing.so.3")

    lib.ZXing_ReaderOptions_new.restype = ctypes.c_void_p
    lib.ZXing_ReaderOptions_delete.argtypes = [ctypes.c_void_p]
    lib.ZXing_ReaderOptions_setTryHarder.argtypes = [ctypes.c_void_p, ctypes.c_bool]
    lib.ZXing_ReaderOptions_setTryInvert.argtypes = [ctypes.c_void_p, ctypes.c_bool]
    lib.ZXing_ReaderOptions_setTryRotate.argtypes = [ctypes.c_void_p, ctypes.c_bool]
    lib.ZXing_ReaderOptions_setTryDownscale.argtypes = [ctypes.c_void_p, ctypes.c_bool]
    lib.ZXing_ReaderOptions_setMaxNumberOfSymbols.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.ZXing_BarcodeFormatsFromString.argtypes = [ctypes.c_char_p]
    lib.ZXing_BarcodeFormatsFromString.restype = ctypes.c_int
    lib.ZXing_ReaderOptions_setFormats.argtypes = [ctypes.c_void_p, ctypes.c_int]

    lib.ZXing_ImageView_new.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
        ctypes.c_int, ctypes.c_int, ctypes.c_int,
    ]
    lib.ZXing_ImageView_new.restype = ctypes.c_void_p
    lib.ZXing_ImageView_delete.argtypes = [ctypes.c_void_p]

    lib.ZXing_ReadBarcodes.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.ZXing_ReadBarcodes.restype = ctypes.c_void_p
    lib.ZXing_Barcodes_size.argtypes = [ctypes.c_void_p]
    lib.ZXing_Barcodes_size.restype = ctypes.c_size_t
    lib.ZXing_Barcodes_at.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    lib.ZXing_Barcodes_at.restype = ctypes.c_void_p
    lib.ZXing_Barcodes_delete.argtypes = [ctypes.c_void_p]
    lib.ZXing_Barcode_text.argtypes = [ctypes.c_void_p]
    lib.ZXing_Barcode_text.restype = ctypes.c_char_p
    lib.ZXing_Barcode_isValid.argtypes = [ctypes.c_void_p]
    lib.ZXing_Barcode_isValid.restype = ctypes.c_bool

    img = Image.open(image_path).convert("L")
    width, height = img.size
    raw = img.tobytes()
    buf = ctypes.create_string_buffer(raw)

    opts = lib.ZXing_ReaderOptions_new()
    if not opts:
        raise RuntimeError("failed to create ZXing ReaderOptions")

    try:
        lib.ZXing_ReaderOptions_setTryHarder(opts, True)
        lib.ZXing_ReaderOptions_setTryInvert(opts, True)
        lib.ZXing_ReaderOptions_setTryRotate(opts, True)
        lib.ZXing_ReaderOptions_setTryDownscale(opts, True)
        lib.ZXing_ReaderOptions_setMaxNumberOfSymbols(opts, 5)
        lib.ZXing_ReaderOptions_setFormats(opts, lib.ZXing_BarcodeFormatsFromString(b"PDF417"))

        # ImageFormat::Lum is 1 in ZXing-C++; row stride = width, pixel stride = 1.
        view = lib.ZXing_ImageView_new(buf, width, height, 1, width, 1)
        if not view:
            raise RuntimeError("failed to create ZXing ImageView")
        try:
            barcodes = lib.ZXing_ReadBarcodes(view, opts)
            if not barcodes:
                raise RuntimeError("ZXing returned no barcode container")
            try:
                count = lib.ZXing_Barcodes_size(barcodes)
                for i in range(count):
                    barcode = lib.ZXing_Barcodes_at(barcodes, i)
                    if barcode and lib.ZXing_Barcode_isValid(barcode):
                        text_ptr = lib.ZXing_Barcode_text(barcode)
                        if text_ptr:
                            return text_ptr.decode("utf-8", errors="replace")
                raise RuntimeError("no valid PDF417 barcode decoded")
            finally:
                lib.ZXing_Barcodes_delete(barcodes)
        finally:
            lib.ZXing_ImageView_delete(view)
    finally:
        lib.ZXing_ReaderOptions_delete(opts)


def main() -> None:
    exe = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("badgecheck.exe")
    out_png = Path("extracted_badge.png")
    extract_png_from_pe(exe, out_png)
    decoded = decode_pdf417_with_zxing(out_png)
    print(decoded)

    match = re.search(r"ThryveCTF\{[^}\n]+\}", decoded)
    if not match:
        raise SystemExit("flag pattern not found in decoded barcode")
    print(match.group(0))


if __name__ == "__main__":
    main()

