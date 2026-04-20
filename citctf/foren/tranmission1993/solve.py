#!/usr/bin/env python3
import re
import subprocess
import sys
from pathlib import Path

from PIL import Image
import pytesseract

ROOT = Path(__file__).resolve().parent
PCAP = ROOT / "call-69e26052e9f5b0c1da0ee369.pcap"
SPANDSP_TESTS = ROOT / "spandsp_src" / "tests"
DECODER = SPANDSP_TESTS / "t38_decode_manual"
OUTPUT_TIF = SPANDSP_TESTS / "t38pcap.tif"


def run(cmd, cwd=None, env=None):
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\nSTDOUT:\n{p.stdout}\nSTDERR:\n{p.stderr}"
        )
    return p


def ensure_decoder():
    if DECODER.exists():
        return
    raise RuntimeError(
        "Decoder belum ada. Build dulu dari folder spandsp_src/tests menjadi t38_decode_manual."
    )


def decode_t38_to_tiff():
    env = dict(**subprocess.os.environ)
    env["LD_LIBRARY_PATH"] = str((ROOT / "spandsp_src" / "src" / ".libs"))

    cmd = [
        str(DECODER),
        "-i",
        str(PCAP),
        "-S",
        "192.168.0.199",
        "-s",
        "38070",
        "-D",
        "23.179.16.198",
        "-d",
        "34654",
    ]
    run(cmd, cwd=SPANDSP_TESTS, env=env)

    if not OUTPUT_TIF.exists():
        raise RuntimeError("TIFF output tidak ditemukan setelah decode T.38")


def ocr_flag():
    img = Image.open(OUTPUT_TIF)
    text = pytesseract.image_to_string(img.convert("L"), config="--psm 6")
    m = re.search(r"CIT\{[^}]+\}", text)
    if not m:
        # fallback OCR mode
        text2 = pytesseract.image_to_string(img.convert("L"), config="--psm 4")
        m = re.search(r"CIT\{[^}]+\}", text2)
    if not m:
        raise RuntimeError("Flag tidak ditemukan dari OCR fax")
    return m.group(0)


def main():
    if not PCAP.exists():
        print(f"PCAP tidak ditemukan: {PCAP}", file=sys.stderr)
        sys.exit(1)

    ensure_decoder()
    decode_t38_to_tiff()
    flag = ocr_flag()
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
