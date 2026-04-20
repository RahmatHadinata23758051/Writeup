#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path

BIN = Path("astro_beacon")
MSG = Path("sos_message.txt")
OUT = Path("decode_result.txt")


def run_decoder() -> str:
    if not BIN.exists():
        raise FileNotFoundError("astro_beacon tidak ditemukan")
    if not MSG.exists():
        raise FileNotFoundError("sos_message.txt tidak ditemukan")

    payload = "d\n" + MSG.read_text(encoding="utf-8") + "\n"
    proc = subprocess.run(
        [f"./{BIN.name}"],
        input=payload,
        text=True,
        capture_output=True,
        check=True,
    )

    if not OUT.exists():
        raise RuntimeError(
            "decode_result.txt tidak terbentuk. Output binary:\n" + proc.stdout + proc.stderr
        )

    return OUT.read_text(encoding="utf-8", errors="ignore")


def extract_flag(decoded_text: str) -> str:
    bits = "".join(ch for ch in decoded_text if ch in "01")
    if len(bits) < 8:
        raise ValueError("Bit tersembunyi tidak ditemukan")

    data = bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits) - (len(bits) % 8), 8))
    text = data.decode("utf-8", errors="ignore")

    m = re.search(r"jctf\{[^}]+\}", text)
    if not m:
        raise ValueError(f"Flag tidak ditemukan. Decoded text: {text!r}")
    return m.group(0)


def main() -> None:
    decoded = run_decoder()
    flag = extract_flag(decoded)
    print(flag)


if __name__ == "__main__":
    main()
