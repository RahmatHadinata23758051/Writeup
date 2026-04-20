#!/usr/bin/env python3
import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

FLAG_RE = re.compile(r"jctf\{[^\n\r\t\x00}]+\}")


def run(cmd):
    return subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def decode_kcs(signal_path: Path) -> str:
    # Kansas City Standard-like decode: 300 baud, 1200/2400 Hz
    proc = run([
        "minimodem",
        "--rx",
        "-f",
        str(signal_path),
        "300",
        "-M",
        "2400",
        "-S",
        "1200",
        "--startbits",
        "1",
        "--stopbits",
        "2",
        "-8",
        "-q",
    ])
    out = proc.stdout.decode("latin-1", errors="ignore")
    m = FLAG_RE.search(out)
    if not m:
        raise ValueError("flag tidak ditemukan pada output minimodem")
    return m.group(0)


def main():
    parser = argparse.ArgumentParser(description="Solve JerseyCTF misc - Recovered Tape")
    parser.add_argument("input", nargs="?", default="clip.wav", help="path ke file wav challenge")
    args = parser.parse_args()

    inp = Path(args.input)
    if not inp.exists():
        print(f"[!] file tidak ditemukan: {inp}", file=sys.stderr)
        sys.exit(1)

    try:
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            right = td / "right.wav"
            signal = td / "signal.wav"

            # Ambil kanal kanan karena payload ada di channel ini.
            run(["sox", str(inp), str(right), "remix", "2"])
            # Potong area sinyal data yang terlihat jelas di spectrogram.
            run(["sox", str(right), str(signal), "trim", "7.7", "=10.0"])

            flag = decode_kcs(signal)
            print(flag)
    except subprocess.CalledProcessError as e:
        print("[!] command gagal:", " ".join(e.cmd), file=sys.stderr)
        if e.stderr:
            print(e.stderr.decode("utf-8", errors="ignore"), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
