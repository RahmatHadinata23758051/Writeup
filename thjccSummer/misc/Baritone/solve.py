#!/usr/bin/env python3
"""
Solver Baritone.

Encoding:
    frequency -> MIDI note number -> ASCII character

Setiap karakter menempati sekitar 0.5 detik.
"""

from __future__ import annotations

import argparse
import math
import subprocess
import sys
from pathlib import Path

import numpy as np


SAMPLE_RATE = 44_100
SYMBOL_SECONDS = 0.5
ANALYSIS_START = 0.12
ANALYSIS_END = 0.38
MIN_FREQ = 200.0
MAX_FREQ = 13_000.0


def decode_mp3(path: Path) -> np.ndarray:
    """Decode MP3 menjadi mono float32 menggunakan ffmpeg."""
    command = [
        "ffmpeg",
        "-v", "error",
        "-i", str(path),
        "-ac", "1",
        "-ar", str(SAMPLE_RATE),
        "-f", "f32le",
        "pipe:1",
    ]

    try:
        completed = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        raise SystemExit("ffmpeg tidak ditemukan di PATH.")
    except subprocess.CalledProcessError as exc:
        error = exc.stderr.decode(errors="replace")
        raise SystemExit(f"Gagal decode MP3:\n{error}")

    return np.frombuffer(completed.stdout, dtype="<f4")


def dominant_frequency(segment: np.ndarray) -> float:
    """Ambil frekuensi paling kuat dari satu slot karakter."""
    if segment.size == 0:
        raise ValueError("Segmen audio kosong")

    windowed = segment * np.hanning(segment.size)
    fft_size = 1 << (segment.size - 1).bit_length()

    spectrum = np.abs(np.fft.rfft(windowed, n=fft_size))
    frequencies = np.fft.rfftfreq(fft_size, d=1.0 / SAMPLE_RATE)

    valid = (frequencies >= MIN_FREQ) & (frequencies <= MAX_FREQ)
    if not np.any(valid):
        raise ValueError("Tidak ada bin frekuensi yang valid")

    return float(frequencies[valid][np.argmax(spectrum[valid])])


def frequency_to_midi(frequency: float) -> int:
    """Konversi Hz ke nomor MIDI terdekat."""
    return round(69 + 12 * math.log2(frequency / 440.0))


def solve(path: Path) -> str:
    audio = decode_mp3(path)
    duration = audio.size / SAMPLE_RATE
    max_symbols = int(duration // SYMBOL_SECONDS)

    decoded: list[str] = []

    print("idx  frequency     MIDI  char")
    print("---  ------------  ----  ----")

    for index in range(max_symbols):
        start_time = index * SYMBOL_SECONDS + ANALYSIS_START
        end_time = index * SYMBOL_SECONDS + ANALYSIS_END

        start = int(start_time * SAMPLE_RATE)
        end = int(end_time * SAMPLE_RATE)
        segment = audio[start:end]

        # Abaikan tail audio yang sudah sangat lemah.
        if segment.size == 0 or float(np.sqrt(np.mean(segment**2))) < 1e-5:
            break

        frequency = dominant_frequency(segment)
        midi = frequency_to_midi(frequency)

        if not 32 <= midi <= 126:
            raise ValueError(
                f"Slot {index}: MIDI {midi} bukan printable ASCII"
            )

        character = chr(midi)
        decoded.append(character)
        print(f"{index:3d}  {frequency:10.2f} Hz  {midi:4d}  {character!r}")

        if character == "}":
            break

    flag = "".join(decoded)
    print(f"\nDecoded: {flag}")

    if not (flag.startswith("THJCC{") and flag.endswith("}")):
        raise ValueError("Hasil tidak cocok dengan format flag")

    return flag


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "audio",
        nargs="?",
        default="baritone.mp3",
        type=Path,
        help="Path file MP3",
    )
    args = parser.parse_args()

    if not args.audio.is_file():
        raise SystemExit(f"File tidak ditemukan: {args.audio}")

    flag = solve(args.audio)
    print(f"\n<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
