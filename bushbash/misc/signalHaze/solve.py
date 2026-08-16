#!/usr/bin/env python3
"""Decode the Signal Haze SSTV transmission (Martin M1 / VIS 44)."""

from __future__ import annotations

import argparse
import subprocess
import sys
import wave
from pathlib import Path

import numpy as np
from PIL import Image
from scipy.signal import hilbert

WIDTH = 320
HEIGHT = 256

# Martin M1 timings, in seconds.
LINE_DURATION = 0.446446
SYNC_DURATION = 0.004862
PORCH_DURATION = 0.000572
SCAN_DURATION = 0.146432
SEPARATOR_DURATION = 0.000572

# Standard SSTV header duration:
# 300 ms leader + 10 ms break + 300 ms leader + 30 ms VIS start
# + 8 * 30 ms VIS bits + 30 ms VIS stop.
IMAGE_START = 0.910000


def convert_to_wav(source: Path, destination: Path) -> None:
    """Convert the supplied media file to mono 44.1 kHz signed-16-bit WAV."""
    command = [
        "ffmpeg",
        "-y",
        "-hide_banner",
        "-loglevel",
        "error",
        "-i",
        str(source),
        "-ac",
        "1",
        "-ar",
        "44100",
        "-c:a",
        "pcm_s16le",
        str(destination),
    ]
    try:
        subprocess.run(command, check=True)
    except FileNotFoundError as exc:
        raise RuntimeError("ffmpeg is required but was not found in PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"ffmpeg failed with exit code {exc.returncode}") from exc


def read_wav(path: Path) -> tuple[int, np.ndarray]:
    """Read a mono 16-bit PCM WAV as normalized float samples."""
    with wave.open(str(path), "rb") as wav:
        if wav.getnchannels() != 1:
            raise ValueError("expected mono WAV")
        if wav.getsampwidth() != 2:
            raise ValueError("expected 16-bit PCM WAV")
        sample_rate = wav.getframerate()
        samples = np.frombuffer(wav.readframes(wav.getnframes()), dtype=np.int16)
    return sample_rate, samples.astype(np.float64) / 32768.0


def tone_energy(samples: np.ndarray, sample_rate: int, frequency: float) -> float:
    """Measure one tone using a compact DFT/Goertzel-style correlation."""
    n = np.arange(samples.size, dtype=np.float64)
    oscillator = np.exp(-2j * np.pi * frequency * n / sample_rate)
    return float(abs(np.dot(samples, oscillator)) ** 2)


def decode_vis(samples: np.ndarray, sample_rate: int) -> tuple[list[int], int, int]:
    """Decode the seven VIS data bits and parity bit from the SSTV header."""
    bits: list[int] = []
    first_bit = 0.640  # header-relative start of the first 30 ms VIS bit

    for index in range(8):
        bit_start = first_bit + index * 0.030
        # Ignore transitions near the edges of each bit cell.
        a = int(round((bit_start + 0.003) * sample_rate))
        b = int(round((bit_start + 0.027) * sample_rate))
        cell = samples[a:b]
        if cell.size == 0:
            raise ValueError("audio is too short to contain a complete VIS header")

        e_1100 = tone_energy(cell, sample_rate, 1100.0)
        e_1300 = tone_energy(cell, sample_rate, 1300.0)
        bits.append(1 if e_1100 > e_1300 else 0)

    vis_value = sum(bits[index] << index for index in range(7))
    parity_bit = bits[7]
    expected_even_parity = sum(bits[:7]) & 1
    if parity_bit != expected_even_parity:
        raise ValueError(
            f"invalid VIS parity: data bits={bits[:7]}, parity={parity_bit}"
        )
    return bits, vis_value, parity_bit


def decode_martin_m1(samples: np.ndarray, sample_rate: int) -> np.ndarray:
    """FM-demodulate a Martin M1 SSTV frame into an RGB image."""
    required = int(round((IMAGE_START + HEIGHT * LINE_DURATION) * sample_rate))
    if samples.size < required - 4:
        raise ValueError(
            f"audio is too short: need about {required} samples, got {samples.size}"
        )

    # The phase slope of the analytic signal is the instantaneous FM frequency.
    phase = np.unwrap(np.angle(hilbert(samples)))

    # Martin modes send color scans in G, B, R order.
    scan_offsets = (
        SYNC_DURATION + PORCH_DURATION,
        SYNC_DURATION + PORCH_DURATION + SCAN_DURATION + SEPARATOR_DURATION,
        SYNC_DURATION
        + PORCH_DURATION
        + 2 * (SCAN_DURATION + SEPARATOR_DURATION),
    )
    rgb_channels = (1, 2, 0)
    pixel_duration = SCAN_DURATION / WIDTH
    image = np.zeros((HEIGHT, WIDTH, 3), dtype=np.uint8)

    for y in range(HEIGHT):
        line_start = IMAGE_START + y * LINE_DURATION
        for scan_offset, channel in zip(scan_offsets, rgb_channels):
            for x in range(WIDTH):
                center = line_start + scan_offset + (x + 0.5) * pixel_duration

                # Estimate the phase slope over the middle 60% of the pixel cell.
                half_window = 0.30 * pixel_duration
                a = max(0, int(round((center - half_window) * sample_rate)))
                b = min(
                    phase.size - 1,
                    int(round((center + half_window) * sample_rate)),
                )
                if b <= a:
                    frequency = 1500.0
                else:
                    frequency = (
                        (phase[b] - phase[a])
                        * sample_rate
                        / (2 * np.pi * (b - a))
                    )

                # SSTV video level: 1500 Hz = black, 2300 Hz = white.
                level = int(round((frequency - 1500.0) * 255.0 / 800.0))
                image[y, x, channel] = np.uint8(np.clip(level, 0, 255))

    return image


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        default=Path("transmission.ogg"),
        help="input Ogg/audio file (default: transmission.ogg)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("decoded_martin_m1.png"),
        help="decoded PNG path",
    )
    args = parser.parse_args()

    if not args.input.is_file():
        print(f"error: input file not found: {args.input}", file=sys.stderr)
        return 1

    wav_path = args.output.with_suffix(".wav")
    try:
        convert_to_wav(args.input, wav_path)
        sample_rate, samples = read_wav(wav_path)
    finally:
        wav_path.unlink(missing_ok=True)

    bits, vis_value, parity = decode_vis(samples, sample_rate)
    print(f"[+] VIS bits (LSB-first, including parity): {''.join(map(str, bits))}")
    print(f"[+] VIS value: {vis_value}; parity bit: {parity}")
    if vis_value != 44:
        print("error: transmission is not Martin M1 (expected VIS 44)", file=sys.stderr)
        return 1

    image = decode_martin_m1(samples, sample_rate)
    Image.fromarray(image, "RGB").save(args.output)
    print(f"[+] Decoded Martin M1 image: {args.output}")
    print("[+] Flag visible in the decoded image:")
    print("<FLAG>bushbash{gR0und_c0ntr0l}</FLAG>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
