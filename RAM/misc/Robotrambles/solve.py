#!/usr/bin/env python3
"""
Decode the SSTV audio from rambles.wav.

The file uses VIS code 60, which is Scottie 1.  This script demodulates the
FM audio into instantaneous frequency, reconstructs the 320x256 RGB image,
and writes decoded_scottie1.png next to the input file.
"""
from __future__ import annotations

import sys
import wave
from pathlib import Path

import numpy as np
from PIL import Image
from scipy.signal import hilbert

WIDTH = 320
HEIGHT = 256

# Scottie 1 timing, in seconds.
SEP = 0.0015
SYNC = 0.009
CHAN = 0.13824
LINE = 3 * CHAN + 3 * SEP + SYNC

# VIS timing.  In this sample the standard VIS start bit starts at 1.410 s:
# 1900 Hz leader, 1200 Hz break, 1900 Hz leader, then 30 ms start/data bits.
VIS_START = 1.410
VIS_BIT = 0.030

BLACK_HZ = 1500.0
WHITE_HZ = 2300.0
VIDEO_SPAN_HZ = WHITE_HZ - BLACK_HZ

FLAG = "RMCTF{1_c4N_533_c13Ar1y_n0W}"


def read_wav(path: Path) -> tuple[int, np.ndarray]:
    with wave.open(str(path), "rb") as wav:
        channels = wav.getnchannels()
        sample_width = wav.getsampwidth()
        sample_rate = wav.getframerate()
        frames = wav.getnframes()
        raw = wav.readframes(frames)

    if sample_width != 2:
        raise ValueError(f"expected 16-bit PCM, got sample width {sample_width}")

    audio = np.frombuffer(raw, dtype="<i2").astype(np.float32) / 32768.0
    if channels > 1:
        audio = audio.reshape(-1, channels).mean(axis=1)
    return sample_rate, audio


def instantaneous_frequency(audio: np.ndarray, sample_rate: int) -> np.ndarray:
    analytic = hilbert(audio)
    phase = np.unwrap(np.angle(analytic))
    return np.diff(phase) * sample_rate / (2 * np.pi)


def median_freq(freq: np.ndarray, sample_rate: int, start: float, duration: float) -> float:
    a = max(0, int(start * sample_rate))
    b = min(len(freq), int((start + duration) * sample_rate))
    if b <= a:
        return float("nan")
    return float(np.median(freq[a:b]))


def read_vis_code(freq: np.ndarray, sample_rate: int, start: float = VIS_START) -> int:
    """Read seven VIS data bits. VIS sends 1100 Hz for 1 and 1300 Hz for 0."""
    bits: list[int] = []
    for i in range(7):
        f = median_freq(freq, sample_rate, start + VIS_BIT * (1 + i), VIS_BIT)
        bits.append(1 if f < 1200.0 else 0)
    return sum(bit << i for i, bit in enumerate(bits))


def sample_video_line(freq: np.ndarray, sample_rate: int, start: float) -> np.ndarray:
    """Sample one 138.24 ms Scottie component into 320 pixels."""
    pixel_time = CHAN / WIDTH
    out = np.empty(WIDTH, dtype=np.float32)

    for x in range(WIDTH):
        # Ignore a small amount of each pixel edge to avoid transition bleed.
        a = int((start + (x + 0.15) * pixel_time) * sample_rate)
        b = int((start + (x + 0.85) * pixel_time) * sample_rate)
        if b <= a:
            b = a + 1
        out[x] = np.median(freq[a:b])

    out = np.clip((out - BLACK_HZ) * 255.0 / VIDEO_SPAN_HZ, 0, 255)
    return out.astype(np.uint8)


def decode_scottie1(freq: np.ndarray, sample_rate: int) -> Image.Image:
    # VIS stop ends after start + 10 VIS bits (start + 7 data + parity + stop).
    # This recording then has the first 9 ms line sync and a 1.5 ms separator.
    first_green = VIS_START + VIS_BIT * 10 + SYNC + SEP

    img = np.zeros((HEIGHT, WIDTH, 3), dtype=np.uint8)
    for y in range(HEIGHT):
        green_start = first_green + y * LINE
        blue_start = green_start + CHAN + SEP
        red_start = green_start + CHAN + SEP + CHAN + SYNC + SEP

        img[y, :, 0] = sample_video_line(freq, sample_rate, red_start)
        img[y, :, 1] = sample_video_line(freq, sample_rate, green_start)
        img[y, :, 2] = sample_video_line(freq, sample_rate, blue_start)

    return Image.fromarray(img, "RGB")


def main() -> None:
    wav_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("rambles.wav")
    out_path = wav_path.with_name("decoded_scottie1.png")

    sample_rate, audio = read_wav(wav_path)
    freq = instantaneous_frequency(audio, sample_rate)
    vis_code = read_vis_code(freq, sample_rate)

    if vis_code != 60:
        raise RuntimeError(f"unexpected VIS code {vis_code}; expected 60 for Scottie 1")

    image = decode_scottie1(freq, sample_rate)
    image.save(out_path)

    print(f"VIS code: {vis_code} (Scottie 1)")
    print(f"Decoded image: {out_path}")
    print(f"Flag: {FLAG}")


if __name__ == "__main__":
    main()
