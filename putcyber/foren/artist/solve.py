#!/usr/bin/env python3
import argparse
import os
import shutil
import wave

import numpy as np
from PIL import Image, ImageDraw


def read_stereo_wav(path: str):
    with wave.open(path, "rb") as w:
        if w.getsampwidth() != 2:
            raise ValueError("Expected 16-bit PCM WAV")
        if w.getnchannels() != 2:
            raise ValueError("Expected stereo WAV (2 channels)")
        fs = w.getframerate()
        raw = w.readframes(w.getnframes())
    samples = np.frombuffer(raw, dtype="<i2").reshape(-1, 2).astype(np.float32) / 32768.0
    return fs, samples


def detect_sweep_boundaries(left_channel: np.ndarray, threshold: float = -0.6, min_gap: int = 1000):
    candidates = np.where(np.diff(left_channel) < threshold)[0] + 1
    boundaries = []
    last = -10**9
    for idx in candidates:
        if idx - last > min_gap:
            boundaries.append(int(idx))
            last = int(idx)
    return np.array(boundaries, dtype=np.int64)


def draw_xy_frame(x: np.ndarray, y: np.ndarray, size: int = 880, line_width: int = 2):
    # Fixed coordinate system like vectorscope: -1..1 on each axis.
    to_px_x = ((np.clip(x, -1.0, 1.0) + 1.0) * 0.5 * (size - 1)).astype(np.int32)
    to_px_y = ((1.0 - (np.clip(y, -1.0, 1.0) + 1.0) * 0.5) * (size - 1)).astype(np.int32)

    img = Image.new("L", (size, size), color=255)
    draw = ImageDraw.Draw(img)
    points = list(zip(to_px_x.tolist(), to_px_y.tolist()))
    if len(points) >= 2:
        draw.line(points, fill=0, width=line_width)
    return img


def build_xy_lines(wav_path: str, out_dir: str, start_sec: float = 13.0, end_sec: float = 28.0):
    fs, stereo = read_stereo_wav(wav_path)
    start = int(start_sec * fs)
    end = int(end_sec * fs)

    left = stereo[start:end, 0]
    right = stereo[start:end, 1]

    boundaries = detect_sweep_boundaries(left, threshold=-0.6, min_gap=1000)
    if len(boundaries) < 2:
        raise RuntimeError("Failed to detect sweep boundaries")

    os.makedirs(out_dir, exist_ok=True)
    count = 0
    for i in range(len(boundaries) - 1):
        a, b = int(boundaries[i]), int(boundaries[i + 1])
        x = left[a:b]
        y = right[a:b]
        if len(x) < 2:
            continue

        frame = draw_xy_frame(x, y, size=880, line_width=2)
        frame.save(os.path.join(out_dir, f"f{i:03d}.png"))
        count += 1

    return count


def main():
    parser = argparse.ArgumentParser(description="Generate xy_lines frames from my_first_song.wav")
    parser.add_argument("-i", "--input", default="my_first_song.wav", help="Input WAV path")
    parser.add_argument("-o", "--output", default="xy_lines", help="Output directory")
    parser.add_argument("--clean", action="store_true", help="Delete existing output directory first")
    args = parser.parse_args()

    if args.clean and os.path.isdir(args.output):
        shutil.rmtree(args.output)

    n = build_xy_lines(args.input, args.output)
    print(f"Generated {n} frame(s) in: {args.output}")


if __name__ == "__main__":
    main()
