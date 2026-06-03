#!/usr/bin/env python3
"""
Solver for Radio Chaos forensic challenge.

The input WAV contains an SSTV transmission. The VIS header decodes to 0x5f,
which is PD120. This script demodulates the SSTV FM audio and reconstructs the
PD120 image as decoded_sstv.png.
"""

import sys
import numpy as np
from scipy.io import wavfile
from scipy.signal import butter, sosfilt, hilbert
from PIL import Image

FREQ_BLACK = 1500.0
FREQ_WHITE = 2300.0
WIDTH = 640
HEIGHT = 496
PIXEL_SEC = 0.00019
SYNC_SEC = 0.020
PORCH_SEC = 0.00208
PERIOD_SEC = SYNC_SEC + PORCH_SEC + (4 * WIDTH * PIXEL_SEC)  # PD120 line-pair time

# The first image sync begins after the SSTV VIS header.
# From the waveform: leader/break/VIS ends, then the first PD120 sync starts here.
FIRST_SYNC_START = 0.909


def freq_to_byte(freq: np.ndarray) -> np.ndarray:
    """Map SSTV tone frequency 1500..2300 Hz back to image byte 0..255."""
    return np.clip((freq - FREQ_BLACK) / (FREQ_WHITE - FREQ_BLACK) * 255, 0, 255).astype(np.uint8)


def main() -> int:
    wav_path = sys.argv[1] if len(sys.argv) > 1 else "chaos.wav"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "decoded_sstv.png"

    sr, data = wavfile.read(wav_path)
    if sr != 44100:
        print(f"[!] Warning: expected 44100 Hz, got {sr} Hz")

    x = data.astype(np.float32)
    if data.dtype.kind in "iu":
        x /= max(abs(np.iinfo(data.dtype).min), np.iinfo(data.dtype).max)

    # Band-pass the SSTV tones, then compute instantaneous frequency.
    sos = butter(3, [900 / (sr / 2), 2600 / (sr / 2)], btype="bandpass", output="sos")
    y = sosfilt(sos, x)
    analytic = hilbert(y)
    phase = np.unwrap(np.angle(analytic))
    inst_freq = np.empty_like(x, dtype=np.float32)
    inst_freq[:-1] = np.diff(phase) * sr / (2 * np.pi)
    inst_freq[-1] = inst_freq[-2]
    inst_freq = np.convolve(inst_freq, np.ones(9, dtype=np.float32) / 9, mode="same")

    image_ycbcr = np.zeros((HEIGHT, WIDTH, 3), dtype=np.uint8)
    pixel_offsets = (np.arange(WIDTH) + 0.5) * PIXEL_SEC * sr
    segment_samples = WIDTH * PIXEL_SEC * sr

    for pair in range(HEIGHT // 2):
        scan_start = FIRST_SYNC_START + pair * PERIOD_SEC + SYNC_SEC + PORCH_SEC
        segments = []
        for seg in range(4):
            indices = np.round(scan_start * sr + seg * segment_samples + pixel_offsets).astype(np.int64)
            indices = np.clip(indices, 0, len(inst_freq) - 1)
            segments.append(freq_to_byte(inst_freq[indices]))

        # PD120 order: Y(line 0), Cb averaged, Cr averaged, Y(line 1)
        y0, cb, cr, y1 = segments
        image_ycbcr[2 * pair, :, 0] = y0
        image_ycbcr[2 * pair, :, 1] = cb
        image_ycbcr[2 * pair, :, 2] = cr
        image_ycbcr[2 * pair + 1, :, 0] = y1
        image_ycbcr[2 * pair + 1, :, 1] = cb
        image_ycbcr[2 * pair + 1, :, 2] = cr

    Image.fromarray(image_ycbcr, "YCbCr").convert("RGB").save(out_path)
    print(f"[+] Decoded SSTV image saved to {out_path}")
    print("[+] Flag: THEM?!CTF{YOU_ARE_A_SSTV_CHAMPION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
