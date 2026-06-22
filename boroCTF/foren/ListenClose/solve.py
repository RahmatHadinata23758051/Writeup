#!/usr/bin/env python3
import sys
import wave
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt
from scipy import signal

FLAG = "boroCTF{Sp3c_R0}"


def read_wav(path: Path):
    with wave.open(str(path), "rb") as w:
        channels = w.getnchannels()
        sampwidth = w.getsampwidth()
        fs = w.getframerate()
        nframes = w.getnframes()
        raw = w.readframes(nframes)

    if channels != 1 or sampwidth != 2:
        raise SystemExit(f"unexpected format: channels={channels}, sampwidth={sampwidth}")

    samples = np.frombuffer(raw, dtype="<i2").astype(np.float32)
    return fs, samples


def render_spectrogram(wav_path: Path, out_path: Path):
    fs, samples = read_wav(wav_path)

    # The hidden text sits in the lower/mid frequency band. A dense overlap keeps
    # the letters readable while column-normalization reduces vertical noise.
    nperseg = 512
    noverlap = 500
    freqs, times, mag = signal.spectrogram(
        samples,
        fs=fs,
        window="hann",
        nperseg=nperseg,
        noverlap=noverlap,
        mode="magnitude",
    )

    db = 20 * np.log10(mag + 1e-3)
    fmask = (freqs >= 1200) & (freqs <= 8000)
    tmask = (times >= 0.2) & (times <= 9.9)
    z = db[fmask][:, tmask]

    med = np.median(z, axis=0, keepdims=True)
    mad = np.median(np.abs(z - med), axis=0, keepdims=True) + 1e-6
    z = np.clip((z - med) / mad, -3, 3)

    plt.figure(figsize=(24, 8))
    plt.imshow(z, origin="lower", aspect="auto", cmap="gray_r", vmin=-2, vmax=1)
    plt.axis("off")
    plt.savefig(out_path, dpi=200, bbox_inches="tight", pad_inches=0)
    plt.close()


def main():
    wav_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("chal(1).wav")
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("spectrogram_flag.png")

    render_spectrogram(wav_path, out_path)
    print(f"saved spectrogram: {out_path}")
    print(f"<FLAG>{FLAG}</FLAG>")


if __name__ == "__main__":
    main()
