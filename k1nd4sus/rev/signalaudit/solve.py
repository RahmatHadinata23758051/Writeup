#!/usr/bin/env python3
import wave
import numpy as np
from scipy.signal import hilbert
from PIL import Image

WAV_PATH = "audit.wav"
OUT_LUMA = "decoded_luma.png"
FLAG = "KSUS{s4n1ty_ch3ck_QSL_7373}"


def load_audio(path: str):
    with wave.open(path, "rb") as w:
        fs = w.getframerate()
        x = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).astype(float)
    return fs, x


def inst_freq(signal: np.ndarray, fs: int):
    ana = hilbert(signal)
    phase = np.unwrap(np.angle(ana))
    f = np.diff(phase) * fs / (2 * np.pi)
    k = max(1, int(fs * 0.00015))
    f = np.convolve(f, np.ones(k) / k, mode="same")
    return f


def decode_robot36_luma(freq: np.ndarray, fs: int, width=320, height=240):
    period = 0.150

    def f_at(t: float):
        i = int(t * fs)
        i = 0 if i < 0 else (len(freq) - 1 if i >= len(freq) else i)
        return freq[i]

    # Find line-0 timing by minimizing sync-tone error on early lines.
    best_err, t0 = 1e18, 0.911
    for cand in np.arange(0.905, 0.918, 0.0002):
        err = 0.0
        for n in range(30):
            st = cand + n * period
            vals = [f_at(st + 0.001 + i * 0.001) for i in range(7)]
            err += np.mean((np.array(vals) - 1200.0) ** 2)
        if err < best_err:
            best_err, t0 = err, cand

    # Robot36 line layout: sync(9ms) + porch(3ms) + Y(88ms)
    y = np.zeros((height, width), dtype=np.uint8)
    for row in range(height):
        st = t0 + row * period
        ystart = st + 0.009 + 0.003
        for col in range(width):
            t = ystart + (col + 0.5) * (0.088 / width)
            val = (f_at(t) - 1500.0) / 800.0 * 255.0
            y[row, col] = np.uint8(np.clip(val, 0, 255))

    return y


def main():
    fs, x = load_audio(WAV_PATH)
    f = inst_freq(x, fs)
    luma = decode_robot36_luma(f, fs)
    Image.fromarray(luma).save(OUT_LUMA)

    # Flag terbaca dari hasil decode SSTV (teks overlay bagian bawah image).
    print(FLAG)


if __name__ == "__main__":
    main()
