#!/usr/bin/env python3
"""Recover the hidden hexadecimal Morse message from chall.wav."""

from __future__ import annotations

import argparse
import re
import wave
from pathlib import Path

import numpy as np

MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9",
}


def read_pcm16_mono(path: Path) -> tuple[int, np.ndarray]:
    with wave.open(str(path), "rb") as wav:
        if wav.getnchannels() != 1 or wav.getsampwidth() != 2:
            raise ValueError("expected mono 16-bit PCM WAV")
        fs = wav.getframerate()
        raw = wav.readframes(wav.getnframes())
    return fs, np.frombuffer(raw, dtype="<i2").astype(np.float64) / 32768.0


def dominant_frequencies(x: np.ndarray, fs: int) -> tuple[float, float]:
    """Infer the audible keying tone and ultrasonic DSB carrier."""
    spectrum = np.fft.rfft(x)
    magnitude = np.abs(spectrum)
    freq = np.fft.rfftfreq(x.size, 1.0 / fs)

    audible = (freq >= 300.0) & (freq <= 3000.0)
    tone = float(freq[np.flatnonzero(audible)[np.argmax(magnitude[audible])]])

    ultrasonic = (freq >= 20000.0) & (freq <= fs / 2 - 100.0)
    candidates = np.flatnonzero(ultrasonic)
    first = candidates[np.argmax(magnitude[ultrasonic])]

    separated = ultrasonic & (np.abs(freq - freq[first]) >= 500.0)
    second_candidates = np.flatnonzero(separated)
    second = second_candidates[np.argmax(magnitude[separated])]
    carrier = float((freq[first] + freq[second]) / 2.0)
    return tone, carrier


def lowpass_fft(x: np.ndarray, fs: int, cutoff: float) -> np.ndarray:
    spectrum = np.fft.rfft(x)
    freq = np.fft.rfftfreq(x.size, 1.0 / fs)
    spectrum[freq > cutoff] = 0.0
    return np.fft.irfft(spectrum, n=x.size)


def moving_average_complex(x: np.ndarray, width: int) -> np.ndarray:
    width = max(1, int(width))
    csum = np.concatenate((np.zeros(1, dtype=np.complex128), np.cumsum(x)))
    avg = (csum[width:] - csum[:-width]) / width
    left = width // 2
    right = x.size - avg.size - left
    return np.pad(avg, (left, right), mode="edge")


def clean_short_runs(bits: np.ndarray, minimum: int) -> np.ndarray:
    bits = bits.copy()
    for _ in range(4):
        changes = np.flatnonzero(np.diff(bits.astype(np.int8))) + 1
        edges = np.concatenate(([0], changes, [bits.size]))
        runs = [(bool(bits[s]), int(s), int(e)) for s, e in zip(edges[:-1], edges[1:])]
        changed = False
        for i, (value, start, end) in enumerate(runs):
            if (
                end - start < minimum
                and i > 0
                and i + 1 < len(runs)
                and runs[i - 1][0] == runs[i + 1][0]
            ):
                bits[start:end] = runs[i - 1][0]
                changed = True
        if not changed:
            break
    return bits


def decode_morse(signal: np.ndarray, fs: int, tone: float) -> tuple[str, list[str]]:
    # Coherent detection of the roughly 1 kHz on/off keyed tone.
    t = np.arange(signal.size, dtype=np.float64) / fs
    baseband = signal * np.exp(-2j * np.pi * tone * t)
    envelope = np.abs(moving_average_complex(baseband, round(0.010 * fs)))

    threshold = (np.median(envelope) + np.percentile(envelope, 95)) / 3.0
    keyed = clean_short_runs(envelope > threshold, round(0.030 * fs))

    changes = np.flatnonzero(np.diff(keyed.astype(np.int8))) + 1
    edges = np.concatenate(([0], changes, [keyed.size]))

    symbols: list[str] = []
    current = ""
    for start, end in zip(edges[:-1], edges[1:]):
        active = bool(keyed[start])
        duration = (end - start) / fs
        if active and duration >= 0.030:
            current += "-" if duration > 0.130 else "."
        elif not active and duration > 0.300 and current:
            symbols.append(current)
            current = ""
    if current:
        symbols.append(current)

    decoded = "".join(MORSE.get(symbol, "?") for symbol in symbols)
    return decoded, symbols


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("wav", nargs="?", default="chall.wav", type=Path)
    args = parser.parse_args()

    fs, samples = read_pcm16_mono(args.wav)
    tone, carrier = dominant_frequencies(samples, fs)

    # The hidden channel is double-sideband suppressed-carrier modulation near 35 kHz.
    t = np.arange(samples.size, dtype=np.float64) / fs
    mixed = 2.0 * samples * np.cos(2.0 * np.pi * carrier * t)
    demodulated = lowpass_fft(mixed, fs, cutoff=7000.0)

    # 80 kHz -> 16 kHz after the signal has been low-pass filtered below 8 kHz.
    factor = max(1, fs // 16000)
    demodulated = demodulated[::factor]
    output_fs = fs // factor

    hidden, symbols = decode_morse(demodulated, output_fs, tone)
    if not re.fullmatch(r"[0-9A-Fa-f]+", hidden):
        raise RuntimeError(f"decoded data is not hexadecimal: {hidden!r}; symbols={symbols}")

    print(f"[+] keying tone : {tone:.2f} Hz")
    print(f"[+] DSB carrier : {carrier:.2f} Hz")
    print(f"[+] Morse       : {' '.join(symbols)}")
    print(f"[+] hex         : {hidden.lower()}")
    print(f"uctf{{{hidden.lower()}}}")


if __name__ == "__main__":
    main()
