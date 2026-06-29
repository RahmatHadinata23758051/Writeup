#!/usr/bin/env python3
from __future__ import annotations

import wave
from pathlib import Path

import numpy as np


WAV_PATH = Path("melody.wav")
CIPHERTEXT_PATH = Path("ciphertext.bin")


def extract_note_frequencies(path: Path) -> list[int]:
    with wave.open(str(path), "rb") as wav_file:
        sample_rate = wav_file.getframerate()
        samples = np.frombuffer(
            wav_file.readframes(wav_file.getnframes()), dtype="<i2"
        ).astype(np.float64)

    seconds = len(samples) // sample_rate
    frequencies = []
    for second in range(seconds):
        chunk = samples[second * sample_rate : (second + 1) * sample_rate]
        windowed = chunk * np.hanning(len(chunk))
        spectrum = np.fft.rfft(windowed)
        freqs = np.fft.rfftfreq(len(windowed), d=1 / sample_rate)
        spectrum[0] = 0
        dominant = int(round(freqs[np.abs(spectrum).argmax()]))
        frequencies.append(dominant)
    return frequencies


def xor_repeating(data: bytes, key: bytes) -> bytes:
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def main() -> None:
    ciphertext = CIPHERTEXT_PATH.read_bytes()
    frequencies = extract_note_frequencies(WAV_PATH)
    key = bytes(freq % 256 for freq in frequencies)
    plaintext = xor_repeating(ciphertext, key)

    print("frequencies:", frequencies)
    print("key_hex:", key.hex())
    print(plaintext.decode())


if __name__ == "__main__":
    main()
