#!/usr/bin/env python3
import re
import subprocess
import numpy as np


def run(cmd: str) -> str:
    return subprocess.check_output(cmd, shell=True, text=True)


def decode_flag(mp3_path: str = "whatsmyname.mp3") -> str:
    sil = run(
        f"ffmpeg -i '{mp3_path}' -af silencedetect=noise=-30dB:d=0.12 -f null - 2>&1"
    )
    starts = [float(x) for x in re.findall(r"silence_start: ([0-9.]+)", sil)]
    ends = [float(x) for x in re.findall(r"silence_end: ([0-9.]+)", sil)]
    sdurs = [e - s for s, e in zip(starts, ends)]

    raw = subprocess.check_output(
        [
            "ffmpeg",
            "-v",
            "error",
            "-i",
            mp3_path,
            "-f",
            "s16le",
            "-acodec",
            "pcm_s16le",
            "-ac",
            "1",
            "-ar",
            "48000",
            "-",
        ]
    )
    a = np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0
    sr = 48000

    segs = []
    pos = 0.0
    for s, e in zip(starts, ends):
        if s > pos:
            segs.append((pos, s))
        pos = e
    dur = len(a) / sr
    if dur > pos:
        segs.append((pos, dur))

    # Map tiap segmen suara jadi bit:
    # peak ~391 Hz => 1, peak ~196/262 Hz => 0
    bits = []
    for s, e in segs:
        x = a[int(s * sr) : int(e * sr)]
        trim = int(0.05 * sr)
        if len(x) > 2 * trim:
            x = x[trim:-trim]

        w = np.hanning(len(x))
        sp = np.abs(np.fft.rfft(x * w))
        f = np.fft.rfftfreq(len(x), 1 / sr)
        mask = (f > 100) & (f < 1000)
        ff = f[mask][np.argmax(sp[mask])]
        b = "1" if ff > 320 else "0"

        # Nada panjang mewakili simbol ganda
        reps = 2 if (e - s) > 1.1 else 1
        bits.append(b * reps)

    # Jeda panjang memisah kelompok kode
    groups = []
    cur = ""
    for i, bb in enumerate(bits):
        cur += bb
        if i < len(sdurs) and sdurs[i] >= 0.8:
            groups.append(cur)
            cur = ""
    if cur:
        groups.append(cur)

    # Dari pohon di sike.png:
    # 00=f, 010=p, 011=i, 10=e, 110=x, 111=r
    huff = {"00": "f", "010": "p", "011": "i", "10": "e", "110": "x", "111": "r"}

    text = ""
    for g in groups:
        i = 0
        while i < len(g):
            m = None
            for L in (2, 3):
                s = g[i : i + L]
                if s in huff:
                    m = s
                    break
            if m is None:
                raise ValueError(f"Decode gagal di bitstream: {g} offset {i}")
            text += huff[m]
            i += len(m)

    return f"sillyCTF{{{text}}}"


if __name__ == "__main__":
    flag = decode_flag("whatsmyname.mp3")
    print(flag)
