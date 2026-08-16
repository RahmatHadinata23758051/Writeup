#!/usr/bin/env python3
import wave
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt

BASE = Path(__file__).resolve().parent
WAV = BASE / 'signal.wav'
OUT = BASE / 'recovered_flag_exact.png'
FLAG = 'THJCC{6pákos}'  # á = U+00E1

def zero_runs(x, min_len):
    z = (x == 0)
    d = np.diff(np.r_[False, z, False].astype(np.int8))
    starts = np.where(d == 1)[0]
    ends = np.where(d == -1)[0]
    return [(s, e) for s, e in zip(starts, ends) if e - s >= min_len]

def divisors(n):
    out=[]
    for i in range(1, int(n**0.5)+1):
        if n % i == 0:
            out += [i]
            if i*i != n:
                out += [n//i]
    return sorted(set(out))

def main():
    with wave.open(str(WAV), 'rb') as w:
        assert w.getnchannels() == 2 and w.getsampwidth() == 2
        sr = w.getframerate()
        a = np.frombuffer(w.readframes(w.getnframes()), dtype='<i2').reshape(-1, 2)

    L, R = a[:,0], a[:,1]
    # The hidden XY payload is bracketed by 150 ms silence in each channel.
    min_zero = int(sr * 0.12)
    zrL = [r for r in zero_runs(L, min_zero) if r[0] > sr]
    zrR = [r for r in zero_runs(R, min_zero) if r[0] > sr]
    if len(zrL) < 2 or len(zrR) < 2:
        raise SystemExit('Could not locate payload boundaries')

    # First long zero run ends at payload start; next begins at payload end.
    sL, eL = zrL[0][1], zrL[1][0]
    sR, eR = zrR[0][1], zrR[1][0]
    delay = sR - sL
    if (eL - sL) != (eR - sR):
        raise SystemExit('Channel payload lengths differ unexpectedly')

    x = L[sL:eL]
    y = R[sR:eR]
    n = len(x)

    # Find the smallest exact repeating frame period common to both channels.
    period = None
    for p in divisors(n):
        if p < 100:
            continue
        if np.array_equal(x, np.tile(x[:p], n//p)) and np.array_equal(y, np.tile(y[:p], n//p)):
            period = p
            break
    if period is None:
        raise SystemExit('Could not find exact frame period')

    x = x[:period].astype(float)
    y = y[:period].astype(float)

    # Rotate drawing to make the two text rows horizontal and suppress fast travel lines.
    deg = -20.0
    t = np.deg2rad(deg)
    xr = x*np.cos(t) - y*np.sin(t)
    yr = x*np.sin(t) + y*np.cos(t)
    speed = np.hypot(np.diff(x), np.diff(y))

    fig = plt.figure(figsize=(15, 7))
    ax = fig.add_subplot(111)
    for i in range(period - 1):
        if speed[i] < 300:
            ax.plot(xr[i:i+2], yr[i:i+2], linewidth=1.3)
    ax.set_aspect('equal', adjustable='box')
    ax.axis('off')
    fig.tight_layout()
    fig.savefig(OUT, dpi=220, bbox_inches='tight')
    plt.close(fig)

    print(f'sample_rate={sr}')
    print(f'channel_delay={delay} samples ({delay/sr*1000:.3f} ms)')
    print(f'payload_length={n} samples')
    print(f'period={period} samples, repeats={n//period}')
    print(f'image={OUT}')
    print(f'FLAG={FLAG}')
    print('UTF-8 for á:', 'á'.encode('utf-8').hex())

if __name__ == '__main__':
    main()

