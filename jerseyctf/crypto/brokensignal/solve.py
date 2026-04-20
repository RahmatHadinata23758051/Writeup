#!/usr/bin/env python3
import wave
import numpy as np
import itertools
from collections import Counter

WAV_PATH = 'Unidentified.wav'
CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ{}._'


def load_wav(path):
    with wave.open(path, 'rb') as w:
        fs = w.getframerate()
        x = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).astype(np.float64)
    return fs, x


def dominant_freq_trace(x, fs, fmin=180, fmax=1700, win=2048, hop=128):
    freq = np.fft.rfftfreq(win, 1 / fs)
    mask = (freq >= fmin) & (freq <= fmax)
    f = freq[mask]
    out = []
    for s in range(0, len(x) - win, hop):
        seg = x[s:s + win] * np.hanning(win)
        S = np.abs(np.fft.rfft(seg))[mask]
        i = int(np.argmax(S))
        out.append(f[i])
    return np.array(out), hop


def quantize_states(freqs, centers):
    c = np.array(centers, dtype=np.float64)
    idx = np.argmin(np.abs(freqs[:, None] - c[None, :]), axis=1)
    return idx


def majority_smooth(states, k=9, nstates=6):
    p = k // 2
    a = np.pad(states, (p, p), mode='edge')
    sm = np.empty_like(states)
    for i in range(len(states)):
        sm[i] = np.bincount(a[i:i + k], minlength=nstates).argmax()
    return sm


def rle(arr):
    runs = []
    cur = int(arr[0])
    l = 1
    for v in arr[1:]:
        v = int(v)
        if v == cur:
            l += 1
        else:
            runs.append((cur, l))
            cur = v
            l = 1
    runs.append((cur, l))
    return runs


def decode_runs_to_text(runs, b, off, mode='rowmajor', row_rev=False, col_rev=False):
    out = []
    for r, l in runs:
        c = int(round((l - off) / b))
        c = max(0, min(4, c))
        rr = 5 - r if row_rev else r
        cc = 4 - c if col_rev else c
        if not (0 <= rr < 6 and 0 <= cc < 5):
            out.append('?')
            continue
        idx = rr * 5 + cc if mode == 'rowmajor' else cc * 6 + rr
        out.append(CHARS[idx])
    return ''.join(out)


def dedup(s):
    out = []
    for ch in s:
        if not out or out[-1] != ch:
            out.append(ch)
    return ''.join(out)


def score_text(s):
    sc = 0
    sc += s.count('{') * 8 + s.count('}') * 8
    if '{' in s and '}' in s:
        sc += 60
    for tok in ['CTF{', 'JERSEY', 'FLAG{', 'BROKEN', 'SIGNAL']:
        sc += 80 * s.count(tok)
    sc += sum(ch in 'ETAOINSHRDLU{}_.' for ch in s[:250]) // 2
    sc -= s.count('?')
    return sc


def main():
    fs, x = load_wav(WAV_PATH)
    print(f'[+] fs={fs} n={len(x)} dur={len(x)/fs:.3f}s')

    # 6-state low-band model suggested by sheet: 252..1512 step ~252
    low_centers = [252, 504, 756, 1008, 1260, 1512]
    trace, hop = dominant_freq_trace(x, fs, 180, 1700, win=2048, hop=128)
    states = quantize_states(trace, low_centers)
    states = majority_smooth(states, k=9, nstates=6)
    runs = rle(states)

    # merge tiny glitches surrounded by equal states
    merged = []
    i = 0
    while i < len(runs):
        if 0 < i < len(runs) - 1 and runs[i][1] <= 2 and runs[i - 1][0] == runs[i + 1][0]:
            a = merged.pop()
            merged.append((a[0], a[1] + runs[i][1] + runs[i + 1][1]))
            i += 2
        else:
            merged.append(runs[i])
            i += 1
    runs = merged

    print(f'[+] runs={len(runs)} top_len={Counter(l for _, l in runs).most_common(12)}')

    cands = []
    for b in np.arange(1.5, 20.1, 0.25):
        for off in np.arange(0, b, 0.5):
            for mode, row_rev, col_rev in itertools.product(['rowmajor', 'colmajor'], [False, True], [False, True]):
                t = decode_runs_to_text(runs, b, off, mode=mode, row_rev=row_rev, col_rev=col_rev)
                td = dedup(t)
                sc = score_text(td)
                cands.append((sc, b, off, mode, row_rev, col_rev, td[:280]))

    cands.sort(key=lambda x: x[0], reverse=True)
    print('\n[+] top candidates:')
    for i, c in enumerate(cands[:30], 1):
        sc, b, off, mode, rr, cr, txt = c
        print(f'[{i:02d}] score={sc} b={b:.2f} off={off:.2f} mode={mode} row_rev={rr} col_rev={cr}')
        print(txt)
        print()


if __name__ == '__main__':
    main()
