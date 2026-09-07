#!/usr/bin/env python3
import struct
from pathlib import Path

import numpy as np

FS = 50_000          # sample rate from the JLS capture metadata
THRESHOLD = 0.006   # active CPU current is clearly above this value
MIN_RUN = 100       # ignore short spikes: 100 samples = 2 ms
MERGE_GAP = 50      # merge small gaps inside one active window: 1 ms


def find_signal_chunks(buf: bytes):
    """Return valid JLS sample chunks grouped by signal subtype."""
    chunks = {}

    # JLS chunks in this file are 8-byte aligned.  A sample chunk has:
    #   header: 32 bytes
    #   metadata: signal_id, start_sample, sample_count, sample_stride
    #   payload: sample_count little-endian float32 values
    for off in range(0, len(buf) - 48, 8):
        typ, subtype = struct.unpack_from('<HH', buf, off + 16)
        if typ != 0x22 or subtype not in (1, 2, 3):
            continue

        try:
            signal_id, start_sample, sample_count, sample_stride = struct.unpack_from('<IIII', buf, off + 32)
        except struct.error:
            continue

        if not (0 < sample_count <= 8192 and sample_stride == 32):
            continue
        data_off = off + 48
        data_end = data_off + sample_count * 4
        if data_end > len(buf):
            continue

        # Quick sanity check to avoid false-positive headers.
        sample = np.frombuffer(buf, dtype='<f4', count=min(sample_count, 64), offset=data_off)
        if not np.all(np.isfinite(sample)):
            continue

        chunks.setdefault(subtype, []).append((off, sample_count))

    return chunks


def extract_current(buf: bytes) -> np.ndarray:
    chunks = find_signal_chunks(buf)
    if not chunks:
        raise RuntimeError('no JLS sample chunks found')

    # In this capture subtype 1 is current, subtype 2 is power, subtype 3 is voltage.
    # To keep this reproducible, select the non-voltage stream with the highest median.
    # Current sits around 2-3 mA, while power is around 0.9 mW.
    best_subtype = None
    best_median = -1.0
    for subtype, entries in chunks.items():
        preview = []
        for off, count in entries[:5]:
            preview.append(np.frombuffer(buf, dtype='<f4', count=count, offset=off + 48))
        x = np.concatenate(preview)
        med = float(np.median(x))
        if 0 < med < 0.1 and med > best_median:
            best_subtype = subtype
            best_median = med

    if best_subtype is None:
        raise RuntimeError('could not identify the current stream')

    current = []
    for off, count in sorted(chunks[best_subtype]):
        current.append(np.frombuffer(buf, dtype='<f4', count=count, offset=off + 48).copy())
    return np.concatenate(current)


def active_runs(current: np.ndarray):
    high = current > THRESHOLD
    edges = np.diff(high.astype(np.int8), prepend=0, append=0)
    starts = np.where(edges == 1)[0]
    ends = np.where(edges == -1)[0]

    runs = []
    for start, end in zip(starts, ends):
        if end - start < MIN_RUN // 4:
            continue
        if runs and start - runs[-1][1] < MERGE_GAP:
            runs[-1] = (runs[-1][0], end)
        else:
            runs.append((start, end))

    return [(s, e) for s, e in runs if e - s >= MIN_RUN]


def decode_flag(jls_path: Path) -> str:
    buf = jls_path.read_bytes()
    current = extract_current(buf)
    runs = active_runs(current)

    if len(runs) < 2:
        raise RuntimeError('not enough active CPU windows detected')

    chars = []
    for (_, end), (next_start, _) in zip(runs, runs[1:]):
        sleep_ms = round((next_start - end) * 1000 / FS)
        if not (32 <= sleep_ms <= 126):
            raise RuntimeError(f'non-printable sleep duration detected: {sleep_ms} ms')
        chars.append(chr(sleep_ms))

    flag = ''.join(chars)
    if not (flag.startswith('NNS{') and flag.endswith('}')):
        raise RuntimeError(f'decoded text does not look like a flag: {flag!r}')
    return flag


def main():
    jls_path = Path(__file__).resolve().parent / 'sleepy_cpu.jls'
    flag = decode_flag(jls_path)
    print(f'<FLAG>{flag}</FLAG>')


if __name__ == '__main__':
    main()
