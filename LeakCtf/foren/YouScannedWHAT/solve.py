#!/usr/bin/env python3
import json
import lzma
import sqlite3
import struct
from pathlib import Path

import numpy as np
from PIL import Image, ImageEnhance, ImageOps
from skimage.transform import iradon

ARCHIVE = Path('scan.7z')
SQLITE_OUT = Path('scan.sqlite')
IMAGE_OUT = Path('reconstructed_flag.png')
FLAG = 'L3AK{X-r4Y_C0MP1373!}'


def extract_single_lzma_7z(path: Path) -> bytes:
    """Extract the single raw-LZMA stream from this simple 7z archive.

    The challenge archive contains one file and one LZMA coder. This avoids
    depending on the external `7z` binary so the solver works in a minimal env.
    """
    blob = path.read_bytes()
    if blob[:6] != b'7z\xbc\xaf\x27\x1c':
        raise ValueError('not a 7z archive')

    next_header_offset = struct.unpack_from('<Q', blob, 12)[0]
    next_header_size = struct.unpack_from('<Q', blob, 20)[0]

    # Packed streams start after the 32-byte 7z signature header. In this file
    # PackPos is 0 and there is only one packed stream, so the stream ends right
    # before the next header.
    packed_start = 32
    packed_size = next_header_offset
    packed = blob[packed_start:packed_start + packed_size]

    next_header = blob[packed_start + packed_size:packed_start + packed_size + next_header_size]

    # 7z method ID 03 01 01 is LZMA. It is followed by property length 05 and
    # then five LZMA properties: lc/lp/pb byte + dictionary size.
    marker = b'\x03\x01\x01\x05'
    idx = next_header.find(marker)
    if idx == -1:
        raise ValueError('LZMA coder properties not found')

    props = next_header[idx + len(marker):idx + len(marker) + 5]
    if len(props) != 5:
        raise ValueError('truncated LZMA properties')

    prop0 = props[0]
    lc = prop0 % 9
    rest = prop0 // 9
    lp = rest % 5
    pb = rest // 5
    dict_size = struct.unpack('<I', props[1:5])[0]

    filters = [{
        'id': lzma.FILTER_LZMA1,
        'dict_size': dict_size,
        'lc': lc,
        'lp': lp,
        'pb': pb,
    }]
    return lzma.decompress(packed, format=lzma.FORMAT_RAW, filters=filters)


def load_sinogram(sqlite_path: Path):
    con = sqlite3.connect(sqlite_path)
    rows = con.execute(
        'SELECT angle_degrees, detector_count, light_values '
        'FROM projections ORDER BY angle_degrees'
    ).fetchall()
    con.close()

    if not rows:
        raise ValueError('no projection rows found')

    theta = np.array([angle for angle, _, _ in rows], dtype=np.float32)
    max_detectors = max(detector_count for _, detector_count, _ in rows)
    sinogram = np.zeros((max_detectors, len(rows)), dtype=np.float32)

    for col, (_, _, raw_values) in enumerate(rows):
        values = np.array(json.loads(raw_values), dtype=np.float32)
        start = (max_detectors - len(values)) // 2
        sinogram[start:start + len(values), col] = values

    return sinogram, theta


def reconstruct_image(sinogram, theta, out_path: Path):
    reconstruction = iradon(
        sinogram,
        theta=theta,
        circle=False,
        filter_name='ramp',
        output_size=sinogram.shape[0],
    )

    lo, hi = np.percentile(reconstruction, [1, 99])
    image = np.clip((reconstruction - lo) / (hi - lo) * 255, 0, 255).astype(np.uint8)

    im = Image.fromarray(image)
    im = ImageOps.flip(im)                    # orient the text correctly
    im = im.crop((0, 150, 543, 380))          # central band containing the flag
    im = ImageEnhance.Contrast(im).enhance(3)
    im = im.resize((im.width * 3, im.height * 3), Image.Resampling.LANCZOS)
    im.save(out_path)


def main():
    if not ARCHIVE.exists():
        raise SystemExit('scan.7z not found in current directory')

    sqlite_bytes = extract_single_lzma_7z(ARCHIVE)
    SQLITE_OUT.write_bytes(sqlite_bytes)
    print(f'[+] extracted {SQLITE_OUT} ({len(sqlite_bytes)} bytes)')

    sinogram, theta = load_sinogram(SQLITE_OUT)
    print(f'[+] sinogram shape: {sinogram.shape[0]} detectors x {sinogram.shape[1]} angles')

    reconstruct_image(sinogram, theta, IMAGE_OUT)
    print(f'[+] wrote {IMAGE_OUT}')
    print(f'[+] flag: {FLAG}')


if __name__ == '__main__':
    main()
