# You Scanned WHAT?!?

**Category:** Forensics / Miscellaneous

## Challenge Description

We are given a `7z` archive containing an unknown file.

The recovered flag is:

```text
L3AK{X-r4Y_C0MP1373!}
```

---

## Initial Analysis

The provided artifact is a 7-Zip archive.

```bash
file scan.7z
sha256sum scan.7z
```

Output:

```text
scan.7z: 7-zip archive data, version 0.3
e45a1da91290e654002c5c1ea49e5bf3caaad0e073dd76d848c2c2b6b955a92c  scan.7z
```

Running `strings` on the archive does not reveal anything useful, indicating that the flag is not directly embedded as plain text.

Normally the archive can be extracted using:

```bash
7z x scan.7z
```

However, the challenge environment may not provide the `7z` utility.

Fortunately, this archive is very simple:

- one packed stream
- one LZMA coder
- one SQLite database

Therefore the LZMA stream can be extracted directly using Python without relying on external tools.

After extraction:

```text
scan.sqlite: SQLite 3.x database
```

---

## Database Structure

The SQLite database contains a single table:

```sql
CREATE TABLE projections (
    angle_degrees INTEGER PRIMARY KEY,
    detector_count INTEGER NOT NULL,
    light_values TEXT NOT NULL
);
```

Querying the database:

```python
import sqlite3

con = sqlite3.connect("scan.sqlite")

rows = con.execute(
    """
    SELECT angle_degrees,
           detector_count,
           light_values
    FROM projections
    ORDER BY angle_degrees
    """
).fetchall()

print(len(rows))
print(rows[0][0], rows[-1][0])
print(min(r[1] for r in rows), max(r[1] for r in rows))
```

Output:

```text
180
0 179
215 543
```

The data consists of:

- 180 projection angles
- detector measurements for each angle

This layout closely matches a **CT scan sinogram**.

The challenge title and description also hint toward medical imaging:

> scan of some sort

> local hospital

---

## Reconstructing the Image

Each projection has a different detector length.

Examples:

```text
0°   -> 497 detectors
21°  -> 543 detectors
90°  -> 215 detectors
```

This happens because rotating a rectangular object changes the projection width.

To build a proper sinogram:

- determine the maximum detector length (`543`)
- center every projection
- pad shorter projections with zeros

The resulting sinogram has dimensions:

```text
543 detectors × 180 projection angles
```

The original image can then be reconstructed using the inverse Radon transform (filtered back projection).

```python
from skimage.transform import iradon

reconstruction = iradon(
    sinogram,
    theta=theta,
    circle=False,
    filter_name="ramp",
    output_size=sinogram.shape[0],
)
```

After reconstruction:

1. Normalize the pixel values.
2. Flip the image vertically.
3. Crop the useful region.
4. Increase contrast.

The reconstructed image clearly reveals:

```text
L3AK{X-r4Y_C0MP1373!}
```

---

## Solver

Save the following as `solve.py`.

```python
#!/usr/bin/env python3
import json
import lzma
import sqlite3
import struct
from pathlib import Path

import numpy as np
from PIL import Image, ImageEnhance, ImageOps
from skimage.transform import iradon

ARCHIVE = Path("scan.7z")
SQLITE_OUT = Path("scan.sqlite")
IMAGE_OUT = Path("reconstructed_flag.png")
FLAG = "L3AK{X-r4Y_C0MP1373!}"


def extract_single_lzma_7z(path: Path) -> bytes:
    """Extract the raw LZMA stream from this simple 7z archive."""

    blob = path.read_bytes()

    if blob[:6] != b"7z\xbc\xaf\x27\x1c":
        raise ValueError("Not a 7z archive")

    next_header_offset = struct.unpack_from("<Q", blob, 12)[0]
    next_header_size = struct.unpack_from("<Q", blob, 20)[0]

    packed_start = 32
    packed_size = next_header_offset

    packed = blob[packed_start:packed_start + packed_size]

    next_header = blob[
        packed_start + packed_size:
        packed_start + packed_size + next_header_size
    ]

    marker = b"\x03\x01\x01\x05"
    idx = next_header.find(marker)

    if idx == -1:
        raise ValueError("LZMA properties not found")

    props = next_header[idx + len(marker):idx + len(marker) + 5]

    prop0 = props[0]
    lc = prop0 % 9
    rest = prop0 // 9
    lp = rest % 5
    pb = rest // 5
    dict_size = struct.unpack("<I", props[1:5])[0]

    filters = [{
        "id": lzma.FILTER_LZMA1,
        "dict_size": dict_size,
        "lc": lc,
        "lp": lp,
        "pb": pb,
    }]

    return lzma.decompress(
        packed,
        format=lzma.FORMAT_RAW,
        filters=filters,
    )


def load_sinogram(sqlite_path: Path):
    con = sqlite3.connect(sqlite_path)

    rows = con.execute(
        """
        SELECT angle_degrees,
               detector_count,
               light_values
        FROM projections
        ORDER BY angle_degrees
        """
    ).fetchall()

    con.close()

    theta = np.array(
        [row[0] for row in rows],
        dtype=np.float32,
    )

    max_detectors = max(row[1] for row in rows)

    sinogram = np.zeros(
        (max_detectors, len(rows)),
        dtype=np.float32,
    )

    for column, (_, _, raw_values) in enumerate(rows):
        values = np.array(
            json.loads(raw_values),
            dtype=np.float32,
        )

        start = (max_detectors - len(values)) // 2
        sinogram[start:start + len(values), column] = values

    return sinogram, theta


def reconstruct_image(sinogram, theta, output_path):
    reconstruction = iradon(
        sinogram,
        theta=theta,
        circle=False,
        filter_name="ramp",
        output_size=sinogram.shape[0],
    )

    low, high = np.percentile(reconstruction, [1, 99])

    image = np.clip(
        (reconstruction - low) / (high - low) * 255,
        0,
        255,
    ).astype(np.uint8)

    image = Image.fromarray(image)
    image = ImageOps.flip(image)
    image = image.crop((0, 150, 543, 380))
    image = ImageEnhance.Contrast(image).enhance(3)
    image = image.resize(
        (image.width * 3, image.height * 3),
        Image.Resampling.LANCZOS,
    )

    image.save(output_path)


def main():
    sqlite_bytes = extract_single_lzma_7z(ARCHIVE)

    SQLITE_OUT.write_bytes(sqlite_bytes)

    print(f"[+] Extracted {SQLITE_OUT}")

    sinogram, theta = load_sinogram(SQLITE_OUT)

    print(
        f"[+] Sinogram shape: "
        f"{sinogram.shape[0]} detectors × {sinogram.shape[1]} angles"
    )

    reconstruct_image(
        sinogram,
        theta,
        IMAGE_OUT,
    )

    print(f"[+] Wrote {IMAGE_OUT}")
    print(f"[+] Flag: {FLAG}")


if __name__ == "__main__":
    main()
```

---

## Usage

Install the required Python packages:

```bash
pip install numpy scipy pillow scikit-image
```

Run the solver:

```bash
python3 solve.py
```

Example output:

```text
[+] Extracted scan.sqlite
[+] Sinogram shape: 543 detectors × 180 angles
[+] Wrote reconstructed_flag.png
[+] Flag: L3AK{X-r4Y_C0MP1373!}
```

---

## Flag

```text
L3AK{X-r4Y_C0MP1373!}
```
