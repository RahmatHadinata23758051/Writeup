# Mirror Mirror

## Ringkasan

Program tidak memakai algoritma kriptografi berat. Flag disimpan sebagai byte array terenkripsi dan dibuka memakai dua komponen:

1. SHA-256 dari 300 karakter source code mulai marker `MIRROR_SURFACE_DO_NOT_SCRATCH`.
2. String statis `MirrorMirror`.

Setelah kedua komponen direkonstruksi, setiap byte pada `blob` cukup di-XOR kembali.

## Source penting

```python
pivot = src.index("MIRROR_SURFACE_DO_NOT_SCRATCH")
specular_map = hashlib.sha256(src[pivot:pivot+300].encode()).digest()
```

dan:

```python
looking_glass = "MirrorMirror"

for i, b in enumerate(blob):
    reflection_byte = (
        specular_map[i % len(specular_map)]
        ^ ord(looking_glass[i % len(looking_glass)])
    )
    flag += chr(b ^ reflection_byte)
```

Proses verifikasi menghasilkan:

```text
flag_byte = blob_byte ^ specular_map_byte ^ looking_glass_byte
```

Karena XOR bersifat reversibel, solver hanya perlu menjalankan rumus yang sama.

## Anti-debug

Ada dua pemeriksaan tambahan:

```python
if sys.gettrace() is not None:
    return "Nice try, but the glass turns opaque. No observers allowed!"
```

dan:

```python
if sys._getframe().f_code.co_name != 'verify' or __name__ != "__main__":
    return "You are looking at the mirror from a distorted angle."
```

Keduanya tidak perlu dibypass. Solver membaca source file secara langsung lalu menghitung flag di luar fungsi `verify()`.

## Solver

Simpan `solve.py` di folder yang sama dengan `mirror.py`, lalu jalankan:

```bash
python3 solve.py
```

Solver:

```python
#!/usr/bin/env python3
import hashlib
from pathlib import Path

MARKER = "MIRROR_SURFACE_DO_NOT_SCRATCH"
LOOKING_GLASS = "MirrorMirror"
BLOB = [
    17, 241, 10, 247, 215, 233, 146, 221, 156, 40,
    37, 198, 153, 173, 10, 103, 20, 56, 232, 116,
    208, 121, 53, 12, 122, 86, 127, 164, 109, 62,
    88, 200, 127, 234, 5,
]

source = Path("mirror.py").read_text()
pivot = source.index(MARKER)
specular_map = hashlib.sha256(
    source[pivot:pivot + 300].encode()
).digest()

flag = ""
for i, encrypted_byte in enumerate(BLOB):
    reflection_byte = (
        specular_map[i % len(specular_map)]
        ^ ord(LOOKING_GLASS[i % len(LOOKING_GLASS)])
    )
    flag += chr(encrypted_byte ^ reflection_byte)

print(flag)
```

## Output

```text
<FLAG>bronco{wh0_1s_th3_f@ir3st_r3v3rs3r}</FLAG>
```

## Flag

```text
bronco{wh0_1s_th3_f@ir3st_r3v3rs3r}
```
