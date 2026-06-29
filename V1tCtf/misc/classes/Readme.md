# Classless

Binary `objectvm` bukan parser `.bbl` biasa. Ada data internal yang di-obfuscate dan bisa dibaca langsung dari binary.

## Ringkas

- Sample `.bbl` ternyata base64 + zlib berisi JSON.
- JSON itu cuma bantu paham model VM: `classes`, `objects`, `entry`, tiga dialect `JAVA` / `PY` / `CPP`.
- `strings`, `readelf`, dan `ltrace` nunjukin ada tiga jalur guard: `verifier`, `resolver`, `dispatcher`.
- Di `.rodata` ada blob aneh dekat string guard. Blob itu bukan random.
- XOR blob dengan `0x37` langsung keluar flag.

## Enumerasi

Lihat file:

```bash
find . -maxdepth 2 -mindepth 1 -printf '%y %p\n' | sort
file ./objectvm
```

Hasil penting:

- `objectvm` ELF 64-bit stripped.
- `samples/*.bbl` ada lima file contoh.

Decode sample:

```bash
python3 - <<'PY'
import base64, zlib, pathlib
for path in sorted(pathlib.Path('samples').glob('*.bbl')):
    raw = zlib.decompress(base64.b64decode(path.read_bytes()))
    print(path.name)
    print(raw.decode())
PY
```

Dari sini kelihatan struktur VM:

- `classes`
- `objects`
- `declared_class`
- `runtime_class`
- `vtable`
- field spesial macam `__task__`, `__class__`, `probe_interface`

Run sample juga kasih clue jalur internal:

```bash
./objectvm samples/02_mro.bbl
./objectvm samples/03_dispatch.bbl
./objectvm samples/04_denied.bbl
```

Output:

- `resolved class: Cat`
- `dispatch slot 7: allow`
- `Vault denied: verifier`

## Cari data tersembunyi

Dump `.rodata`:

```bash
readelf -p .rodata ./objectvm
```

Dekat string:

- `Vault denied: verifier`
- `Vault denied: resolver`
- `Vault denied: dispatcher`

ada blob begini:

```text
A^FCLCE^[^YPBV[hACVU[RhUVUR[h...
```

Itu kelihatan seperti data yang di-XOR. Coba brute sederhana di Python. Kunci `0x37` langsung pas.

```bash
python3 - <<'PY'
from pathlib import Path
b = Path('objectvm').read_bytes()
start = 0x134a0
chunk = b[start:start+96]
print(bytes(x ^ 0x37 for x in chunk))
PY
```

Awal hasil decode:

```text
b'v1t{trilingual_vtable_babel_6f01a2c9}...'
```

Flag sudah jelas muncul lengkap.

## Solver

`solve.py` tidak hardcode offset. Script scan seluruh binary, XOR semua byte dengan `0x37`, lalu cari pola `v1t{...}`.

Jalankan:

```bash
python3 solve.py
```

Output:

```text
v1t{trilingual_vtable_babel_6f01a2c9}
```

## Flag

```text
v1t{trilingual_vtable_babel_6f01a2c9}
```
