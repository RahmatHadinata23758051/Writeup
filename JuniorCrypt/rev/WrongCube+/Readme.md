# WrongCube+

**Category:** Reverse  
**Flag format:** `grodno{}`

## Ringkas

File `WrongCube+.exe` adalah aplikasi Windows PyInstaller berbasis PyQt. Logic challenge ada di DLL native `build\wrongkube_validator.dll`, bukan di UI Python-nya. DLL itu punya export `validate_cluster` yang mengeluarkan JSON dengan field `flag`.

## Analisis

String awal sudah cukup memberi arah:

```bash
strings -a -n 5 WrongCube+.exe | rg -i 'pyi|validator|wkubeproj|flag'
```

Output penting:

```text
pyi-python-flag
src.validator_bridge
assets\demo.wkubeproj
build\wrongkube_validator.dll
```

Archive PyInstaller dibaca dengan `pyi-archive_viewer`/`CArchiveReader`. Modul `src.validator_bridge` menunjukkan Python hanya melakukan normalisasi project lalu memanggil:

```python
validate_cluster(encoded_project)
```

DLL mengembalikan JSON seperti ini:

```text
{"ok":%s,"score":%d,"signature":%d,"summary":"%s","flag":"%s",...}
```

Di tail fungsi `validate_cluster`, jalur sukses penuh melakukan decrypt buffer 47 byte dari `.rdata` alamat VA `0x18002bf00`. Loop-nya memakai state LCG sederhana dan XOR. Byte terenkripsinya:

```text
07 9f 08 64 d3 e9 f9 60 d8 6c 37 a9 d4 18 5d 53
d6 42 fe 3a 6c ac 57 f8 1d 4a 04 55 ca 6f ea 13
a8 c2 00 88 02 d7 20 31 7b 5b 74 91 31 3e 00
```

Reimplementasi loop decrypt langsung menghasilkan flag, tanpa perlu menyusun graph Kubernetes yang valid untuk melewati semua constraint validator.

## Solver

`solve.py` mulai dari `WrongCube+.exe`, ekstrak `build\wrongkube_validator.dll` dari PyInstaller archive, mapping VA ke file offset PE, lalu decrypt flag.

```bash
python3 solve.py
```

Output:

```text
grodno{5h4d0w_c0ntr0l_pl4n3_qu0rum_r3c0nc1l3d}
```

## Flag

```text
grodno{5h4d0w_c0ntr0l_pl4n3_qu0rum_r3c0nc1l3d}
```
