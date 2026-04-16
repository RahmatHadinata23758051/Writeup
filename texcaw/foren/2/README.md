# Journaling

## Summary

Target artefak utamanya adalah image NTFS `evidence.001`. Flag ternyata disebar ke beberapa lokasi kecil:

- nama folder di `Notes`
- nama file yang dihapus
- alternate data stream `tasks.txt:source`
- string UTF-16LE yang masih tertinggal di `$MFT` / jejak USN

Flag final:

```text
texsaw{u5njOurn@l_unc0v3rs_4lter3d_f1les_3fd19982505363d0}
```

## Langkah Analisis

### 1. Recon awal

Identifikasi file:

```bash
file evidence.001
mmls evidence.001
fsstat -o 128 evidence.001
```

Hasil penting:

- `evidence.001` adalah disk image NTFS
- partisi NTFS mulai di sektor `128`

### 2. Enumerasi filesystem

Cari direktori user dan file menarik:

```bash
fls -o 128 evidence.001
fls -o 128 -r evidence.001 | rg -i 'Notes|txt|flagsegment|journal|note'
```

Artefak kunci:

- `Users/user/Notes`
- folder `flagsegment_u5njOurn@l`
- `notetoself.txt`
- `monitor.log`
- file terhapus `flagsegment_f1les.txt`
- `tasks.txt`
- ADS `tasks.txt:source`

### 3. Ekstraksi artefak kecil

```bash
icat -o 128 evidence.001 942-128-1
icat -o 128 evidence.001 944-128-1
icat -o 128 evidence.001 945-128-1
icat -o 128 evidence.001 945-128-3
```

Temuan:

- nama folder memberi segmen `u5njOurn@l`
- nama file terhapus memberi segmen `f1les`
- ADS `tasks.txt:source` berisi:

```text
flagsegment_3fd19982505363d0
```

- `tasks.txt` memberi petunjuk:

```text
... find out where part 5 is...
```

Ini mengindikasikan segmen hash dari ADS adalah part terakhir.

### 4. Cari segmen yang tertinggal di metadata

Segmen lain tidak muncul sebagai file aktif, jadi pivot ke string UTF-16LE dari image / MFT:

```bash
icat -o 128 evidence.001 0-128-6 > mft.bin
strings -el mft.bin | rg 'flagsegment|4lter3d|unc0v3rs'
```

Muncul:

- `flagsegment_4lter3d`

Lalu pencarian UTF-16LE langsung di image:

```bash
rg -a -n 'flagsegment_' evidence.001
```

dan dump konteks byte mengungkap:

- `flagsegment_unc0v3rs.txt`

Jadi semua segmen yang ditemukan adalah:

1. `u5njOurn@l`
2. `unc0v3rs`
3. `4lter3d`
4. `f1les`
5. `3fd19982505363d0`

### 5. Menyusun urutan

Urutan tidak ditebak. Dasarnya:

- `tasks.txt` eksplisit menyebut mencari `part 5`, dan ADS `tasks.txt:source` berisi hash `3fd19982505363d0`, jadi itu part 5
- segmen lain membentuk frasa yang masuk akal:

```text
journal uncovers altered files
```

dengan gaya obfuscation challenge:

```text
u5njOurn@l_unc0v3rs_4lter3d_f1les
```

Sehingga flag lengkapnya:

```text
texsaw{u5njOurn@l_unc0v3rs_4lter3d_f1les_3fd19982505363d0}
```

## Solver

`solve.py` membaca `evidence.001`, mengambil string UTF-16LE yang relevan, lalu merangkai flag:

```bash
python3 solve.py
```

Output:

```text
texsaw{u5njOurn@l_unc0v3rs_4lter3d_f1les_3fd19982505363d0}
```
