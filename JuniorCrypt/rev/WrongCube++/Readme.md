# WrongCube++

Kategori: Reverse

`WrongKube++.exe` adalah executable PyInstaller untuk aplikasi PyQt. Archive internalnya berisi modul Python dan `build\\wrongkube_validator.dll`, sebuah DLL native yang melakukan validasi topology Kubernetes.

## Analisis

String PyInstaller seperti `PYZ.pyz`, `src.validator_bridge`, dan `wrongkube_validator.dll` menunjukkan bahwa logika penting tidak berada di UI. `src.validator_bridge` memuat DLL lalu memanggil ekspor `validate_cluster`.

Fungsi tersebut mengurai JSON graph, menghitung sejumlah checksum/constraint, dan hanya mengambil jalur sukses jika semua nilai cocok. Di jalur itu ada loop 45 byte yang mendekripsi data pada RVA `0x2b310`. Loop memakai state 32-bit, dua perkalian konstanta, penambahan state, dan XOR byte. Tidak perlu menyusun topology valid untuk mendapatkan plaintext karena ciphertext dan seluruh state awal tertanam di validator.

`solve.py` mengekstrak DLL langsung dari CArchive PyInstaller, menerjemahkan RVA ke file offset PE, lalu menjalankan ulang loop dekripsi dengan overflow 32-bit.

## Solve

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Output:

```text
grodno{wr0ngkub3pp_5p3ctr4l_qu0rum_0v3rdr1v3}
```

## Flag

```text
grodno{wr0ngkub3pp_5p3ctr4l_qu0rum_0v3rdr1v3}
```
