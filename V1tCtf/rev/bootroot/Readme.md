# BootRoot: Root of No Return

Binary `eEyeBootRoot2005.exe` tidak di-strip, jadi quick triage langsung kelihatan:

- `bExplode()` membuka `\\.\PhysicalDrive0`
- lalu menulis 512 byte dari blob `.data` ke offset 0
- setelah itu ada efek layar dan BSOD pakai `NtRaiseHardError`

Bagian penting ada di blob 512-byte yang dipakai buat overwrite MBR. Di sana ada string Vietnam:

`Bo may de dia chi lai roi, co gioi thi tim toi va chan bo may de`

String itu memudahkan cari awal payload MBR di file. Setelah dibuka, struktur sektor ini aneh:

- boot code valid
- signature `0x55aa` valid
- area partition table (`0x1be..0x1fd`) hampir semuanya nol
- hanya 19 byte terakhir yang diisi data:

```text
83 3e 81 88 3e 3f 85 3e 3d 6c 66 72 7b 6c 79 6e 7b 74 8a
```

Kalau setiap byte dikurangi `0x0d`, hasilnya jadi:

```text
v1t{12x10_Yen_lang}
```

Itu flag-nya. Jadi flag tidak diambil dari MBR aktif di disk image, tapi dari MBR jahat yang di-embed di executable.

## Langkah singkat

1. Extract `eEyeBootRoot2005.exe` dari image.
2. Reverse `bExplode()` dan lihat 512-byte blob yang ditulis ke `PhysicalDrive0`.
3. Ambil tail non-zero di area partition table MBR palsu.
4. Decode dengan `byte - 13`.

## Solver

```bash
python3 solve.py
```

Output:

```text
v1t{12x10_Yen_lang}
```
