# L3ak APT

Flag: `L3AK{For3nsics_hUm4n$_C4n_c00K_AI}`

## Sumber flag

Flag bukan berasal dari title browser `L3ak{Current_Members}`. Nilai itu hanya decoy di Chrome/Edge history.

Sumber sebenarnya adalah thumbnail cache Windows:

```text
Users/Max/AppData/Local/Microsoft/Windows/Explorer/thumbcache_1280.db
```

File challenge asli berada di dalam direktori `important files` yang tercatat pada `$MFT`, tetapi file aslinya tidak ikut diekspor. Windows tetap menyimpan thumbnail-nya. Format thumbnail cache memakai signature `FF D8 FF` untuk JPEG dan `FF D9` sebagai akhir JPEG.

Carving JPEG dari `thumbcache_1280.db` menghasilkan enam gambar. Gambar kedua berukuran `852x1280` menampilkan poster **RIZZLER**. Pada bagian bawah poster terdapat teks:

```text
L3AK{For3nsics_hUm4n$_C4n_c00K_AI}
```

Hash SHA-256 thumbnail yang memuat flag:

```text
daa218b9d1713248f7069667ace2e21bcc46b42980e8b87c955ab1ec341701a2
```

## Reproduksi

```bash
python3 solve.py
```

Script membaca cache dalam mode read-only, melakukan carving JPEG, memvalidasi thumbnail target dengan SHA-256, lalu mencetak flag yang terlihat pada thumbnail tersebut.

## Triage pendukung

- `$MFT` menunjukkan `important files.7z` dan folder `important files/Projects/media`.
- Isi folder media mencatat `ARS-CB-047.png`, `ARS-NC-001.png`, dan `ARS-SEC-154.png`.
- Recent LNK dan Windows Search index menguatkan bahwa file media tersebut pernah dibuka.
- Browser history berisi `L3ak{Current_Members}`, tetapi tidak dipakai sebagai flag final.
