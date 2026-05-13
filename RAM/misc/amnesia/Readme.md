# Amnesia

Service ini ternyata bukan “LLM” beneran. Setelah connect ke `nc 10.42.5.10 1337`, kita dikasih serial console ke VM kecil dan langsung login sebagai `root`.

Artefak paling penting di guest cuma `/chal`. Setelah binary itu saya ambil dan dibalik statically, `main()`-nya sangat pendek:

1. buka `/flag`
2. baca sampai `0x40` byte ke stack
3. alokasikan heap nol
4. loop 64 kali:
   - `mmap()` satu page 4KB anonim
   - `strncpy()` isi flag ke page itu
5. `unlink("/flag")`

Jadi isi flag tidak hilang begitu saja. Ia disalin ke banyak page memori lalu file aslinya dihapus.

Awalnya saya cek jalur yang kelihatan paling obvious:

- dump region initrd dari `boot_params`
- cek `/proc/kcore`
- cek sisa memori fisik

Tapi region initrd utama memang dipenuhi `0xCC` karena dibersihkan kernel setelah boot, jadi recovery langsung dari `ramdisk_image` tidak cukup.

Yang berhasil justru dump chunk tertentu dari `/proc/kcore`. Dengan membaca header ELF `kcore`, ada satu `LOAD` segment berukuran `0x2830000`. Dump chunk 4MB pada offset relatif `0x1800000` dari segment itu memperlihatkan flag muncul berulang kali pada boundary 4KB, konsisten dengan perilaku `/chal` yang membuat banyak copy page-aligned.

Regex yang valid dari chunk itu adalah:

`RMCTF{1_kn3w_1_f0rg07_50m37h1n6}`

## Langkah solve

Jalankan:

```bash
python3 solve.py
```

Script akan:

1. connect ke service
2. tunggu shell guest
3. baca header `/proc/kcore`
4. cari `LOAD` segment target
5. dump chunk 4MB pada offset relatif `0x1800000`
6. regex flag dari chunk tersebut

## Flag

`RMCTF{1_kn3w_1_f0rg07_50m37h1n6}`
