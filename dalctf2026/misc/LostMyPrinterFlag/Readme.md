# Lost My Flag Printer

Challenge ini kelihatannya simpel karena kita disuruh login sebagai user `ebpf` dengan password kosong, tapi setelah dibuka ternyata poin utamanya bukan di login shell, melainkan di object eBPF yang dibuat oleh binary setuid `/chal`.

## Ringkasan ide

Binary `/chal` berjalan sebagai root, lalu membuat tiga object eBPF yang di-pin ke bpffs:

- `/sys/fs/bpf/flag`
- `/sys/fs/bpf/prog`
- `/sys/fs/bpf/prog_map`

Setelah itu program menampilkan pesan:

`Dang, I left my flag printer in /sys/fs/bpf/prog_map.`

Kalimat itu sebenarnya spoiler. Flag printer-nya memang disimpan sebagai program eBPF, tapi tidak langsung dijalankan. Program root tersebut hanya:

1. Membuat map `flag`
2. Me-load sebuah program eBPF
3. Menaruh FD program itu ke `prog_map`

Akibatnya `/sys/fs/bpf/flag` tetap kosong sampai ada yang men-trigger program tersebut.

## Enumerasi

Begitu login sebagai `ebpf`, jalankan:

```sh
/chal
ls -la /sys/fs/bpf
```

Setelah `/chal` dijalankan, akan muncul object berikut:

```sh
/sys/fs/bpf/flag
/sys/fs/bpf/prog
/sys/fs/bpf/prog_map
```

Yang menarik:

- `flag` bisa diakses user
- `prog_map` juga bisa diakses user
- kernel mengizinkan unprivileged BPF

Nilai `unprivileged_bpf_disabled` di target adalah `0`, jadi user `ebpf` masih bisa me-load program BPF sendiri.

## Analisis binary

Dari reversing `chal`, alurnya seperti ini:

1. `BPF_MAP_CREATE` untuk `flag`
2. `BPF_OBJ_PIN` ke `/sys/fs/bpf/flag`
3. `BPF_PROG_LOAD` untuk sebuah program `SOCKET_FILTER`
4. `BPF_OBJ_PIN` ke `/sys/fs/bpf/prog`
5. `BPF_MAP_CREATE` lagi untuk `prog_map`
6. `BPF_OBJ_PIN` ke `/sys/fs/bpf/prog_map`
7. `BPF_MAP_UPDATE_ELEM(prog_map, key=0, value=prog_fd)`

Program BPF yang di-load root berisi literal potongan flag, lalu saat dieksekusi dia menulis flag itu ke map `flag`.

Masalahnya: root tidak pernah menjalankan program itu.

## Titik lemah

Karena `prog_map` dipin dan dapat dibuka oleh user `ebpf`, kita bisa:

1. Membuka pinned map `/sys/fs/bpf/prog_map`
2. Me-load program BPF kecil milik kita sendiri sebagai `SOCKET_FILTER`
3. Dari program kecil itu, memanggil helper `bpf_tail_call(ctx, prog_map, 0)`

Kalau key `0` berisi FD program milik root, tail call akan lompat ke sana dan program root tersebut berjalan dalam konteks eksekusi paket yang kita trigger.

Begitu program root itu jalan, flag ditulis ke map `/sys/fs/bpf/flag`.

Terakhir tinggal baca isi map tersebut dari userland.

## Bentuk exploit

Saya buat helper ELF kecil `exploit_min` yang:

1. `BPF_OBJ_GET("/sys/fs/bpf/prog_map")`
2. `BPF_OBJ_GET("/sys/fs/bpf/flag")`
3. `BPF_PROG_LOAD()` untuk program BPF minimal yang hanya:
   - copy `ctx` ke `r6`
   - set `r3 = 0`
   - load `prog_map` sebagai pseudo map fd ke `r2`
   - call `bpf_tail_call`
   - return
4. Attach program itu ke UNIX datagram socket dengan `SO_ATTACH_BPF`
5. Kirim 1 byte ke socket untuk men-trigger program
6. `BPF_MAP_LOOKUP_ELEM(flag, key=0)`

Hasil lookup itulah flag.

## Kenapa upload helper, bukan langsung dari shell?

Environment target sangat minimal. Tidak ada compiler, tidak ada bpftool, dan shell serial raw cukup rewel untuk payload panjang. Jadi cara paling stabil adalah:

1. Encode helper binary ke base64
2. Upload bertahap per chunk
3. Decode jadi `/tmp/ex`
4. Jalankan `/chal`
5. Jalankan helper

Itu yang dilakukan `solve.py`.

## Menjalankan solve

```sh
python3 solve.py --port 23076
```

Atau untuk instance lain:

```sh
python3 solve.py --host instancer.dalctf2026.com --port <PORT>
```

Script akan print flag langsung.

## Flag

```text
dalctf{1_<3_t41l_c4ll5}
