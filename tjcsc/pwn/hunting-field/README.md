# Hunting Field Writeup

## Ringkasan

Binary ini kelihatan seperti game kecil 9x9. Kita bisa gerak (`M`) atau menyerang (`A`) ke empat arah. Flag tidak keluar dari jalur eksploitasi biasa, tapi dari fungsi `game_over()` yang punya kondisi khusus:

```c
if (*kills == 1752526452)
```

Jadi target utamanya bukan ROP atau shell, tapi membuat variabel `killCt` di stack bernilai `1752526452`, lalu memaksa game masuk ke `game_over()`.

## Recon

Hasil `checksec`:

- Arch: `amd64`
- RELRO: Partial
- Canary: tidak ada
- NX: aktif
- PIE: tidak ada

Source `game.c` juga tersedia, jadi analisisnya jauh lebih cepat karena kita bisa langsung cocokkan perilaku binary dengan kodenya.

## Titik bug

Fungsi paling penting ada di `game()`:

```c
char input_log[64];
int killCt = 0;
int *kills = &killCt;
char *array_ptr = &input_log[63];
```

Setiap kali input dimasukkan, program menyimpan dua byte input ke `input_log` dengan cara mundur:

```c
*array_ptr = player_input[0];
array_ptr -= sizeof(player_input[0]);
*array_ptr = player_input[1];
array_ptr -= sizeof(player_input[1]);
```

Masalahnya, tidak ada pengecekan batas. Selama kita terus memberi input yang tidak valid, loop input akan terus berjalan dan `array_ptr` akan terus bergerak ke alamat yang lebih rendah. Itu berarti isi tulisannya akan lewat dari `input_log` dan masuk ke variabel stack lain.

## Target overwrite

Dari disassembly, layout stack yang relevan terlihat seperti ini:

- `player_input` di sekitar `rbp-0x86`
- `killCt` di `rbp-0x84`
- `input_log` di `rbp-0x80 .. rbp-0x41`

Artinya, kalau kita isi `input_log` penuh lalu terus lanjut dua kali lagi, kita bisa menulis empat byte `killCt`.

Nilai magic di `game_over()` adalah:

```text
1752526452 = 0x68756e74
```

Karena little-endian, byte yang harus masuk ke `killCt` adalah:

```text
74 6e 75 68
 t  n  u  h
```

Urutan penulisan stack-nya terjadi dari byte tinggi ke byte rendah, jadi pasangan input yang enak dipakai adalah:

- `hu`
- `nt`

Setelah 32 kali input invalid sebagai filler, `hu` dan `nt` akan membuat `killCt = 0x68756e74`.

## Kenapa perlu satu input invalid tambahan

Ada detail kecil yang gampang bikin bingung.

Setelah `killCt` selesai ditulis, `array_ptr` sudah turun sampai menimpa area `player_input`. Saat itu, store pertama akan menulis ke `player_input[1]`, lalu store kedua akan membaca nilai yang sudah ketimpa tadi. Efeknya, satu attempt input berubah menjadi duplikasi karakter pertama.

Contoh:

- kita kirim `MN`
- hasil akhirnya bukan `MN`
- yang tersimpan jadi `MM`

Karena `MM` bukan command valid, loop input lanjut satu kali lagi. Justru itu yang kita manfaatkan. Setelah satu attempt invalid tambahan tersebut, `array_ptr` sudah lewat dari `player_input`, jadi command berikutnya kembali normal.

Jadi urutan awal yang benar adalah:

1. `zz` x32
2. `hu`
3. `nt`
4. `MN`  -> sengaja invalid setelah self-overwrite
5. `MN`  -> command valid pertama

## Memicu `game_over()`

Setelah `killCt` berisi nilai magic, kita tidak perlu membunuh ribuan enemy atau bikin ROP chain. Cukup bikin karakter mati.

Dari simulasi logika game, rangkaian command valid berikut cukup untuk memunculkan enemy dan membiarkan mereka mencapai player:

- `MN`
- `AS`
- `MN`
- `MN`

Begitu `game_over()` terpanggil, program mencetak:

```c
printf("You defeated %i enemies!\n", *kills);
```

Karena `*kills` sudah kita ubah ke `1752526452`, kondisi flag terpenuhi dan flag keluar.

## Sequence final

Urutan lengkap payload input:

```text
zz x32
hu
nt
MN
MN
AS
MN
MN
```

## Exploit

File exploit ada di `exploit.py`.

Jalankan remote:

```bash
source /home/nata/ctf_env/bin/activate
python3 exploit.py
```

Kalau mau test lokal:

```bash
source /home/nata/ctf_env/bin/activate
python3 exploit.py LOCAL=1
```

## Flag

```text
tjctf{pr0fes5iona1_hunt3r}
```
