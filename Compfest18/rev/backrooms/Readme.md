# Backrooms Writeup

## Ringkasan

Binary `rev_backrooms.exe` adalah game Windows x86-64 berbasis Rust/Bevy. Flag tidak muncul sebagai string plaintext. Data flag disimpan sebagai 60 byte terenkripsi di `.rdata`, lalu saat runtime didecode menjadi bitmap kecil 4x120 pixel. Bitmap itu membentuk tulisan flag dengan font pixel 4 kolom per karakter.

## File Challenge

```
rev_backrooms.exe
assets/backrooms/Backroosm.gltf
assets/backrooms/Backroosm.bin
assets/backrooms/audio.mp3
assets/backrooms/BackRoomsCarpet.png
assets/backrooms/the_backrooms_wallpaper__seamless__by_dalay_lamma_df1ci3n-fullview.jpg
```

## Analisis Awal

Pengecekan awal:

```
file * assets/backrooms/*
strings -a rev_backrooms.exe | head
```

Hasil penting:

```
rev_backrooms.exe: PE32+ executable for MS Windows 6.00 (console), x86-64
```

String yang kelihatan mengarah ke Rust/Bevy:

```
src\main.rs
rev_backrooms::Player
rev_backrooms::LookAngles
backrooms/Backroosm.gltf
backrooms/audio.mp3
```

Pencarian langsung `COMPFEST` tidak menemukan flag plaintext.

## Analisis Static

Bagian menarik ada di fungsi startup sekitar `0x140003d30`. Di sana binary load asset `Backroosm.gltf` dan `audio.mp3`, lalu spawn objek-objek scene.

Dari xref `.rdata`, ada blok instruksi mencurigakan di sekitar `0x140005276`:

```asm
mov    edx,0xa3f1924d
mov    r8d,0x1
mov    r9b,0xdb
lea    r10,[rip+0x2f3a6ed] ; 0x142f3f978
...
imul   edx,edx,0x41c64e6d
add    edx,0x3039
...
add    r11b,r9b
ror-like operation dengan i % 7
xor    r11b,dil        ; dil = (seed >> 16) & 0xff
```

Blok data terenkripsi berada di VA:

```
0x142f3f978
```

Isinya 60 byte:

```
4a bf e0 17 ba 9a 05 1b 4a ca ab dc 34 ff a4 30
e0 83 8b d4 72 75 0b 0f 60 ba bb 7b 13 d1 3e 00
e8 2b e1 99 a9 cb a3 aa 95 b5 df 39 d4 e3 1b 74
ad 40 9b f6 6e 1e ff e1 64 5a 85 6f
```

## Analisis Dynamic

Binary tidak dijalankan di environment ini karena targetnya Windows GUI/game. Analisis static sudah cukup karena algoritma decode dan data hardcoded kelihatan jelas dari disassembly.

## Algoritma Validasi atau Encoding

Loop decode melakukan ini untuk tiap byte:

1. Seed LCG diawali `0xa3f1924d`.
2. Tiap iterasi seed diupdate:

```
seed = seed * 0x41c64e6d + 0x3039
```

3. Byte terenkripsi ditambah key awal `0xdb`, key ini bertambah `0xf3` tiap iterasi.
4. Hasilnya di-rotate right sebanyak `(i % 7) + 1`.
5. Hasil rotate di-XOR dengan `(seed >> 16) & 0xff`.
6. Byte hasil decode ditulis sebagai bit MSB ke LSB.

60 byte hasil decode menghasilkan `60 * 8 = 480` bit. Program memakai 480 bit itu sebagai bitmap `4 x 120`. Setiap karakter lebarnya 4 kolom, jadi totalnya 30 karakter.

Bitmap yang terbaca:

```
 ██ ███ ██  ███ ███ ███  ██ ███ ██   ██   █ █ █ ███     ███  ██     ██   █      █ █ ███ ███ ███  ██     ███ █   ██  █
█   █ █ ███ █ █ █   ██  ██   █   █  ███ ██  ███ ██       █  ██       ██ █ █     █ █ ██  █ █ █ █ ██      █ █ █   █ █  ██
█   █ █ █ █ ███ ██  █     █  █   █  █ █  █  █ █ █        █    █     █   █ █      █  █   ███ ██    █     █ █ █   █ █  █
 ██ ███ █ █ █   █   ███ ██   █  ███ ███   █ █ █ ███ ███ ███ ██  ███ ███  █  ███  █  ███ █ █ █ █ ██  ███ ███ ███ ██  █
```

Dibaca dengan font 4-kolom menghasilkan:

```
COMPFEST18{HE_IS_20_YEARS_OLD}
```

## Penyusunan Solve Script

`solve.py` membaca `rev_backrooms.exe`, translate VA `0x142f3f978` ke file offset PE, mengambil 60 byte terenkripsi, menjalankan algoritma decode, lalu menerjemahkan bitmap 4x120 menjadi teks flag.

## Cara Menjalankan

```
python3 solve.py
```

Output:

```
COMPFEST18{HE_IS_20_YEARS_OLD}
```

## Flag

```
COMPFEST18{HE_IS_20_YEARS_OLD}
```
