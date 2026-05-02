# Writeup

Awal lihat challenge ini kesannya cuma flag checker biasa. Tapi pas dicek, ternyata enggak sesimpel itu.

Binary yang dikasih itu `checker.exe`, formatnya PE 64-bit buat Windows. Dari string-string yang kelihatan, langsung kebaca kalau format flag-nya `CBC{...}`. Terus dari pengecekan di fungsi `main`, ketahuan juga kalau total panjang flag harus 21 karakter. Artinya isi di dalam `{}` ada 16 karakter.

Jadi titik awalnya udah jelas:

- prefix harus `CBC{`
- suffix harus `}`
- isi tengah 16 byte

Nah, habis itu saya kira tinggal bongkar beberapa operasi XOR atau compare biasa. Ternyata enggak. Binary ini bawa-bawa CUDA.

## Langkah awal

Pertama saya cek isi folder sama tipe filenya:

```bash
file checker.exe
objdump -h checker.exe
strings checker.exe
```

Dari situ kelihatan ada section `.nv_fatb` dan seabrek import `cuda*`. Itu udah jadi red flag kalau validasi utamanya kemungkinan jalan di GPU, bukan di kode CPU biasa.

Di `main`, alurnya kurang lebih begini:

1. cek jumlah argumen
2. cek panjang input
3. cek `CBC{` di depan dan `}` di belakang
4. ambil isi tengah 16 byte
5. kirim ke fungsi yang pakai CUDA
6. kalau hasil akhirnya cocok, print `:)`

Jadi bagian CPU cuma jadi satpam depan doang. Inti validasinya ada di kernel CUDA.

## Kernel CUDA-nya di mana?

Section `.nv_fatb` ternyata nyimpen blob ELF buat device code NVIDIA. Saya scan magic `ELF` di binary dan ketemu dua blob. Yang pertama cuma metadata, yang kedua baru cubin yang beneran ada isi kernel-nya.

Supaya enak dibaca, saya ekstrak tool CUDA lokal dari paket Debian, terus pakai:

```bash
nvdisasm
cuobjdump
```

Setelah itu baru kelihatan nama kernel-nya:

```cpp
_Z9check_keyPKhPj
```

Kalau didemangle itu kurang lebih `check_key`.

## Isi kernel

Pas kernel-nya dibedah, polanya lumayan jelas walau awalnya keliatan ribet banget.

Kernel ini:

- baca 16 byte input
- pecah jadi 4 blok, masing-masing 4 byte
- rakit tiap blok jadi word 32-bit
- proses word itu satu per satu

Selain input, ada juga data penting di constant section:

- `tr` = target akhir
- `kbf` = deretan konstanta 32-bit
- `rtbl` = deretan angka rotasi

Pola prosesnya kira-kira begini:

1. blok pertama di-xor dulu dengan konstanta awal
2. terus berkali-kali di-rotate kiri/kanan
3. tiap ronde di-xor sama konstanta dari `kbf`
4. lalu di-xor lagi sama konstanta tetap
5. hasil blok sebelumnya dipakai buat ngacak blok berikutnya

Jadi ini modelnya chaining. Bukan 4 blok yang berdiri sendiri.

## Bagian yang paling ngeselin

Yang paling bikin waktu habis justru bukan ide besarnya, tapi detail kecilnya.

Ada dua hal yang sempat bikin model awal saya salah:

1. semantik instruksi `SHF`
2. ada dua konstanta yang mirip banget:

```text
0xb00b800b
0x8008b00b
```

Awalnya saya kira tinggal translate SASS ke rotate biasa dan langsung selesai. Ternyata kalau salah naruh operand `SHF`, hasil solver langsung `unsat`.

Buat mastikan itu, saya bikin PTX mini sendiri yang isinya cuma instruksi `shf`, compile pakai `ptxas`, terus saya lihat SASS hasilnya. Dari situ baru kebaca operand mana yang jadi nilai, mana yang jadi shift amount, dan mana yang sebenernya cuma hasil lowering dari rotate.

Setelah mapping ini bener, modelnya langsung masuk akal.

## Ngebalikinnya pakai Z3

Daripada brute force 16 karakter, jauh lebih waras modelkan transform-nya terus minta solver nyari input yang bikin hasil akhirnya sama dengan target.

Saya tulis ulang logika kernel ke `solve.py`:

- 16 byte jadi 4 word 32-bit
- word pertama diolah beberapa ronde
- hasilnya dipakai buat xor word kedua
- terus lanjut chaining sampai word keempat
- hasil akhir harus sama dengan nilai di `tr`

Begitu constraint-nya pas, Z3 keluarin isi flag tengah:

```text
Cc_uV_dAa___GPU!
```

Jadi flag lengkapnya:

```text
CBC{Cc_uV_dAa___GPU!}
```

## Verifikasi

Solver final saya jalanin ulang dan hasilnya konsisten:

```bash
python solve.py
```

Output:

```text
CBC{Cc_uV_dAa___GPU!}
```

## Flag

```text
CBC{Cc_uV_dAa___GPU!}
```
