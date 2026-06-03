# M4terM4xima's HINT (part 1/2)

Binary `HINT.elf` adalah ELF RISC-V 32-bit statically linked dan tidak di-strip. Dari `strings` sudah kelihatan ada beberapa pesan umpan seperti `You just called a HINT`, `Are you sure that you are looking for HINT?`, dan `Congratulation, you just found a HINT`. Karena ini bare-metal RISC-V, menjalankan binary langsung dengan `qemu-riscv32` tidak memberi hasil berguna. Dari `INSTRUCTIONS.md` juga ada petunjuk bahwa binary idealnya dijalankan dengan `spike`, jadi fokus paling masuk akal adalah reversing statis.

Langkah paling membantu adalah melihat simbol karena binary tidak di-strip. Ada tiga fungsi yang langsung mencolok: `HINT`, `main`, dan `maybe_HINT`. Fungsi `main` cuma loop memanggil `maybe_HINT`. Di dalam `maybe_HINT`, program lebih dulu mencetak string `Are you sure that you are looking for HINT?`, lalu membaca 128 byte melalui mekanisme HTIF/HINT. Setelah itu buffer divalidasi sebagai UTF-8. Kalau validasi gagal, eksekusi lompat ke jalur panic. Kalau lolos, buffer diproses dengan transform sederhana: nilai awal `0x55`, lalu setiap byte di-XOR dengan byte sebelumnya, dan hasilnya ditulis balik in-place.

Sesudah transform itu, program memeriksa panjang hasil. Hanya input sepanjang 20 byte yang bisa lanjut ke pembandingan final. Konstanta pembanding ada di `.rodata` pada alamat `0x80000ddc`, yaitu:

```text
01 1c 0b 38 17 19 1c 49 5a 1f 17 1d 43 0c 4f 17 49 03 01 4e
```

Karena transformnya berbentuk rantai XOR:

```text
out[0] = in[0] ^ 0x55
out[i] = in[i] ^ in[i - 1]
```

maka pembalikannya langsung:

```text
in[0] = out[0] ^ 0x55
in[i] = out[i] ^ in[i - 1]
```

Saya pakai logika itu untuk merekonstruksi 20 byte input asli dari konstanta terenkripsi. Hasilnya adalah:

```text
THC{lui zero, ox123}
```

Jadi flag part 1 adalah:

```text
THC{lui zero, ox123}
```

Solver final disimpan di `solve.py`. Script itu hanya membalik XOR-chain dari konstanta yang diambil saat reversing, lalu mencetak flag.
