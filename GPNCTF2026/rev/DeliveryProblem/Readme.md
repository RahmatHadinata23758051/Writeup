# Konigsberg Delivery Problem

Binary yang disediakan cuma `cartographer`. Dari `file` dan `checksec` terlihat ini ELF 64-bit PIE, NX aktif, tidak stripped, dan tidak ada stack canary. Jalur paling masuk akal bukan memory corruption, tapi reverse logic binary.

## Ringkasan perilaku binary

Fungsi `main` melakukan `scanf("%hhd;")` sebanyak 250 kali. Artinya program menunggu 250 bilangan signed byte yang dipisahkan `;`.

Setelah semua angka dibaca, `main` memanggil fungsi besar bernama `cfg`. Di dalam `cfg` ada pola yang berulang:

1. Sebuah byte counter pada stack di-increment.
2. Byte input saat ini dibaca.
3. Nilainya dibandingkan dengan batas maksimum tertentu.
4. Jika nilai input masih dalam batas, nilai itu dipakai sebagai indeks ke jump table berikutnya.
5. Jika nilai input lebih besar dari batas node saat ini, eksekusi lompat ke blok akhir yang memanggil `check_instance`.

`check_instance` tidak memverifikasi urutan secara rumit. Ia hanya mengecek apakah seluruh 250 byte counter di stack sudah non-zero. Kalau semuanya pernah disentuh minimal satu kali, program membuka `/flag` dan mencetak isinya. Kalau ada satu saja yang nol, program mencetak `Not quite, try again!`.

Jadi inti challenge-nya:

- ada 250 state/node,
- setiap state menandai dirinya sebagai "visited",
- input valid memilih state berikutnya lewat jump table,
- input invalid menghentikan traversal dan memicu pengecekan,
- flag keluar kalau seluruh 250 state sudah dikunjungi setidaknya sekali.

## Bentuk graph

Setelah jump table diekstrak, fungsi `cfg` ternyata membentuk graph terarah dengan 250 node. Node awal adalah state pertama di `0x1210`. Masing-masing node punya banyak edge keluar, dan graph-nya strongly connected.

Karena tujuan `check_instance` hanya memastikan semua node pernah dikunjungi, problem ini berubah menjadi:

1. cari path yang mengunjungi semua 250 node tepat sebelum exit,
2. lalu kirim satu byte yang lebih besar dari batas node terakhir supaya eksekusi masuk ke `check_instance`.

Saya parse graph langsung dari binary:

- alamat state ke-`i` mengikuti pola blok 0x30 byte,
- setiap blok punya `cmp rdx, imm8` yang memberi tahu batas input valid untuk state itu,
- blok juga punya `lea` ke base jump table,
- setiap entry jump table berisi offset relatif ke state berikutnya.

Dengan representasi itu, saya jalankan DFS greedy sederhana. Karena graph sangat padat, path Hamiltonian ditemukan sangat cepat tanpa perlu angr atau SMT solver.

## Payload final

DFS menghasilkan 249 transisi valid yang melewati semua 250 node. Setelah itu saya tambahkan satu nilai invalid untuk node terakhir, sehingga `cfg` keluar ke `check_instance`.

Payload akhirnya adalah:

```text
15;31;54;15;52;47;44;79;8;34;76;32;23;51;67;45;67;70;43;34;83;44;12;7;49;83;12;72;41;3;53;45;72;42;14;69;71;89;94;56;81;5;59;85;66;43;23;75;10;74;45;0;30;47;30;38;5;4;72;15;11;4;84;34;35;17;34;77;53;79;54;42;70;27;6;48;0;72;87;56;72;12;8;57;29;58;68;81;39;34;74;81;43;72;35;15;24;48;35;78;25;12;16;16;100;1;87;90;16;4;66;45;96;56;74;27;17;77;74;94;74;50;45;40;75;57;94;69;75;62;37;8;24;94;86;81;49;52;57;19;45;35;98;108;24;67;43;44;93;24;84;46;94;4;20;39;54;85;31;54;77;0;61;9;70;26;103;72;110;24;55;16;15;3;88;25;95;79;64;63;83;104;79;15;48;27;35;103;37;91;104;5;40;6;75;63;33;25;96;0;15;37;56;4;22;112;16;55;40;53;51;86;17;37;41;0;54;30;30;5;12;27;9;78;41;95;58;62;30;94;40;75;18;63;78;54;54;67;42;90;12;46;108;32;67;94;78;67;34;112
```

## Catatan remote

Saat koneksi pertama saya sempat mendapat `Connection refused` dari `ncat --ssl`. Masalahnya ternyata resolusi awal mengarah ke IPv6/NAT64, sementara service IPv4-nya yang stabil. Karena itu solver final memakai `socket.create_connection()` biasa yang menuju alamat host aktif dan dibungkus TLS dengan `ssl`.

## Menjalankan solver

```bash
python3 solve.py
```

Output remote yang berhasil:

```text
Congratulations! Here is your flag: GPNCTF{saY_3UleR_7he_0wL_0W1s_1n_köN16s8er6_10_7IMes_f4ST!}
```
