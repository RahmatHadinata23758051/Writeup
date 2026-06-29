# Ducks Ping-Pong Revenge — Reverse Engineering Writeup

## Informasi challenge

- CTF: V1T CTF 2026
- Kategori: Reverse
- File: `DucksPingPongV2.exe`, `DucksKDv2.sys`
- Deskripsi: `you thought kernel reversing was the hard part? this is the retaliation, now reverse what it became!!!`
- Flag: `v1t{th3_duck_n3v3r_h4nds_y0u_th3_k3y}`

## Triage

```bash
unzip -l pingpongrevenge.zip
unzip pingpongrevenge.zip
file DucksPingPongV2.exe DucksKDv2.sys
strings -a DucksPingPongV2.exe | less
strings -a DucksKDv2.sys | less
```

Arsip berisi executable Windows x64 dan driver kernel x64. Executable membuka device:

```text
\\.\DucksKD
```

Versi revenge masih memakai pola ping-pong antara user-mode dan kernel, tetapi protokolnya diperluas menjadi lima stage, custom VM, custom KDF, dan transformasi ARX final.

## Protokol IOCTL

Xref `DeviceIoControl` di executable dan dispatcher `IRP_MJ_DEVICE_CONTROL` di driver menghasilkan empat IOCTL:

| IOCTL | Fungsi |
|---|---|
| `0x222480` | Membuka sesi dan mengikat state ke proses pemanggil |
| `0x222484` | Mengirim token untuk satu stage |
| `0x222488` | Membaca status atau stage aktif |
| `0x22248c` | Mengambil respons final setelah lima stage selesai |

Paket memakai magic berikut:

```text
0x44555632
```

Respons sukses final membawa tag `0x51554143` dan sembilan byte:

```text
11 a9 56 14 73 8b 7f 65 b3
```

## Blob VM

Executable menyimpan blob VM sepanjang `0x4c8` byte. Blob tidak berada dalam bentuk langsung; tiga stream disimpan terpisah lalu disisipkan kembali ke indeks `0 mod 3`, `1 mod 3`, dan `2 mod 3` menggunakan state LCG berbeda.

Setelah opcode VM dipetakan dan interpreter ditulis ulang, VM menghasilkan 50 byte:

```text
d76f83d50038ea79e041ab35eff9982c8954a707e0b9e4841c4a42de8a3b895341135794c94a3f87f0cb66c6d0731b7edbde
```

Sebagian output VM dipakai sebagai token stage, sebagian lagi menjadi material KDF dan ciphertext final.

## Lima template stage

Executable dan driver sama-sama mendekode lima template berukuran 64 byte. Layout yang relevan:

```text
+0x00  16 byte salt stage
+0x10  16 byte material lain
+0x20  16 byte material sukses
+0x30  16 byte target commit
```

Validasi token di driver dapat ditulis sebagai:

```text
KDF(
    domain = 0x50 + stage,
    parts  = [token, template[0:16], "stage-commit"]
) == template[48:64]
```

Panjang token dibatasi 8 sampai 16 byte. Beberapa preimage dapat dicari dengan solver bit-vector, tetapi menyelesaikan kelima token bukan syarat untuk memperoleh flag.

## Kenapa preimage stage bisa dilewati

Driver membentuk respons stage dengan mem-mask material sukses. Client kemudian membatalkan mask tersebut sebelum menyimpan state lokal. Jika operasi driver dan client disederhanakan, nilai akhirnya selalu:

```text
client_stage_state[stage] = template[32:48]
```

Artinya, buffer state yang seharusnya muncul setelah lima transaksi sukses sudah tersedia secara statis di executable. Kita cukup mengambil blok `0x20..0x2f` dari setiap template.

Lima blok tersebut adalah:

```text
stage 0: 3a2881e038b14b4242f2ec4e6932b333
stage 1: dedb0fcc598d080666e34b8a9d21e969
stage 2: 14533547e87c3091f19b92878663b4fb
stage 3: 1b4b485175e2a43d3337052459b8926a
stage 4: 54f0984b907adb24745aa3b1960d7738
```

Ini menghilangkan kebutuhan menjalankan driver, memicu bugcheck path, atau menyelesaikan semua preimage KDF.

## Material terenkripsi di executable

RVA `0x1a9f8` berisi 51 byte yang didekode dengan LCG:

```python
state = 0x654dff2b
for i, byte in enumerate(source):
    state = (state * 0x19660d + 0x3c6ef35f + i) & 0xffffffff
    decoded[i] = byte ^ (state >> 16) ^ (i * 0x25 + 0x5d)
```

Hasil dekodenya:

```text
f3a4ff56a3636016c9fce8380b2c3c94f39e18755a8e8a4b11f0467702d72c0323cc2da42a776b9478a90377c1cbc167bbaa70
```

Ciphertext 37 byte dibangun dari empat bagian:

```text
decoded[0:9]
|| final_response_9_bytes
|| vm_output[25:34]
|| (stage_2_material[0:10] XOR decoded[9:19])
```

Hasilnya:

```text
f3a4ff56a3636016c911a95614738b7f65b34a42de8a3b89534113e8bb0d4cc440a4626f83
```

## Custom KDF

KDF bekerja pada empat word 32-bit. Setiap part diawali panjang little-endian, lalu byte diserap ke word berdasarkan `counter & 3`. Setiap empat byte, state masuk ke fungsi `mix()` berbasis rotate, add, dan XOR.

Dua key 16 byte dihitung dengan urutan part yang berlawanan:

```text
left  = KDF(0x91, ["pond-left",  S0, S1, S2, S3, S4, vm_tail, extra])
right = KDF(0x92, ["pond-right", extra, vm_tail, S4, S3, S2, S1, S0])
```

Nilai akhirnya:

```text
left : 2384abd80df2c6fd2f35378b68c54cfb
right: 0fc8109effd54b082cf32c4f08ef7985
```

Keduanya digabung menjadi key 32 byte untuk fungsi transformasi di RVA `0x3010`.

## Transformasi final

Fungsi final memecah key menjadi delapan word 32-bit, membentuk empat register state, lalu menjalankan empat round ARX per byte ciphertext. Keystream byte diambil dari beberapa byte register dan di-XOR dengan:

- byte ciphertext saat ini;
- indeks byte;
- byte rendah state;
- byte ciphertext sebelumnya;
- seed awal `0xa7` untuk byte pertama.

Tidak ada algoritma standar seperti AES atau ChaCha. Menyalin operasi assembly secara langsung lebih aman daripada mencoba mengenali cipher.

Hasil transformasi:

```text
v1t{th3_duck_n3v3r_h4nds_y0u_th3_k3y}
```

## Solver

`solve.py` tidak memerlukan driver Windows atau library Python tambahan. Script membaca executable langsung dari ZIP, memetakan RVA PE secara manual, mendekode material, membangun dua key, lalu menjalankan transformasi final.

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py pingpongrevenge.zip
```

Output:

```text
v1t{th3_duck_n3v3r_h4nds_y0u_th3_k3y}
```

## Flag

```text
v1t{th3_duck_n3v3r_h4nds_y0u_th3_k3y}
```
