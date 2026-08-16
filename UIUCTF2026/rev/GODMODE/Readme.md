# Writeup — GODMODE//999

## Challenge

Pada challenge ini kita diberikan dua file utama:

```bash
godmode.rom
ranked.img
```

Binary dijalankan menggunakan QEMU AArch64:

```bash
qemu-system-aarch64 \
  -M virt \
  -cpu cortex-a72 \
  -m 128M \
  -global virtio-mmio.force-legacy=false \
  -bios godmode.rom \
  -drive file=ranked.img,format=raw,if=none,id=ranked \
  -device virtio-blk-device,drive=ranked \
  -nographic
```

Deskripsi challenge memberi petunjuk penting:

```text
The server remembers every rollback.
Only committed ticks affect MMR.
```

Artinya, tidak semua perubahan di disk image valid. Kita harus memulihkan state yang benar-benar sudah committed, bukan state terbaru setelah rollback/jebakan.

---

## Initial Recon

Pertama, file `ranked.img` dianalisis sebagai raw disk image.

Dari hasil parsing, ditemukan filesystem custom dengan magic:

```text
RNK9
```

Di dalam filesystem ini terdapat journal record dengan magic:

```text
JRNL
```

Setiap journal record memiliki checksum sendiri. Jadi sebelum memakai record, checksum harus diverifikasi terlebih dahulu.

Struktur umumnya:

```text
RNK9 header
journal start
journal count
journal records
encrypted file blocks
```

Setiap file di filesystem memiliki metadata seperti:

```text
path
block offset
file size
file id
active flag
```

---

## RankedFS Journal

Journal record memiliki beberapa tipe operasi. Dari reversing parser-nya, operasi pentingnya adalah:

```text
type 1 = create/update entry
type 2 = update block/size
type 3 = rename
type 4 = delete
type 5 = checkpoint
type 6 = rollback
type 7 = commit
```

Karena deskripsi challenge mengatakan hanya committed ticks yang dihitung, maka kita tidak boleh langsung mengambil state terakhir dari journal.

Kita harus melakukan replay journal seperti server:

1. Mulai dari state kosong.
2. Terapkan semua record satu per satu.
3. Simpan snapshot ketika menemukan checkpoint.
4. Jika ada rollback yang cocok dengan checkpoint, kembalikan state ke snapshot.
5. Ketika menemukan commit, simpan state tersebut sebagai final committed state.

Hasil pentingnya: committed state berhenti pada commit tick yang valid. Entry setelah commit, seperti replay jebakan, tidak dihitung.

---

## File yang Ditemukan

Setelah journal direplay sampai committed state, ditemukan beberapa file penting:

```text
/replays/tutorial.raid
/replays/placement.raid
/replays/promotion.raid
/replays/godmode.raid
/cache/achievement.bin
```

Ada juga replay yang terlihat menarik, tetapi muncul setelah commit:

```text
/replays/one_button_clear.raid
```

File ini adalah jebakan. Sesuai deskripsi challenge, rollback dan perubahan setelah commit tidak memengaruhi MMR, jadi file tersebut tidak dipakai untuk solusi.

---

## Membaca File dari RankedFS

Isi file tidak tersimpan plaintext. Block file dienkripsi menggunakan stream key dari BLAKE2s.

Untuk membaca file, key stream per 32 byte dibuat dari:

```text
root_hash || file_id || block_counter || "RANKEDFS-BLOCK"
```

Lalu ciphertext di-XOR dengan key stream tersebut.

Secara konsep:

```python
key = blake2s(root + file_id + p32(counter) + b"RANKEDFS-BLOCK").digest()
plaintext = ciphertext ^ key
```

Setelah fungsi readfile dibuat, file `.raid` dan `achievement.bin` bisa diekstrak.

---

## Format File `.raid`

Setiap file `.raid` adalah replay program kecil. Isinya terdiri dari:

```text
header
nodes
edges
lane target
```

Header menyimpan beberapa field penting:

```text
stage id
jumlah node
jumlah edge
jumlah lane/register
input offset
input length
seed/key material
encrypted target lanes
```

Replay `.raid` ini bekerja seperti VM kecil berbentuk graph. Node dieksekusi berdasarkan topological order dari edge graph.

---

## VM Replay

VM memakai register 32-bit. Beberapa opcode yang ditemukan:

```text
op 0  = input load
op 1  = load constant
op 2  = add/rotate mix
op 3  = xor/rotate mix
op 4  = multiply/add mix
op 5  = xorshift-like mix
op 6  = two-register mix
op 7  = swap
op 8  = checkpoint
op 9  = rollback check
op 10 = update MMR
op 11 = success marker
op 12 = swap
```

Setiap stage menghasilkan target register. Kalau input benar, hasil akhir register VM akan sama dengan target tersebut.

---

## Kenapa Tidak Perlu Brute Force

Player code panjangnya 48 byte:

```text
????????????????????????????????????????????????
```

Kalau di-bruteforce langsung, ukurannya terlalu besar.

Namun VM ini reversible. Hampir semua operasi bisa dibalik:

```text
rol  -> ror
xor  -> xor
add  -> subtract
imul dengan angka ganjil -> modular inverse mod 2^32
xorshift -> inverse xorshift
swap -> swap
```

Karena itu strategi solusinya adalah menjalankan VM secara mundur dari target register.

---

## Reversing Stage

Untuk setiap `.raid`, langkahnya:

1. Parse node dan edge.
2. Tentukan urutan eksekusi dengan topological sort.
3. Dekripsi target lane/register.
4. Jalankan node dari belakang ke depan.
5. Saat menemukan operasi input, ambil nilai register saat itu sebagai 4 byte player code.
6. Ulangi untuk semua stage.

Karena ada opcode rollback, solver mencoba kemungkinan rollback mask untuk node `op 9`.

Setelah reverse kandidat selesai, kandidat divalidasi lagi dengan forward execution. Kandidat dianggap benar hanya jika:

```text
hasil register == target register
rollback yang terjadi == rollback mask yang diasumsikan
```

---

## Stage yang Diselesaikan

Replay yang dipakai:

```text
/replays/tutorial.raid
/replays/placement.raid
/replays/promotion.raid
/replays/godmode.raid
```

Masing-masing stage membuka bagian berbeda dari player code dan memperbarui state.

Pada akhirnya, MMR naik dari:

```text
995 -> 999
```

Ini sesuai judul challenge, `GODMODE//999`.

---

## Player Code

Hasil reverse VM menghasilkan player code berikut:

```text
r0llb4ck_th3_un1v3rs3_4nd_qu3u3_f0r_LV999!!!n0w!
```

Player code ini bukan flag, tetapi dipakai untuk membuka achievement.

---

## Decrypt Achievement

File berikut berisi achievement terenkripsi:

```text
/cache/achievement.bin
```

Key achievement diturunkan dari beberapa komponen:

```text
player_code
raid state
MMR
stage output
achievement metadata
```

Kemudian key dipakai untuk membuka ciphertext menggunakan skema mirip ChaCha20-Poly1305.

Langkah decrypt:

1. Derive key dengan BLAKE2s.
2. Verifikasi Poly1305 tag.
3. Jika tag valid, decrypt ciphertext dengan ChaCha20.
4. Plaintext menghasilkan flag.

---

## Solver Output

Ketika solver dijalankan:

```bash
python3 solve_godmode.py
```

Output:

```text
player_code = r0llb4ck_th3_un1v3rs3_4nd_qu3u3_f0r_LV999!!!n0w!
flag = uiuctf{r0llb4ck_th3_un1v3rs3_4nd_qu3u3_4g41n}
```

---

## Flag

```text
uiuctf{r0llb4ck_th3_un1v3rs3_4nd_qu3u3_4g41n}
```

---

