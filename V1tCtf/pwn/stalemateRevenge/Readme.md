# StaleMate - Revenge

## Info

- Category: Pwn
- Binary: `service`
- Protections: Full RELRO, Canary, NX, PIE
- Target: `nc pwn.v1t.site 31338`

## Ringkasan

Bug utamanya ada di alur `open pipe -> mirror pipe -> drop pipe`.

Pipe yang sudah di-drop masih punya stale view yang tetap aktif. Stale view itu bisa dipakai buat baca/tulis page yang sudah direuse allocator untuk objek lain. Di challenge ini, reuse itu dipakai untuk dua hal:

1. Leak key workspace dari descriptor page yang kebetulan ketiban stale view.
2. Tulis descriptor baru supaya page tertentu bisa dibaca/tulis lewat menu `fetch slice` dan `store slice`.

Setelah key workspace ketemu, descriptor encoding bisa direkonstruksi. Dari situ kita bisa buka akses ke page-page yang berisi record chain, patch field yang stale, hitung ulang hash, lalu `claim record` mengeluarkan flag.

## Recon

Binary ini adalah ELF64 PIE dengan proteksi aktif:

```text
Full RELRO | Canary found | NX enabled | PIE enabled
```

Menu yang relevan:

```text
1. open pipe
2. mirror pipe
3. drop pipe
4. send packet
5. trace packet
6. open workspace
7. attach shelf
8. fetch slice
9. store slice
10. sync ledger
11. stage voucher
12. discard voucher
13. claim record
```

Menu `trace packet` dan `send packet` adalah primitive paling penting. Dengan stale view, keduanya jadi baca/tulis ke page yang sudah direuse untuk workspace metadata.

## Analisis Bug

### 1. Stale view UAF

Urutan:

```text
open pipe -> mirror pipe -> drop pipe
```

menghapus objek pipe, tapi view hasil `mirror` masih hidup. Saat allocator reuses page itu untuk workspace, stale view tadi bisa membaca dan menulis isi workspace.

### 2. Workspace key bersifat per-instance

Workspace metadata punya dua key random `A` dan `B`. Key ini dipakai di helper encoding/decoding descriptor. Tanpa dua key ini, hasil `send packet` cuma menghasilkan descriptor yang gagal diverifikasi.

Stale view pada order kecil dipakai untuk leak descriptor page workspace. Dari slot `1`, value `x` dan `y` bisa dibalik ke `A` dan `B` karena plaintext slot itu sudah diketahui.

### 3. Descriptor encoding

Disassembly helper menunjukkan encoding descriptor memakai dua tahap:

- `mix()` style splitmix64
- rotasi dan XOR yang bergantung pada `level` dan `index`

Setelah `A` dan `B` direcover, descriptor baru bisa dibangun ulang. Itu memungkinkan kita menulis slot descriptor pada page-level tertentu dan mengarahkan workspace ke page yang kita mau.

## Eksploitasi

### Step 1 - Leak `A` dan `B`

Pakai:

```text
open pipe(1, 0x40)
mirror pipe(1)
drop pipe(1)
open workspace
attach shelf
sync ledger
trace packet(view=0, slot=1)
```

Slot `1` pada stale view ini stabil untuk leak descriptor workspace. Plaintext slot itu diketahui, jadi dari `x/y` kita balik lagi ke `A` dan `B`.

### Step 2 - Buka page descriptor tambahan

Setelah key workspace ketemu, buka stale view lain dengan ring yang lebih besar:

```text
open pipe(1, 0x40)
open pipe(2, 0x200)
mirror/drop keduanya
open workspace
attach shelf
sync ledger
```

Dengan layout ini, `trace packet(view=1, slot=0x1d)` dan slot-slot lain memberi akses ke descriptor page level-2. Descriptor baru untuk slot `0xa8..0xac` bisa diarahkan ke page fisik 8..12.

### Step 3 - Patch record pages

Page yang dipetakan via descriptor baru dipakai buat baca dan tulis record chain:

- page `A` di offset `0x120`
- page `B` di offset `0x260`
- page `C` di offset `0x090`
- page `D` di offset `0x330`
- page `E` di offset `0x1d0`

Isi record chain punya field stale yang tidak konsisten dengan hash internal. Yang perlu diperbaiki:

- root record perlu cross-hash baru
- record `B`, `C`, `D`, dan `E` harus punya field pointer dan constant yang sesuai
- hash di tiap record harus dihitung ulang

Konstanta penting yang dipakai:

- `0x8120`
- `0x9260`
- `0xa090`
- `0xb330`
- `0xc1d0`

Setelah patch ditulis balik lewat `store slice`, `claim record` lolos dan service ngeluarin flag.

## Solver

File exploit final:

- `solve.py`

Run lokal:

```bash
source /home/kali/tools/ctf/bin/activate
python3 solve.py LOCAL=1
```

Run remote:

```bash
source /home/kali/tools/ctf/bin/activate
python3 solve.py
```

## Flag

```text
v1t{revenge_requires_grooming_not_grep}
```
