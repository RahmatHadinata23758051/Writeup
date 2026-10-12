# Countersign

## Ringkasan

Binary menjalankan attestation core berbasis VM kecil. Input `RUN` harus 24 byte. `GET` memberikan program image instance saat itu, tapi edge graph berisi banyak edge palsu. Edge asli bisa difilter lewat oracle `MINT` karena fungsi stamp bug: byte label (`'M'` untuk MINT dan `'E'` untuk edge) tertimpa ketika data length > 0, jadi `MINT <edge_message>` menghasilkan stamp yang sama dengan stamp edge.

Setelah edge asli diketahui, graph berubah menjadi rantai branch deterministic. State terakhir membandingkan enam register 32-bit dengan konstanta target. Semua state mixer sebelum checker bersifat reversible, jadi solver enumerate path valid, reverse operasi dari konstanta checker ke input awal, lalu validasi dengan `RUN`.

## File Challenge

- `countersign`: ELF 64-bit PIE, stripped.
- `note.txt`: dokumen protokol service.

## Analisis Awal

`note.txt` menjelaskan command utama:

```
GET            stream this instance's program image as hex
NONCE          this instance's nonce
MINT <hex>     debug stamp for up to 16 bytes
RUN <hex>      drive the core with a 24 byte input, print what it emits
```

Binary lokal menampilkan banner:

```
Countersign attestation core v2 ready.
commands: GET | NONCE | MINT <hex<=16> | RUN <hex 24>
```

`file countersign`:

```
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

## Analisis Static / Dynamic

Command parser mengenali `GET`, `NONCE`, `MINT`, `RUN`, dan `QUIT`.

Format program image dari `GET`:

```
magic      4 bytes  "CSGN"
version    u16
count      u16
start_id   u16
nonce      8 bytes
states...
```

Format tiap state:

```
state_id   u16
guard_reg  u8
guard_bit  u8
fallback   u16
code_len   u16
code       code_len bytes
edge_count u8
edges...
```

Format tiap edge:

```
guard_value u8
dst_id      u16
msg         u32
sig         6 bytes
```

VM memiliki register 32-bit. Opcode penting:

```
0x01 mov_imm32
0x02 mov_reg
0x03 add_reg
0x04 xor_reg
0x06 or_reg
0x07 rol
0x08 shr
0x09 add_imm32
0x0a xor_imm32
0x0c load_input_byte
0x0d emit FLAG getenv
0x0e set output flag
0x0f ret/error
```

State awal menyusun input 24 byte menjadi 6 register little-endian (r0..r5). State branch melakukan round reversible pada r0..r3. State kecil lain mengubah r4..r5. Checker akhir menghitung:

```
r6 = (r0 ^ C0) | (r1 ^ C1) | ... | (r5 ^ C5)
r6 |= r6 >> 16
r6 |= r6 >> 8
r6 |= r6 >> 4
r6 |= r6 >> 2
r6 |= r6 >> 1
```

Kalau `r6 & 1 == 0`, berarti semua register cocok dengan konstanta target dan route lanjut ke state flag.

## Algoritma Validasi atau Encoding

Edge graph tidak bisa dipakai langsung karena banyak edge decoy. Fungsi edge verification membuat message 9 byte:

```python
struct.pack('<HHBI', src_state, dst_state, guard_value, msg32)
```

Lalu membandingkan 6-byte stamp hasil fungsi hash internal dengan `sig` di image.

Bug-nya ada di fungsi stamp. Label command (`0x4d` untuk MINT, `0x45` untuk edge) ditulis ke buffer, tapi langsung dioverwrite oleh data ketika panjang data lebih dari nol. Karena edge message panjangnya 9 byte, label tidak berpengaruh. Akibatnya:

```
MINT edge_message == stamp edge internal
```

Solver memanggil `MINT` untuk setiap edge di image. Edge yang output stamp-nya sama dengan `sig` dianggap edge asli.

## Penyusunan Solve Script

`solve.py` melakukan langkah berikut:

1. Ambil image dengan `GET`.
2. Parse header, state, bytecode, dan edge.
3. Untuk setiap edge, panggil `MINT <src|dst|guard|msg>` dan cocokkan dengan signature edge.
4. DFS path valid dari start state ke flag state.
5. Untuk tiap path, ambil konstanta checker akhir.
6. Reverse semua operasi reversible dari checker ke state setelah loader input.
7. Susun 6 register hasil reverse menjadi 24 byte input little-endian.
8. Simulasikan ulang path secara lokal.
9. Kirim `RUN <input_hex>` ke instance yang sama.

Jalankan lokal:

```
python3 solve.py --local ./countersign
```

Test lokal dengan environment dummy:

```
FLAG='H7CTF{dummy_local_flag}' python3 solve.py --local ./countersign
```

Hasil test dummy membuktikan route valid:

```
[+] RUN output: H7CTF{dummy_local_flag}
<FLAG>H7CTF{dummy_local_flag}</FLAG>
```

Jalankan remote:

```
python3 solve.py --remote pwn.h7tex.com 42322
```

## Flag

Solver dijalankan ke service remote:

```
python3 solve.py --remote pwn.h7tex.com 42322
```

Output remote menghasilkan flag valid:

```
<FLAG>H7CTF{d0855f07-fdad-4f47-9d4b-8c22e98b3a52}</FLAG>
```

Flag akhir:

```
H7CTF{d0855f07-fdad-4f47-9d4b-8c22e98b3a52}
```

