# Behind the Curtain

## Ringkasan

Challenge ini memberikan sebuah ELF 64-bit PIE bernama `sparkle` yang menjalankan LuaJIT bytecode tersembunyi.

Flag tidak muncul sebagai string plaintext biasa.

Binary memuat chunk:

```text
@curtain
```

kemudian membaca input dan memvalidasi input sepanjang **70 byte** melalui dua lapisan:

1. VM internal dengan record/opcode yang didecrypt saat runtime.
2. Validator akhir berbasis operasi ARX/permutasi pada 72 word.

Solusi diperoleh dengan:

1. Membalik validator akhir untuk mendapatkan output target VM.
2. Membalik VM internal dari output target tersebut sampai mendapatkan state input awal.
3. Menangani ambiguity nilai `0x00` pada state modulo 257.
4. Melakukan forward-check terhadap hasil akhir.

Flag:

```text
uiuctf{t4k3_th3_m4sk_fr0m_4_m4sk3d_f00l_4nd_wh4t5_l3ft_15_ju5t_4_f00l}
```

---

## File Challenge

File utama:

```text
sparkle
```

Informasi binary:

```text
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

SHA256:

```text
8465657fc6f7650c4a2fe834e83f776e3e529e33b907d93a2ef243175ead2e5c
```

---

## Recon Awal

Beberapa string yang terlihat menggunakan `strings`:

```text
The curtain rises. Which mask takes the final bow?
The mask laughs back.
The audience erupts in applause.
@curtain
```

Tidak terdapat flag plaintext di dalam binary.

Di bagian `.rodata` terdapat marker LuaJIT bytecode:

```text
1b 4c 4a 02
```

Header tersebut merupakan signature LuaJIT bytecode.

Dari perilaku runtime diketahui:

- input harus memiliki panjang tepat 70 byte;
- input yang salah menghasilkan:
  ```text
  The mask laughs back.
  ```
- input yang benar menghasilkan:
  ```text
  The audience erupts in applause.
  ```

Karena ELF stripped dan bytecode LuaJIT disimpan sebagai data, pendekatan static analysis saja kurang nyaman.

Pendekatan yang lebih efektif adalah melakukan dynamic analysis dan meng-hook runtime setelah Lua state dibuat untuk mengekspos fungsi checker beserta upvalue Lua-nya.

---

# Analisis Static

Chunk utama menyimpan sebuah fungsi `CHECKER`.

Fungsi tersebut bukan validator langsung, tetapi wrapper menuju dispatcher LuaJIT yang menggunakan banyak tabel dan fungsi upvalue.

Objek penting ditemukan pada tabel VM:

```text
T[349][1]  = validator akhir
T[349][2]  = memory object/cdata
T[349][4]  = encrypted VM byte stream
T[349][5]  = stage-local opcode map
T[349][10] = state VM 72 elemen
```

Encrypted VM stream setelah didecrypt memiliki ukuran:

```text
28720 byte
```

Karena setiap record berukuran 8 byte:

```text
28720 / 8 = 3590 record
```

Jadi terdapat:

```text
3590 record x 8 byte
```

---

# Analisis Dynamic

Dispatcher Lua di-hook untuk melihat state:

```text
T[349][10]
```

setelah setiap record dieksekusi.

Beberapa input digunakan untuk melakukan differential tracing:

```text
A * 70
B * 70
\x00 * 70
```

Dari trace tersebut dapat diketahui bagaimana setiap opcode memengaruhi state.

Opcode VM diacak berdasarkan stage.

Setelah opcode mapping dibalik, semantic operation yang digunakan hanya terdiri dari delapan jenis:

```text
1 = load input
2 = set constant 256
3 = linear update
4 = quadratic update
5 = swap
6 = copy/output, tidak mengubah state utama
7 = next stage
8 = halt
```

---

# VM Record

Setiap record memiliki ukuran 8 byte.

Contoh record quadratic:

```text
bb 01 00 00 b2 1b 01 00
```

Record tersebut berarti:

```text
state[1] += 0xb2 * state[0] * state[0]
          + 0x1b * state[0]
          + 0x01

state[1] %= 257
```

Untuk input:

```text
A = 0x41
```

hasil state sesuai dengan trace runtime, yaitu:

```text
0x5a
```

---

# Semantic Operation

## Semantic 3 — Linear Update

Bentuk operasinya:

```python
state[d] = (
    state[d]
    + (r3 - r4) * state[a]
    + r5 - r6
) % 257
```

Operasi ini hanya menggunakan source state sebelum destination ditulis.

---

## Semantic 4 — Quadratic Update

Bentuk operasinya:

```python
state[d] = (
    state[d]
    + r4 * state[a] * state[b]
    + r5 * state[a]
    + r6 - r7
) % 257
```

Karena destination tidak digunakan sebagai source dalam update, operasi ini dapat dibalik langsung.

---

## Semantic 5 — Swap

Operasinya sederhana:

```python
swap(state[a], state[b])
```

Untuk inverse, swap yang sama dapat dilakukan kembali:

```python
swap(state[a], state[b])
```

---

# Modulus 257

Aritmetika VM menggunakan:

```text
mod 257
```

Ini penting karena state bukan hanya merepresentasikan nilai byte `0..255`.

Nilai:

```text
256
```

juga dapat muncul di dalam state.

Akibatnya terdapat ambiguity khusus untuk output byte:

```text
0x00
```

Nilai tersebut dapat berhubungan dengan representasi state:

```text
0
```

atau:

```text
256
```

Solver harus mencoba kedua kemungkinan tersebut jika diperlukan.

---

# Validator Akhir

Setelah VM menghasilkan output, data tersebut masuk ke validator akhir.

Validator menerima:

```text
72 byte
```

Data kemudian diproses menggunakan beberapa tahap:

1. Initial mask menggunakan PRNG kecil.
2. 16 ronde ARX/permutation.
3. Final target comparison.

Secara konseptual:

```text
VM output
   |
   v
Initial mask
   |
   v
16 rounds ARX/permutation
   |
   v
Target comparison
```

Target hardcoded berada di dalam memory binary.

---

# Membalik Validator

Karena semua operasi pada validator bersifat reversible, validator dapat dibalik dari belakang.

Proses inverse:

```text
target
  |
  v
undo target mask
  |
  v
undo round 15
  |
  v
undo round 14
  |
  v
...
  |
  v
undo round 0
  |
  v
undo initial mask
  |
  v
VM output
```

Hasil reverse validator adalah output 72 byte yang harus dihasilkan oleh VM.

Output target VM yang diperoleh:

```text
24d2da3e7fbc2a5c4bc60bb1338ef5bc2bdb32ba5589780900f265336af97759554ad1a4bdc35ceb779f08dbc1f9b821802f23ed5222d2f48cf1f9c60fe3f2e83f52806dfc12c4fe
```

---

# Membalik VM

Setelah mendapatkan output target VM, langkah berikutnya adalah menjalankan VM secara terbalik.

VM dibalik dari:

```text
stage 13
```

kembali menuju:

```text
stage 2
```

dan record pada setiap stage diproses dari belakang ke depan.

Untuk operasi update:

```text
state[d] = (state[d] + expression) % 257
```

inverse-nya cukup:

```text
state[d] = (state[d] - expression) % 257
```

Karena expression tidak bergantung pada nilai destination yang baru, operasi dapat diinversi secara langsung.

Untuk swap:

```python
swap(state[a], state[b])
```

cukup dilakukan kembali.

---

# Penyusunan Solver

`solve.py` berisi beberapa komponen utama:

```text
1. Decrypted VM record
2. Opcode map untuk setiap stage
3. Target output 72 byte hasil inverse validator
4. Forward VM emulator
5. Inverse VM emulator
6. Logic untuk menangani ambiguity 0 / 256
```

Struktur proses solver:

```text
Encrypted VM records
        |
        v
Decrypt records
        |
        v
Recover opcode mappings
        |
        v
Inverse final validator
        |
        v
72-byte VM target
        |
        v
Inverse VM
        |
        v
70-byte input
        |
        v
Forward VM sanity check
        |
        v
Flag
```

---

# Ambiguity `0x00`

Karena VM menggunakan modulus:

```text
257
```

nilai byte:

```text
0x00
```

memiliki dua kemungkinan representasi pada proses reverse:

```text
0
```

atau:

```text
256
```

Solver mencoba kedua kemungkinan.

Kandidat yang benar dapat dibedakan berdasarkan hasil akhir:

1. Harus menghasilkan input sepanjang 70 byte.
2. Harus memiliki format flag yang masuk akal.
3. Harus lolos forward-check VM.
4. Kandidat valid menghasilkan:
   ```text
   uiuctf{...}
   ```

Hanya representasi raw `0` yang menghasilkan kandidat valid dan printable.

---

# Solve Script

Solver disimpan sebagai:

```text
solve.py
```

Isi solver menggunakan:

- decrypted VM stream;
- opcode map per stage;
- inverse validator;
- inverse VM;
- forward emulator sebagai sanity check.

Jalankan dengan:

```bash
cd /mnt/data/behind_the_curtain
python3 solve.py
```

Output:

```text
uiuctf{t4k3_th3_m4sk_fr0m_4_m4sk3d_f00l_4nd_wh4t5_l3ft_15_ju5t_4_f00l}
```

---

# Validasi ke Binary

Setelah mendapatkan kandidat input, validasi langsung terhadap binary:

```bash
printf '%s\n' \
'uiuctf{t4k3_th3_m4sk_fr0m_4_m4sk3d_f00l_4nd_wh4t5_l3ft_15_ju5t_4_f00l}' \
| ./sparkle
```

Binary memberikan:

```text
The curtain rises. Which mask takes the final bow?
The audience erupts in applause.
```

Pesan:

```text
The audience erupts in applause.
```

menunjukkan bahwa input berhasil melewati seluruh validator.

---

# Exploit / Solve Chain

Keseluruhan proses dapat diringkas menjadi:

```text
ELF sparkle
    |
    v
Hidden LuaJIT bytecode
    |
    v
Recover CHECKER + VM tables
    |
    v
Decrypt VM stream
    |
    v
Recover stage opcode maps
    |
    v
Trace VM dengan dynamic analysis
    |
    v
Recover semantic operations
    |
    v
Reverse final ARX validator
    |
    v
72-byte VM target
    |
    v
Reverse VM stage 13 -> stage 2
    |
    v
70-byte candidate input
    |
    v
Resolve 0 / 256 ambiguity
    |
    v
Forward-check
    |
    v
Valid input
```

---

# Kesimpulan

Challenge ini menggabungkan beberapa lapisan obfuscation:

- ELF PIE stripped;
- LuaJIT bytecode tersembunyi;
- runtime decryption;
- stage-local opcode mapping;
- VM dengan state 72 elemen;
- aritmetika modulo 257;
- validator akhir berbasis ARX/permutation.

Pendekatan yang efektif bukan mencoba brute-force input 70 byte.

Sebaliknya, validator akhir dan VM keduanya reversible.

Langkah kuncinya adalah:

1. Mengekspos state Lua melalui dynamic analysis.
2. Mendekripsi VM record.
3. Memetakan opcode ke semantic operation.
4. Membalik validator akhir untuk mendapatkan target output VM.
5. Membalik seluruh VM dari stage terakhir.
6. Menyelesaikan ambiguity `0` versus `256`.
7. Melakukan forward-check terhadap binary.

Input yang dihasilkan kemudian diterima oleh `sparkle`.

## Flag

```text
uiuctf{t4k3_th3_m4sk_fr0m_4_m4sk3d_f00l_4nd_wh4t5_l3ft_15_ju5t_4_f00l}
```
