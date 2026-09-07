# Bank of NNS

## Ringkasan

Service Bank of NNS menerima command `settle <amount> <proof>` dan memverifikasi proof Kimchi/Mina sebelum mengurangi vault. Bug-nya ada di constraint range-check 64-bit: witness bisa dibuat untuk amount besar berbentuk:

```
amount = high * 2^76 + low
```

selama bit `64..75` bernilai `0`. Bagian `high` disimpan di witness range-check yang tidak dipaksa nol, sementara service tetap memakai public `amount` penuh untuk mengurangi vault. Efeknya, withdrawal besar tetap punya bukti valid, tetapi daily limit hanya berkurang kecil dari komponen low (`10` NNS per withdrawal pada solve ini).

Flag didapat setelah vault menjadi `0`, lalu menjalankan command lowercase `balance`.

```
NNS{so_tH3_M1na_P3rMu7at10N_cYCle_f0r_eaCH_bl0cK_w4s_4_lie?!}
```

## File Challenge

```
Cargo.toml
Cargo.lock
src/main.rs
src/challenge.rs
```

File utama:

- `src/main.rs`: contoh client/prover untuk withdrawal normal `AMOUNT = 10`.
- `src/challenge.rs`: definisi circuit Kimchi, public input, gate range-check, dan koneksi constraint.

## Analisis Awal

Source client membuat satu proof untuk `AMOUNT = 10`, serialize proof pakai `rmp_serde`, encode dengan base64, lalu kirim:

```
settle <amount> <base64-proof>
```

Service remote memberi banner seperti ini:

```
BALANCE                      10000 NNS
VAULT     100000000000000000000000 NNS
COMMANDS  SETTLE <amount> <proof> : BALANCE : QUIT
```

Walaupun banner menulis command uppercase, parser service ternyata case-sensitive dan command yang benar adalah lowercase:

```
balance
quit
```

Uppercase `BALANCE` cuma mengembalikan help command.

## Temuan Penting

Di `src/challenge.rs`, circuit membuat dua public input lalu menambahkan range-check:

```rust
CircuitGate::<Fp>::create_generic_gadget(Wire::for_row(0), GenericGateSpec::Pub, None),
CircuitGate::<Fp>::create_generic_gadget(Wire::for_row(1), GenericGateSpec::Pub, None),
...
CircuitGate::<Fp>::extend_range_check(&mut gates, &mut row);
gates.connect_64bit(1, 2);
gates.connect_cell_pair((0, 0), (2, 0));
```

`connect_cell_pair((0, 0), (2, 0))` membuat public amount sama dengan nilai amount di row range-check.

Masalahnya, layout witness untuk range-check bisa dimodifikasi. Kode normal di `src/main.rs` mengisi:

```rust
row[0] = Fp::from(amount);
row[1] = Fp::zero();
row[2] = Fp::zero();
```

Limb lain berisi potongan bawah amount:

```rust
for (i, shift) in [52, 40, 28, 16].iter().enumerate() {
    row[3 + i] = Fp::from(((amount >> shift) & 0xfff) as u64);
}
for i in 0..8 {
    row[7 + i] = Fp::from(((amount >> (14 - 2 * i)) & 0x3) as u64);
}
```

Limb tersebut hanya merepresentasikan bagian bawah 64-bit. Pada exploit, `row[1]` tidak dibuat nol, tapi diisi dengan `amount >> 76`. Dengan syarat bit `64..75` nol, circuit masih bisa menerima witness tersebut.

Payload amount yang lolos punya bentuk:

```
amount = high * 2^76 + low
low = 10
bits 64..75 = 0
```

Contoh amount yang dipakai:

```
2^76 + 10  = 75557863725914323419146
2^88 + 10  = 309485009821345068724781066
```

Withdrawal pertama mengurangi vault besar-besaran tapi balance/daily limit hanya turun `10`:

```
approved - dispensing 75557863725914323419146 NNS
BALANCE 9990 NNS
VAULT   24442136274085676580854 NNS
```

Withdrawal kedua dengan `2^88 + 10` mengosongkan sisa vault:

```
approved - dispensing 309485009821345068724781066 NNS
BALANCE 9980 NNS
VAULT   0 NNS
```

## Proses Ekstraksi

Solver menambahkan binary Rust kecil di `src/bin/gen_proof.rs`. Binary ini memakai circuit challenge yang sama, tapi witness-nya diganti:

```rust
row[0] = amount;
row[1] = fp_from_big(&(amount_big >> 76usize));
row[2] = Fp::zero();
```

Sebelum membuat proof, solver memastikan amount masih canonical di field `Fp` dan bit `64..75` bernilai nol:

```rust
let middle_12 = limb(amount_big, 64, 0xfff);
if middle_12 != 0 {
    eprintln!("amount is not provable by the broken 64-bit check: bits 64..75 must be zero");
    std::process::exit(2);
}
```

Setelah proof lokal lolos `verify(...)`, proof diserialize dan dikirim ke service sebagai command `settle`.

Alur eksploit:

1. Ambil status awal dari service.
2. Pilih amount berbentuk `high * 2^76 + 10`.
3. Generate proof valid untuk amount besar tersebut.
4. Kirim `settle <amount> <proof>`.
5. Ulangi sampai `VAULT` menjadi `0`.
6. Jalankan `balance` lowercase untuk mengambil statement dan flag.

## Solve Script

File `solve.py` melakukan tiga hal:

1. Membuat `src/bin/gen_proof.rs` jika belum ada.
2. Menjalankan `cargo run --release --quiet --bin gen_proof -- <amount>` untuk membuat proof.
3. Berinteraksi ke service TLS dengan command `settle`, `balance`, dan `quit`.

Mode utama:

```bash
HOST=bank-of-nns-4cada48ae4f4.chall.nnsc.tf PORT=1337 python3 solve.py
```

Untuk instance yang vault-nya sudah kosong:

```bash
HOST=bank-of-nns-4cada48ae4f4.chall.nnsc.tf PORT=1337 python3 solve.py --balance
```

Kalau mau manual setelah vault kosong:

```bash
ncat --ssl bank-of-nns-4cada48ae4f4.chall.nnsc.tf 1337
```

Lalu ketik:

```
balance
quit
```

Catatan: jangan pakai Bash arithmetic untuk `2^76`, misalnya:

```bash
python3 solve.py --amount $(( (1 << 76) + 10 ))
```

Di Bash, angka itu overflow dan berubah jadi `4106`, sehingga ditolak daily limit. Kalau perlu amount manual, tulis decimal penuh:

```bash
python3 solve.py --amount 75557863725914323419146
```

## Cara Menjalankan

Dari folder challenge asli yang berisi `Cargo.toml` dan `src/challenge.rs`:

```bash
python3 solve.py
```

Atau dengan target eksplisit:

```bash
HOST=bank-of-nns-4cada48ae4f4.chall.nnsc.tf PORT=1337 python3 solve.py
```

Jika proses proof pertama agak lama, tunggu sampai `cargo` selesai build release. Run berikutnya jauh lebih cepat karena binary sudah ter-compile.

## Flag

Flag muncul dari output `balance` setelah `VAULT` menjadi `0`:

```
--- STATEMENT --------------------------------------------------
 BALANCE                       9980 NNS
 WITHDRAWN 309560567685070983048200212 NNS
 VAULT                            0 NNS
 FLAG      NNS{so_tH3_M1na_P3rMu7at10N_cYCle_f0r_eaCH_bl0cK_w4s_4_lie?!}
----------------------------------------------------------------
```

```
<FLAG>NNS{so_tH3_M1na_P3rMu7at10N_cYCle_f0r_eaCH_bl0cK_w4s_4_lie?!}</FLAG>
```
