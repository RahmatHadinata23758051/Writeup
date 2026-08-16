# Market — Writeup

## Challenge

**Name:** Market
**Category:** Blockchain / Solana
**Remote:** `nc challs.scriptsorcerers.xyz 10341`

Description:

> A market where the flag does not exist...

Challenge ini memberikan program Solana dan server launcher. Tujuan akhirnya adalah mengambil alih ownership market sehingga server menganggap kita berhasil mencuri market dan mencetak flag.

## Flag

```text
scriptCTF{w41t_4_s3c0nd_wh0_4r3_y0u???_5e3b035867ff}
```

## TL;DR

Bug ada di fungsi `buy()`.

Pada branch pembelian item selain item `0`, program hanya menghitung PDA untuk item `SHELL`, tetapi tidak memvalidasi bahwa account `item` yang dikirim benar-benar PDA `SHELL`.

Akibatnya, attacker bisa mengirim account item lain dan menyalahgunakan account `Config` sebagai account `Holding`.

Payload inti:

1. Buat/init user PDA.
2. Deposit SOL secukupnya.
3. Panggil `buy()` dengan kombinasi account yang sengaja salah:

   * `item = RUBBERDUCK`
   * `item_id = 1337`
   * `holding = CONFIG PDA`
4. Karena layout `Config` dan `Holding` mirip, penulisan field `holding.owner = user` akan menimpa `config.owner`.
5. Server membaca `Current owner == user`, lalu flag keluar.

## Analisis Source

Dari source program, terdapat beberapa account utama, di antaranya `Config`, `Item`, `User`, dan `Holding`.

Struktur pentingnya:

```rust
pub struct Config {
    pub owner: Pubkey,
    pub treasury: Pubkey,
    pub shop_item_count: u64,
}

pub struct Holding {
    pub owner: Pubkey,
    pub item: Pubkey,
    pub quantity: u64,
}
```

Kedua struct tersebut punya layout yang kompatibel:

```text
Config  : Pubkey | Pubkey | u64
Holding : Pubkey | Pubkey | u64
```

Artinya, jika account `Config` diperlakukan sebagai `Holding`, field `Holding.owner` berada di offset yang sama dengan `Config.owner`.

## Bug di `buy()`

Fungsi `buy()` melakukan validasi item berdasarkan `item_id`.

Untuk item pertama, validasi PDA dilakukan dengan benar. Namun pada branch lain, logic-nya bermasalah:

```rust
else {
    let (item1_pda, item1_expected_bump) =
        Pubkey::find_program_address(&[b"SHELL"], program);
}
```

Masalahnya, kode tersebut hanya menghitung PDA `SHELL`, tetapi tidak membandingkan hasilnya dengan account `item` yang dikirim user.

Seharusnya ada validasi seperti:

```rust
if item.key != &item1_pda {
    return Err(ProgramError::InvalidAccountData);
}
```

Namun validasi tersebut tidak ada.

## Dampak Bug

Karena account `item` tidak divalidasi pada branch tersebut, attacker bebas mengirim account item lain.

Yang lebih penting, parameter `holding` juga bisa diarahkan ke account `Config`.

Saat proses `buy()` berjalan, program menganggap account `holding` adalah `Holding` dan menulis:

```rust
holding_data.owner = user;
holding_data.item = item;
holding_data.quantity += 1;
```

Namun karena `holding` sebenarnya adalah account `Config`, efek sebenarnya menjadi:

```text
config.owner = user
config.treasury = item
config.shop_item_count += 1
```

Field paling penting adalah:

```text
config.owner = user
```

Inilah yang membuat ownership market berpindah ke attacker.

## Exploit Flow

Exploit menggunakan program solver SBF kecil untuk melakukan CPI ke program market.

Alur eksploitasi:

1. Connect ke remote service.
2. Upload `solve.so` ke environment challenge.
3. Ambil program id market dari output server.
4. Hitung PDA yang dibutuhkan:

   * `CONFIG`
   * `TREASURY`
   * user PDA
   * item PDA seperti `RUBBERDUCK`
5. Kirim instruction ke solver program.
6. Solver melakukan beberapa CPI:

   * init/create user
   * deposit lamports
   * panggil `buy()` dengan account confusion
7. Account `Config` ter-overwrite sehingga owner menjadi user attacker.
8. Server mencetak flag.

## Solver

Contoh pemakaian solver:

```bash
python3 solve.py challs.scriptsorcerers.xyz 10341
```

Output sukses remote:

```text
[*] solve.so size: 49920 bytes
[*] market program: 11157t3sqMV725NVRLrVQbAu98Jjfk1uCKehJnXXQs
[*] user          : CXK8X6s7xx7yHEAm5PgGPpt4i2K9ZrtmmC1xU9wHGjub
num accounts:
ix len:
Done
Current owner: CXK8X6s7xx7yHEAm5PgGPpt4i2K9ZrtmmC1xU9wHGjub
Did you just steal the market from ME?? I SHALL BE BACK!: scriptCTF{w41t_4_s3c0nd_wh0_4r3_y0u???_5e3b035867ff}

[+] flag: scriptCTF{w41t_4_s3c0nd_wh0_4r3_y0u???_5e3b035867ff}
```

## Build Notes

Saat build solver SBF, sempat muncul beberapa error dependency seperti:

```text
feature `edition2024` is required
```

Penyebabnya adalah `cargo build-sbf` memakai Rust/Cargo dari Solana platform tools yang lebih tua, sementara beberapa dependency terbaru di crates.io sudah memakai Rust edition 2024 atau membutuhkan Rust lebih baru.

Solusi yang dipakai adalah mem-pin dependency agar kompatibel dengan compiler SBF:

```toml
solana-program = "=1.18.26"
blake3 = "=1.5.0"
digest = "=0.10.7"
block-buffer = "=0.10.4"
crypto-common = "=0.1.6"
indexmap = "=2.2.6"
zeroize = "=1.3.0"
zeroize_derive = "=1.4.2"
borsh = "=1.5.7"
jobserver = "=0.1.32"
```

Command build yang dipakai:

```bash
export PATH="$HOME/.cargo/bin:$HOME/.local/share/solana/install/active_release/bin:$PATH"
rm -rf solve/target solve/Cargo.lock "$HOME/.cargo/registry/src/index.crates.io-"* /tmp/cargo-build-sbf
cd solve
cargo generate-lockfile
cargo build-sbf
cd ..
```

Catatan penting: jangan memakai `\~/.cargo` ketika menghapus cache. Gunakan `~/.cargo` atau `$HOME/.cargo`, karena `\~` tidak akan diekspansi menjadi home directory.

## Kesimpulan

Challenge ini bukan tentang membeli item yang benar-benar memiliki flag. Sesuai deskripsi, “the flag does not exist” di market sebagai item biasa.

Bug sebenarnya adalah missing account validation pada fungsi `buy()`. Karena account `item` tidak dicek pada branch tertentu, attacker bisa menyusun account list yang membuat account `Config` diperlakukan sebagai `Holding`. Akibatnya, field `owner` pada config tertimpa menjadi public key attacker.

Setelah ownership market berhasil dicuri, server memberikan flag.

Final flag:

```text
scriptCTF{w41t_4_s3c0nd_wh0_4r3_y0u???_5e3b035867ff}
```
