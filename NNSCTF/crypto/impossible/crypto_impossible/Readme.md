# Writeup: impossible

## Challenge

Challenge ini memakai Groth16 proof. Target server hanya menerima sebuah proof untuk klaim:

```rust
pub const CLAIM: u64 = 1_000_000_000;
```

Padahal circuit aslinya membatasi nilai mint dari balance yang sudah fixed.

Flag:

```text
NNS{1MP05s1Bl3_pR00fs_fr0m_c3R3M0nY_45H3s}
```

## Analisis

Circuit yang dipakai ada di `src/lib.rs`:

```rust
pub struct MintCircuit {
    pub amount: Option<Fr>,
    pub balance: Option<Fr>,
}
```

Bagian pentingnya:

```rust
cs.enforce(
    || "mint cannot exceed balance",
    |lc| lc + balance,
    |lc| lc + CS::one(),
    |lc| lc + amount,
);

cs.enforce(
    || "fixed authorized balance",
    |lc| lc + balance,
    |lc| lc + CS::one(),
    |lc| lc + (fr(100), CS::one()),
);
```

Walaupun label constraint pertama bilang `mint cannot exceed balance`, implementasinya sebenarnya:

```text
balance = amount
balance = 100
```

Jadi proof valid normal hanya mungkin kalau:

```text
amount = 100
```

Sedangkan server meminta public input:

```text
amount = CLAIM = 1_000_000_000
```

Secara witness normal, ini impossible. Maka jalurnya bukan cari witness, tapi forge proof.

## Temuan

Ada file `secret`:

```text
PRERZBAL_VQ=3p311q9qso7735r42643s394qp2p10ns
GNH=3894627051107121998319229043008213446770981528672674568925122813412699817
```

Teks ini ternyata ROT13:

```text
CEREMONY_ID=3c311d9dfb7735e42643f394dc2c10af
TAU=3894627051107121998319229043008213446770981528672674568925122813412699817
```

Ini fatal, karena `TAU` adalah toxic waste dari trusted setup. Kalau toxic waste masih ada, Groth16 proof bisa dipalsukan tanpa witness yang valid.

## Teori yang Dipakai

Verifikasi Groth16 secara konsep mengecek pairing equation:

```text
e(A, B) = e(alpha, beta) · e(IC0 + x · IC1, gamma) · e(C, delta)
```

Dengan:

```text
x = public input
```

Di challenge ini:

```text
x = CLAIM = 1_000_000_000
```

Karena kita punya `tau`, challenge menyediakan fungsi:

```rust
derive(tau)
mint_ic_scalars(tau, alpha, beta, gamma)
```

Dari situ kita bisa dapat:

```text
alpha, beta, gamma, delta
IC0, IC1
```

Verifying key juga memakai scaling:

```text
G1 scale = g1_scale
G2 scale = g2_scale
```

Maka proof palsu bisa dibuat dengan memilih:

```text
A = alpha * g1_scale
B = beta  * g2_scale
```

Lalu pairing bagian `IC` dibatalkan lewat `C`:

```text
acc = IC0 + CLAIM * IC1
C = -g1_scale * acc * gamma / delta
```

Jadi verifier tetap melihat pairing equation valid, walaupun tidak ada witness yang memenuhi circuit.

## Solver

Replace isi `src/bin/solve.rs` dengan ini:

```rust
use bellman::groth16::Proof as BellmanProof;
use impossible_player::*;
use pairing::bls12_381::Fr;
use pairing::{Field, PrimeField};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};

const REMOTE: &str = "impossible-XXXXXXX.chall.nnsc.tf:31337";

const CEREMONY_ID: &str = "3c311d9dfb7735e42643f394dc2c10af";
const TAU_DEC: &str =
    "3894627051107121998319229043008213446770981528672674568925122813412699817";

fn submit(proof: Proof) -> std::io::Result<String> {
    let payload = encode_proof(&proof);

    let mut stream = TcpStream::connect(REMOTE)?;
    stream.write_all(payload.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.shutdown(Shutdown::Write)?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn main() -> std::io::Result<()> {
    let tau = Fr::from_str(TAU_DEC).unwrap();

    let [alpha, beta, gamma, delta, g1_scale, g2_scale] = derive(tau);
    let [ic0, ic1] = mint_ic_scalars(tau, alpha, beta, gamma);

    // acc = IC0 + CLAIM * IC1
    let mut acc = ic1;
    acc.mul_assign(&fr(CLAIM));
    acc.add_assign(&ic0);

    // A = [alpha]1 with G1 ceremony scale
    let mut a = alpha;
    a.mul_assign(&g1_scale);

    // B = [beta]2 with G2 ceremony scale
    let mut b = beta;
    b.mul_assign(&g2_scale);

    // C cancels the public input pairing term:
    // C = -g1_scale * acc * gamma / delta
    let mut c = acc;
    c.mul_assign(&gamma);
    c.mul_assign(&delta.inverse().unwrap());
    c.mul_assign(&g1_scale);
    c.negate();

    let proof = Proof {
        ceremony_id: CEREMONY_ID.to_string(),
        claim: CLAIM,
        inner: BellmanProof {
            a: g1(a),
            b: g2(b),
            c: g1(c),
        },
    };

    println!("{}", submit(proof)?);

    Ok(())
}
```

Jalankan:

```bash
cargo run --locked --bin solve
```

Output server:

```text
NNS{1MP05s1Bl3_pR00fs_fr0m_c3R3M0nY_45H3s}
```

## Kesimpulan

Bug utama challenge ini adalah toxic waste dari ceremony masih bisa direcover dari file `secret`.

Circuit memang membuat klaim `1_000_000_000` impossible secara witness normal, karena balance dipaksa `100`. Tapi karena `tau` bocor, kita tidak perlu witness. Kita cukup forge komponen Groth16 proof langsung dari pairing equation.

Intinya:

```text
ROT13 secret -> recover ceremony_id dan tau
tau -> derive alpha, beta, gamma, delta
tau -> compute IC0, IC1
forge A, B, C
submit proof
```

Final flag:

```text
NNS{1MP05s1Bl3_pR00fs_fr0m_c3R3M0nY_45H3s}
```
