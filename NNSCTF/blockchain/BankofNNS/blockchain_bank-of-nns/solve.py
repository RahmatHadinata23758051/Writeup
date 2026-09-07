#!/usr/bin/env python3
import argparse
import os
import re
import socket
import ssl
import subprocess
import sys
from pathlib import Path

DEFAULT_HOST = "bank-of-nns-8f7e05c5b0c4.chall.nnsc.tf"
DEFAULT_PORT = 1337
STEP = 1 << 76
LOW_DEFAULT = 10
FLAG_RE = re.compile(r"[A-Za-z0-9_{}\-]+\{[^\n{}]{4,}\}")

BASE_DIR = Path(__file__).resolve().parent
GEN = BASE_DIR / "src" / "bin" / "gen_proof.rs"

GEN_SRC = r'''
use ark_ff::{BigInteger, PrimeField, Zero};
use base64::{engine::general_purpose::STANDARD, Engine};
use groupmap::GroupMap;
use kimchi::{circuits::polynomial::COLUMNS, proof::ProverProof, verifier::verify};
use mina_curves::pasta::{Fp, Vesta, VestaParameters};
use mina_poseidon::{
    constants::PlonkSpongeConstantsKimchi as SC,
    pasta::FULL_ROUNDS,
    sponge::{DefaultFqSponge, DefaultFrSponge},
};
use num_bigint::BigUint;
use poly_commitment::{commitment::CommitmentCurve, ipa::OpeningProof};
use std::env;

#[path = "../challenge.rs"]
mod challenge;

type BaseSponge = DefaultFqSponge<VestaParameters, SC, FULL_ROUNDS>;
type ScalarSponge = DefaultFrSponge<Fp, SC, FULL_ROUNDS>;
type Opening = OpeningProof<Vesta, FULL_ROUNDS>;

fn fp_to_big(f: Fp) -> BigUint {
    BigUint::from_bytes_le(&f.into_bigint().to_bytes_le())
}

fn fp_from_big(n: &BigUint) -> Fp {
    Fp::from_le_bytes_mod_order(&n.to_bytes_le())
}

fn low_u64(n: &BigUint) -> u64 {
    n.to_u64_digits().get(0).copied().unwrap_or(0)
}

fn limb(amount: &BigUint, shift: usize, mask: u64) -> u64 {
    let v = (amount >> shift) & BigUint::from(mask);
    low_u64(&v)
}

fn settlement_row(amount_big: &BigUint) -> ([Fp; COLUMNS], Fp) {
    let amount = fp_from_big(amount_big);
    if fp_to_big(amount) != *amount_big {
        eprintln!("amount is outside canonical Fp range; choose a smaller amount");
        std::process::exit(2);
    }
    let middle_12 = limb(amount_big, 64, 0xfff);
    if middle_12 != 0 {
        eprintln!("amount is not provable by the broken 64-bit check: bits 64..75 must be zero");
        std::process::exit(2);
    }

    let mut row = [Fp::zero(); COLUMNS];
    row[0] = amount;
    row[1] = fp_from_big(&(amount_big >> 76usize));
    row[2] = Fp::zero();

    for (i, shift) in [52usize, 40, 28, 16].iter().enumerate() {
        row[3 + i] = Fp::from(limb(amount_big, *shift, 0xfff));
    }
    for i in 0..8usize {
        row[7 + i] = Fp::from(limb(amount_big, 14 - 2 * i, 0x3));
    }
    (row, amount)
}

fn main() {
    let amount_arg = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: cargo run --release --bin gen_proof -- <amount>");
        std::process::exit(2);
    });
    let amount_big: BigUint = amount_arg.parse().unwrap_or_else(|_| {
        eprintln!("invalid decimal amount: {amount_arg}");
        std::process::exit(2);
    });

    let (row, amount) = settlement_row(&amount_big);
    let public = vec![amount, Fp::zero()];
    let witness: [Vec<Fp>; COLUMNS] = core::array::from_fn(|c| {
        vec![if c == 0 { amount } else { Fp::zero() }, Fp::zero(), row[c]]
    });

    let index = challenge::prover_index();
    let group_map = <Vesta as CommitmentCurve>::Map::setup();
    eprintln!("[+] proving exploit amount {}", amount_arg);

    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ProverProof::create::<BaseSponge, ScalarSponge, _>(
            &group_map,
            witness,
            &[],
            &index,
            &mut rand::rngs::OsRng,
        )
    }));
    std::panic::set_hook(hook);

    let Ok(Ok(proof)) = attempt else {
        eprintln!("the settlement circuit rejected this witness");
        std::process::exit(1);
    };
    if verify::<FULL_ROUNDS, Vesta, BaseSponge, ScalarSponge, Opening>(
        &group_map,
        &index.verifier_index(),
        &proof,
        &public,
    )
    .is_err()
    {
        eprintln!("the proof did not verify locally");
        std::process::exit(1);
    }

    let bytes = rmp_serde::to_vec(&proof).expect("serialize proof");
    println!("settle {} {}", amount_arg, STANDARD.encode(&bytes));
}
'''.lstrip()


def ensure_generator() -> None:
    GEN.parent.mkdir(parents=True, exist_ok=True)
    if not GEN.exists() or GEN.read_text() != GEN_SRC:
        GEN.write_text(GEN_SRC)


def recv_some(sock: ssl.SSLSocket, timeout: float = 1.0, total_timeout: float = 5.0) -> str:
    sock.settimeout(timeout)
    out = bytearray()
    import time
    end = time.time() + total_timeout
    while time.time() < end:
        try:
            chunk = sock.recv(8192)
            if not chunk:
                break
            out.extend(chunk)
            if b"nns>" in out.lower() or b"goodbye" in out.lower() or b"flag" in out.lower():
                # keep reading briefly for trailing lines
                continue
        except (socket.timeout, TimeoutError):
            break
    return out.decode("utf-8", "replace")


def talk(host: str, port: int, commands, timeout: float = 30.0) -> str:
    ctx = ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            banner = recv_some(s, timeout=0.7, total_timeout=2.5)
            for cmd in commands:
                if not cmd.endswith("\n"):
                    cmd += "\n"
                s.sendall(cmd.encode())
            reply = recv_some(s, timeout=1.0, total_timeout=timeout)
            return banner + reply


def generate_settle(amount: int) -> str:
    ensure_generator()
    cmd = ["cargo", "run", "--release", "--quiet", "--bin", "gen_proof", "--", str(amount)]
    print(f"[+] generating proof for amount {amount}", file=sys.stderr)
    p = subprocess.run(cmd, cwd=BASE_DIR, text=True, capture_output=True)
    if p.stderr:
        print(p.stderr, end="", file=sys.stderr)
    if p.returncode != 0:
        raise RuntimeError(f"proof generator failed with exit {p.returncode}")
    for line in p.stdout.splitlines():
        if line.startswith("settle "):
            return line
    raise RuntimeError("proof generator did not print a settle line")


def extract_numbers(text: str):
    # Prefer numbers printed near words that usually describe the vault/balance.
    scored = []
    for m in re.finditer(r"\d+", text.replace(",", "")):
        n = int(m.group(0))
        window = text[max(0, m.start() - 60): m.end() + 60].lower()
        score = 0
        for word in ("vault", "balance", "fund", "reserve", "bank"):
            if word in window:
                score += 5
        if n >= 100:
            score += 1
        scored.append((score, n, window))
    scored.sort(reverse=True)
    return scored


def valid_amount_with_low(high: int, low: int) -> int:
    return high * STEP + low


def provable_at_least(target: int, low: int) -> int:
    high = max(1, (target - low + STEP - 1) // STEP)
    return valid_amount_with_low(high, low)


def provable_at_most(target: int, low: int) -> int | None:
    if target < low:
        return None
    high = (target - low) // STEP
    if high <= 0:
        return None
    return valid_amount_with_low(high, low)


def build_candidates(banner: str, low: int):
    candidates = []
    seen = set()

    def add(x):
        if x and x > 0 and ((x >> 64) & 0xfff) == 0 and x not in seen:
            seen.add(x)
            candidates.append(x)

    for _, n, _ in extract_numbers(banner)[:4]:
        # Try exact if the displayed vault value already satisfies the broken circuit shape.
        add(n)
        add(provable_at_most(n, low))
        add(provable_at_least(n, low))

    # Generic exploit amounts.  All have bits 64..75 clear and low64 == low.
    add((1 << 76) + low)
    add((1 << 88) + low)
    add((1 << 100) + low)
    add((1 << 120) + low)
    add(((1 << 52) - 1) * STEP + low)  # largest u128-shaped candidate with c2 == 0
    return candidates


def find_flag(text: str):
    if "flag" in text.lower():
        for line in text.splitlines():
            if "flag" in line.lower() or "ctf" in line.lower() or "nns" in line.lower():
                m = FLAG_RE.search(line)
                if m:
                    return m.group(0)
        m = FLAG_RE.search(text)
        if m:
            return m.group(0)
    else:
        m = FLAG_RE.search(text)
        if m:
            return m.group(0)
    return None


def main():
    ap = argparse.ArgumentParser(description="Exploit Bank of NNS broken Kimchi 64-bit range check")
    ap.add_argument("host", nargs="?", default=os.environ.get("HOST", DEFAULT_HOST))
    ap.add_argument("port", nargs="?", type=int, default=int(os.environ.get("PORT", DEFAULT_PORT)))
    ap.add_argument("--amount", type=int, help="single decimal amount to prove and submit")
    ap.add_argument("--low", type=int, default=int(os.environ.get("LOW", LOW_DEFAULT)), help="low 64-bit amount; default 10")
    ap.add_argument("--max-tries", type=int, default=5)
    args = ap.parse_args()

    print(f"[+] target: {args.host}:{args.port}")
    try:
        banner = talk(args.host, args.port, ["quit"], timeout=8.0)
    except Exception as e:
        print(f"[!] banner probe failed: {e}", file=sys.stderr)
        banner = ""
    if banner.strip():
        print("[+] banner/probe:")
        print(banner.strip())

    if args.amount is not None:
        candidates = [args.amount]
    else:
        candidates = build_candidates(banner, args.low)

    print("[+] candidate amounts:")
    for x in candidates[:args.max_tries]:
        print(f"    {x}")

    last_reply = ""
    for amount in candidates[:args.max_tries]:
        try:
            settle = generate_settle(amount)
            print(f"[+] submitting amount {amount}")
            reply = talk(args.host, args.port, [settle, "quit"], timeout=45.0)
            last_reply = reply
            print(reply.strip())
            flag = find_flag(reply)
            if flag:
                print(f"\n<FLAG>{flag}</FLAG>")
                return
            low_reply = reply.lower()
            if "insufficient" in low_reply or "too much" in low_reply or "not enough" in low_reply:
                print("[*] service says amount was too high; trying next candidate", file=sys.stderr)
                continue
            if "daily" in low_reply or "limit" in low_reply:
                print("[*] daily-limit response seen; the low64 component may need adjustment", file=sys.stderr)
                continue
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"[-] failed for amount {amount}: {e}", file=sys.stderr)

    print("[-] flag not recovered automatically.")
    if last_reply:
        print("[+] last reply was:")
        print(last_reply)
    print("[*] Try an exact displayed vault amount with: python3 solve.py --amount <amount>")


if __name__ == "__main__":
    main()
