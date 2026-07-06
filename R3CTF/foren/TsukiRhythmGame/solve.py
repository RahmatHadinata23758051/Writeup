#!/usr/bin/env python3
import hashlib
import json
import marshal
from pathlib import Path

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from eth_account import Account
from PIL import Image


BASE_URL = "http://challenge.ctf2026.r3kapig.com:31702"
GAME_EXE = Path("Game/TsukiRhythmGame.exe")
EGGDRASIL = Path("Game/charts/Eggdrasil.tsuki")
STREAM31_CLIENT = Path("stream31_client.bin")
STREAM31_SERVER = Path("stream31_server.bin")
CACHE_BIN = Path("Evidence_extracted/Cache0000.bin")

BEATMAP_KEY = b"TsukiRhythmKey!!"
BEATMAP_IV = b"TsukiRhythmIV!!!"
INITIAL_XOR_KEY = bytes.fromhex("1337c0de")
SEED_PHRASE = "labor trophy emerge material divorce input faint bench cricket merge sunset cream"

Account.enable_unaudited_hdwallet_features()


def md5_file(path: Path) -> str:
    return hashlib.md5(path.read_bytes()).hexdigest()


def decrypt_beatmap(path: Path) -> dict:
    data = path.read_bytes()
    plain = unpad(AES.new(BEATMAP_KEY, AES.MODE_CBC, BEATMAP_IV).decrypt(data), 16)
    return json.loads(plain.decode())


def hidden_payload_md5() -> str:
    beatmap = decrypt_beatmap(EGGDRASIL)
    notes = [n for n in beatmap["notes"] if n.get("type") == 99]
    bits = []
    for note in notes:
        lane = note["lane"]
        bits.extend([(lane >> 1) & 1, lane & 1])
    payload = bytearray()
    for i in range(0, len(bits), 8):
        value = 0
        for bit in bits[i:i + 8]:
            value = (value << 1) | bit
        payload.append(value)
    marshal.loads(bytes(payload))
    return hashlib.md5(bytes(payload)).hexdigest()


def parse_length_prefixed(path: Path) -> list[bytes]:
    data = path.read_bytes()
    items = []
    pos = 0
    while pos + 4 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        pos += 4
        items.append(data[pos:pos + length])
        pos += length
    return items


def recover_hh_exe() -> bytes:
    first_message = parse_length_prefixed(STREAM31_CLIENT)[0]
    return bytes(b ^ INITIAL_XOR_KEY[i % 4] for i, b in enumerate(first_message))


def build_index_map(hh_bytes: bytes) -> dict[int, int]:
    mapping = {}
    seen = set()
    for index, value in enumerate(hh_bytes):
        if value not in seen:
            seen.add(value)
            mapping[index] = value
    return mapping


def decode_numeric_payload(payload: bytes, idx_to_byte: dict[int, int]) -> bytes:
    numbers = [int(part) for part in payload.decode().split(".") if part]
    out = bytearray()
    for number in numbers:
        if number < 0:
            out.append((-number) & 0xFF)
        else:
            out.append(idx_to_byte[number])
    return bytes(out)


def decrypt_c2_packet(packet: bytes) -> str:
    a, middle, c = packet[:16], packet[16:-16], packet[-16:]
    plain = unpad(AES.new(a, AES.MODE_CBC, c).decrypt(middle), 16)
    return plain.decode()


def rdp_cache_seed_phrase() -> str:
    # Analyst-side recovery from the RDP tile cache contact sheet.
    # The cache still contains the MetaMask recovery phrase screen.
    if not CACHE_BIN.exists():
        return SEED_PHRASE
    data = CACHE_BIN.read_bytes()
    records = (len(data) - 12) // 16396
    out_dir = Path("tiles")
    out_dir.mkdir(exist_ok=True)
    saved = []
    for i in range(records):
        off = 12 + i * 16396
        dims = int.from_bytes(data[off + 8:off + 12], "little")
        width = (dims >> 16) & 0xFFFF
        height = dims & 0xFFFF
        pixels = data[off + 12:off + 12 + 16384]
        image = Image.frombytes("RGBA", (width, height), pixels, "raw", "BGRA")
        colors = image.convert("RGB").getcolors(maxcolors=4096)
        if colors is not None and len(colors) <= 4:
            continue
        path = out_dir / f"{i:04d}.png"
        image.save(path)
        saved.append(path)
        if len(saved) >= 888:
            break
    return SEED_PHRASE


def derive_wallet_address(seed_phrase: str) -> str:
    account = Account.from_mnemonic(seed_phrase, account_path="m/44'/60'/0'/0/0")
    return account.address


def answers() -> list[str]:
    hh_bytes = recover_hh_exe()
    idx_to_byte = build_index_map(hh_bytes)
    server_messages = parse_length_prefixed(STREAM31_SERVER)
    client_messages = parse_length_prefixed(STREAM31_CLIENT)

    first_command = decrypt_c2_packet(decode_numeric_payload(server_messages[0], idx_to_byte))
    whoami_result = decrypt_c2_packet(decode_numeric_payload(client_messages[2], idx_to_byte)).strip()
    seed_phrase = rdp_cache_seed_phrase()
    wallet_address = derive_wallet_address(seed_phrase)

    return [
        md5_file(GAME_EXE),
        "TsukiRhythmKey!!_TsukiRhythmIV!!!",
        hidden_payload_md5(),
        "4444",
        r"C:\Windows\hh.exe",
        hashlib.md5(hh_bytes).hexdigest(),
        first_command,
        whoami_result,
        "aurahack_P@ssw0rd",
        seed_phrase.split()[6],
        wallet_address,
    ]


def submit_all() -> None:
    session = requests.Session()
    session.get(f"{BASE_URL}/", timeout=10)
    solved_answers = answers()
    for index, answer in enumerate(solved_answers, start=1):
        response = session.post(
            f"{BASE_URL}/api/submit",
            json={"answer": answer},
            timeout=10,
        )
        data = response.json()
        print(f"Q{index}: {answer}")
        print(json.dumps(data, indent=2))
        if not data.get("correct"):
            raise SystemExit(f"wrong answer at question {index}")
        if data.get("finished"):
            print(data["flag"])
            return


if __name__ == "__main__":
    submit_all()
