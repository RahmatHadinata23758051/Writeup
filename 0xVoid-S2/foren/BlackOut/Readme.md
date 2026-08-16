# BlackOut — Full Walkthrough

## Ringkasan

Challenge BlackOut berisi artefak insiden forensik: endpoint logs, network logs, memory strings, encrypted loader configuration, dan relay payload terenkripsi. Tujuannya bukan hanya mencari satu flag, tapi menyusun rantai intrusi dari awal sampai payload relay terakhir.

Dari lima pertanyaan stage, hasil akhirnya:

| No. | Pertanyaan | Jawaban |
|---|---|---|
| 1 | Compromised user, workstation, first payload | `0xV01D{nova0x_NOVA-FIN-044_invoice_0814.lnk}` |
| 2 | Defense evasion command dan recovery removal command | `0xV01D{Set-MpPreference_vssadmin_delete_shadows}` |
| 3 | Campaign value hidden in DNS TXT records | `0xV01D{void-ops_august-red}` |
| 4 | Loader config family dan C2 endpoint | `0xV01D{oxide_loader_198.51.100.42_8080}` |
| 5 | Final relay objective dan session | `0xV01D{blackout_key_recovered_from_memory_and_relay_stream_7f4d9b2c}` |

Alur besarnya:

1. Endpoint logs menunjukkan user `nova0x` di host `NOVA-FIN-044` menjalankan payload awal `invoice_0814.lnk`.
2. Log proses menunjukkan operator mematikan proteksi Defender dan menghapus shadow copies.
3. DNS TXT fragments berisi potongan Base64 yang jika disusun membentuk campaign value.
4. Campaign value + device + session dipakai untuk derive key dan decrypt loader config `oxide_loader.config.enc`.
5. Key config dipakai lagi untuk derive final relay key, lalu decrypt relay payload untuk mendapatkan objective final.

## File Challenge

Struktur artefak utama:

```
BlackOut/
├── CASE_BRIEF.txt
├── STAGE_PROMPTS.txt
├── evidence/
│   ├── Endpoint/
│   │   ├── Security/
│   │   │   └── Security_4688.csv
│   │   ├── PowerShell/
│   │   └── Sysmon/
│   │       └── Microsoft-Windows-Sysmon_Operational.evtx.xml
│   ├── Malware/
│   │   └── oxide_loader.config.enc
│   ├── Memory/
│   │   └── NOVA-FIN-044_strings.bin
│   └── Network/
│       ├── Zeek/
│       │   ├── conn.log.csv
│       │   ├── dns.log.csv
│       │   └── http.log.csv
│       └── relay_stream_8080.bin
```

File yang paling penting:

- `CASE_BRIEF.txt`: konteks host dan user.
- `Security_4688.csv`: process creation Windows Event ID 4688.
- `Microsoft-Windows-Sysmon_Operational.evtx.xml`: detail process execution, parent-child process, command line.
- `dns.log.csv`: DNS TXT fragments.
- `NOVA-FIN-044_strings.bin`: memory fragments berisi session, device, nonce, dan hint derivasi key.
- `oxide_loader.config.enc`: encrypted loader configuration.
- `relay_stream_8080.bin`: relay payload terenkripsi di dalam WebSocket + gzip.

## Tools yang Dipakai

Tools lokal yang cukup:

```bash
unzip blackout.zip
find . -type f
strings -a evidence/Memory/NOVA-FIN-044_strings.bin
python3 solve_blackout.py
```

Library Python yang dipakai solver:

```
base64
re
json
gzip
hmac
hashlib
cryptography
```

## Stage 1 — Compromised User, Workstation, dan First Payload

### Tujuan

Pertanyaan:

```
Find the compromised user, workstation, and first payload.
Submit format: 0xV01D{user_host_payload}
```

### Analisis

Dari brief dan endpoint logs, workstation korban adalah:

```
NOVA-FIN-044
```

User yang muncul pada workstation tersebut:

```
THRYVE\nova0x
```

Untuk format flag, domain `THRYVE\` tidak dipakai, jadi user-nya:

```
nova0x
```

Payload awal terlihat dari path Downloads:

```
C:\Users\nova0x\Downloads\invoice_0814.lnk
```

Log proses menunjukkan payload ini dijalankan melalui LOLBin `mshta.exe`:

```
mshta.exe "C:\Users\nova0x\Downloads\invoice_0814.lnk"
```

Relay final juga menguatkan bahwa initial payload chain adalah:

```
invoice_0814.lnk -> signed_update.hta
```

Karena yang diminta adalah first payload, yang dipakai adalah file pertama dalam chain:

```
invoice_0814.lnk
```

### Flag Stage 1

```
0xV01D{nova0x_NOVA-FIN-044_invoice_0814.lnk}
```

## Stage 2 — Defense Evasion Command dan Recovery Removal Command

### Tujuan

Pertanyaan:

```
Identify the defense evasion command and the recovery removal command.
Submit format: 0xV01D{defender_command_shadow_command}
```

### Analisis

Ada dua command penting di endpoint logs.

Command pertama mematikan proteksi Defender:

```
Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true
```

Command kedua menghapus recovery/shadow copies:

```
vssadmin delete shadows /all /quiet
```

Untuk format submit, challenge tidak meminta full argument string, tapi nama command utama dan aksi shadow command.

Jadi token yang dipakai:

```
Set-MpPreference
vssadmin_delete_shadows
```

### Flag Stage 2

```
0xV01D{Set-MpPreference_vssadmin_delete_shadows}
```

## Stage 3 — Campaign Value dari DNS TXT Records

### Tujuan

Pertanyaan:

```
Recover the campaign value hidden in DNS TXT records.
Submit format: 0xV01D{campaign_value}
```

### Analisis

Di `dns.log.csv`, ditemukan query TXT ke subdomain `voidcdn.net` dengan index fragment:

```
_0.k984.voidcdn.net
_1.k984.voidcdn.net
_2.k984.voidcdn.net
```

Masing-masing TXT record menyimpan potongan Base64:

```
_0 -> dm9pZC1vcHMv
_1 -> YXVndXN0LXJl
_2 -> ZA==
```

Decode Base64:

```
dm9pZC1vcHMv -> void-ops/
YXVndXN0LXJl -> august-re
ZA==         -> d
```

Jika digabung:

```
void-ops/august-red
```

Namun format flag memakai underscore sebagai separator. Slash `/` dinormalisasi menjadi `_`, sementara hyphen `-` tetap dipertahankan.

```
void-ops/august-red -> void-ops_august-red
```

### Script Decode Singkat

```python
import base64

parts = [
    "dm9pZC1vcHMv",
    "YXVndXN0LXJl",
    "ZA==",
]

campaign = b"".join(base64.b64decode(x) for x in parts).decode()
print(campaign)
print(campaign.replace("/", "_"))
```

Output:

```
void-ops/august-red
void-ops_august-red
```

### Flag Stage 3

```
0xV01D{void-ops_august-red}
```

## Stage 4 — Decrypt Loader Configuration, Family, dan C2 Endpoint

### Tujuan

Pertanyaan:

```
Decrypt the loader configuration and identify the config family and C2 endpoint.
Submit format: 0xV01D{family_c2host_port}
```

### Artefak Penting

File config terenkripsi:

```
evidence/Malware/oxide_loader.config.enc
```

Network logs menunjukkan endpoint C2:

```
198.51.100.42:8080
```

Memory strings berisi material derivasi key:

```
session=7f4d9b2c-a9e1-4a71-bd44-70b2f4d0c661
device=NOVA-FIN-044|aws_afaneh
hkdf-sha256(campaign+device, session, oxide-loader/config/v3)
registry nonce cache: 2fd4c0b88e7153164ac09e77f1a2b3c4
```

### Format Config

Header file config:

```
OXID | version | nonce_length | nonce | ciphertext
```

Magic `OXID` menandai blob config, tetapi family yang dipakai checker berasal dari nama artefak/config family:

```
oxide_loader
```

Bukan:

```
OXID
oxid
oxide
oxide-loader
oxide-loader/v3
```

### Key Derivation

Campaign dari Stage 3 dipakai sebagai input HKDF.

Campaign mentah untuk key derivation tetap memakai slash:

```
void-ops/august-red
```

Device dari memory:

```
NOVA-FIN-044|aws_afaneh
```

Session dari memory:

```
7f4d9b2c-a9e1-4a71-bd44-70b2f4d0c661
```

Key config:

```python
HKDF-SHA256(
    ikm = campaign + b"|" + device,
    salt = session,
    info = b"oxide-loader/config/v3",
    length = 32,
)
```

Catatan penting: ada separator `b"|"` antara campaign dan device.

### Decrypt AES-CTR

Config didecrypt dengan AES-CTR:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

plaintext = Cipher(
    algorithms.AES(config_key),
    modes.CTR(nonce),
).decryptor().update(ciphertext)
```

Plaintext config berisi JSON seperti ini:

```json
{
  "case": "VOID-2026-0814",
  "host": "NOVA-FIN-044",
  "operator": "not-afaneh",
  "staging_user": "nova0x",
  "disable_chain": "Set-MpPreference -> reg add TamperProtection -> vssadmin",
  "stage4_flag": "0xV01D{heap_nonce_and_session_unwrapped_oxide_config}"
}
```

C2 endpoint dikonfirmasi dari Zeek HTTP/conn log:

```
198.51.100.42:8080
```

### Flag Stage 4

```
0xV01D{oxide_loader_198.51.100.42_8080}
```

## Stage 5 — Decrypt Final Relay Payload dan Recover Operator Objective

### Tujuan

Pertanyaan:

```
Decrypt the final relay payload and recover the operator objective.
Submit format: 0xV01D{objective_session}
```

### Artefak Penting

Relay payload:

```
evidence/Network/relay_stream_8080.bin
```

Memory hint:

```
relay-final uses hmac(config_key, blackout-final|session)
```

### Parsing Relay Stream

File relay adalah WebSocket binary frame.

Struktur awal:

```
0x82 0x7e <u16 length> <gzip payload>
```

Langkah decode:

1. Ambil payload WebSocket.
2. Gzip decompress.
3. Hasilnya blob dengan magic `TRLY`.
4. Parse nonce dan ciphertext.
5. Derive final key dari `config_key`.
6. AES-CTR decrypt.

### Final Key Derivation

Final key dibuat dari `config_key` yang sudah didapat di Stage 4:

```python
final_key = HMAC-SHA256(
    key = config_key,
    msg = b"blackout-final|" + session,
)
```

Lalu relay ciphertext didecrypt dengan AES-CTR.

### Relay Plaintext

Hasil decrypt relay:

```json
{
  "incident": "blackout",
  "recovered_user": "nova0x",
  "initial_payload": "invoice_0814.lnk -> signed_update.hta",
  "defender_disable": "Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true",
  "encryption_key_location": "HKCU\\Software\\Classes\\CLSID\\{8b70-void}\\InprocServer32\\ThreadingModel",
  "flag": "0xV01D{blackout_key_recovered_from_memory_and_relay_stream_7f4d9b2c}"
}
```

Operator objective yang diminta di format challenge adalah bagian sebelum session:

```
blackout_key_recovered_from_memory_and_relay_stream
```

Session pendek yang dipakai adalah prefix dari session UUID:

```
7f4d9b2c
```

### Flag Stage 5

```
0xV01D{blackout_key_recovered_from_memory_and_relay_stream_7f4d9b2c}
```
