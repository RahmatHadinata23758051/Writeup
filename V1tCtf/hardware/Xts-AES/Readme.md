# XTS-AES

## Ringkasan

`BLOCK_KEY0` memang tidak dapat dibaca, tetapi provisioning firmware yang bocor masih menyimpan seluruh proses derivasi kunci. Kunci AES-XTS direkonstruksi dari `BLOCK_USR_DATA`, konstanta HMAC di firmware, dan MAC perangkat. Partisi `flagdata` kemudian didekripsi dengan format tweak milik hardware flash encryption ESP32-S3.

Flag:

```text
V1T{7h15_5h1d_k1nd4_h4rd_1kn0w}
```

## File yang diberikan

```text
flash_dump.bin               raw flash dump, 4 MiB
leaked_debug_firmware.bin    ELF Xtensa ESP32-S3, stripped
efuse_sum.json               output espefuse summary
```

Triage awal:

```bash
file leaked_debug_firmware.bin flash_dump.bin efuse_sum.json
strings -a leaked_debug_firmware.bin | grep -Ei 'provision|USR_DATA|PBKDF2|XTS|flagdata'
```

String penting dari firmware:

```text
V1T PROVISIONING TOOL v2.1
reading BLOCK_USR_DATA (24 bytes)... ok
step 1: hmac-sha256 digest (32 bytes)
step 2: pbkdf2-hmac-sha256
burning derived key to BLOCK_KEY0
key_purpose  : XTS_AES_128_KEY
writing flag data to partition 'flagdata'... ok
```

## Informasi eFuse

Field yang relevan:

```text
KEY_PURPOSE_0      = XTS_AES_128_KEY
BLOCK_KEY0         = read-protected
SPI_BOOT_CRYPT_CNT = Enable
MAC                = d0:cf:13:2f:36:c8
```

`BLOCK_USR_DATA` masih readable:

```text
ee d8 22 f5 40 24 e4 90 e5 9c a5 e6 70 78 4a 5d
 aa 1f 04 fd 07 78 73 53 00 00 00 00 00 00 00 00
```

Firmware hanya memakai 24 byte pertama:

```text
eed822f54024e490e59ca5e670784a5daa1f04fd07787353
```

## Reverse provisioning firmware

Xref dari string log derivasi membawa ke helper KDF. Konstanta HMAC 16 byte tersimpan di firmware:

```text
855780fc45bce8878d68f0040630cdbb
```

Rantai derivasi yang dipakai:

```python
digest = HMAC_SHA256(
    key=bytes.fromhex("855780fc45bce8878d68f0040630cdbb"),
    message=BLOCK_USR_DATA[:24],
)

xts_key = PBKDF2_HMAC_SHA256(
    password=digest,
    salt=bytes.fromhex("d0cf132f36c8"),
    iterations=4096,
    output_length=32,
)
```

Hasilnya:

```text
HMAC digest:
b783262211c7eb5996cc376f236761b184ad9a6260f9d5fa96ed4f3972579b7b

AES-XTS key:
3c0c3d36a5f470de0bb31bffb7cf4e1f2cc68b04868d0482c408a218976797ce
```

`XTS_AES_128_KEY` berarti dua key AES 128-bit, sehingga material yang diperlukan memang 32 byte.

## Mencari partisi flag

Partition table berada dalam keadaan plaintext di offset `0x8000`. Setiap entry berukuran 32 byte dengan magic `aa 50`.

```bash
od -Ax -tx1z -v -j $((0x8000)) -N 256 flash_dump.bin
```

Entry `flagdata`:

```text
aa 50 01 40 00 30 11 00 00 10 00 00 66 6c 61 67
64 61 74 61 00 00 00 00 00 00 00 00 00 00 00 00
```

Parsing little-endian:

```text
type    = 0x01
subtype = 0x40
offset  = 0x113000
size    = 0x1000
label   = flagdata
```

## Detail AES-XTS ESP32-S3

Dekripsi tidak cukup memakai AES-XTS standar dengan nomor sektor biasa. Flash encryption ESP32-S3 memakai aturan berikut:

- Data diproses per unit `0x80` byte.
- Tweak adalah `LE32(physical_address & ~0x7f) || 12 null bytes`.
- Seluruh unit 128 byte dibalik sebelum operasi XTS.
- Hasil XTS dibalik lagi setelah dekripsi.

Pseudocode:

```python
for block in encrypted_partition.chunks(0x80):
    tweak = p32(address & ~0x7f) + b"\x00" * 12
    plaintext = AES_XTS_DECRYPT(key, tweak, block[::-1])[::-1]
    address += 0x80
```

Dekripsi `flash_dump.bin[0x113000:0x114000]` menghasilkan:

```text
V1T{7h15_5h1d_k1nd4_h4rd_1kn0w}\x00\xff\xff\xff...
```

## Solver

Dependency:

```bash
source /home/nata/ctf_env/bin/activate
pip install cryptography
```

Jalankan:

```bash
python3 solve.py
```

Output:

```text
[+] BLOCK_USR_DATA[:24]: eed822f54024e490e59ca5e670784a5daa1f04fd07787353
[+] MAC salt:              d0cf132f36c8
[+] HMAC digest:           b783262211c7eb5996cc376f236761b184ad9a6260f9d5fa96ed4f3972579b7b
[+] AES-XTS key:           3c0c3d36a5f470de0bb31bffb7cf4e1f2cc68b04868d0482c408a218976797ce
[+] flagdata:              offset=0x113000, size=0x1000
[+] flag:                  V1T{7h15_5h1d_k1nd4_h4rd_1kn0w}
```
