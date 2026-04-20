# CTF Writeup — RogueCart

**Event:** JerseyCTF  
**Category:** Pwn  
**Difficulty:** Medium  
**Flag:** `jctf{r09U3_cART_hE4p_H!j4Ck}`

---

## Challenge Description

> A rescue shuttle has drifted off-course, and its onboard maintenance systems are behaving strangely. The control interface still responds, but corrupted diagnostics suggest the distress relay is pointing somewhere it shouldn’t.
>
> You’ve gained access to the shuttle’s recovery console. Analyze the binary, manipulate the maintenance systems, and recover whatever message is buried in the wreckage before the link dies.
>
> **Hint:** The input is larger than the visible buffer. Look closely at how adjacent stack fields are validated. Little endian matters.

---

## Reconnaissance

### Step 1 — Enumerate the Binary

Pertama cek properti binary:

```bash
file roguecart
checksec --file=roguecart
```

Hasil penting:
- ELF 64-bit, dynamically linked, **No PIE**
- **Canary ON**, **NX ON**, Partial RELRO
- Simbol tidak di-strip (fungsi seperti `servicePanel`, `primeShuttle`, `loadFlag` terlihat)

### Step 2 — Observe Program Behavior

Jalankan binary dan lihat menu:

```text
1. Jettison shuttle
2. Load maintenance blob
3. Broadcast distress relay
4. Exit
```

Di awal program ada leak pointer:

```text
[ SHUTTLE HANDLE: 0x... ]
```

Pointer ini ternyata adalah alamat heap object `serviceShuttle`.

### Step 3 — Identify Interesting Routines

Dari disassembly (`objdump -d -M intel roguecart`), fungsi kunci:
- `loadFlag()` membaca `flag.txt` ke `vaultChunk` (heap)
- `primeShuttle()` mengatur alokasi heap object
- `servicePanel()` menangani menu interaktif dan bug utama

---

## Exploitation

### Step 4 — Analyze Heap Layout

Di `primeShuttle()`, urutan alokasi:

1. `vaultChunk = malloc(0x40)`  
2. `spacerA = malloc(0x40)`  
3. `spacerB = malloc(0x40)`  
4. `serviceShuttle = malloc(0x40)`  
5. `serviceShuttle->relay = malloc(0x40)` (field pointer di offset `+0x20`)

Karena semua size user `0x40`, stride chunk glibc jadi `0x50`.

### Step 5 — Find the Primitive (Use-After-Free)

Di `servicePanel()`:
- Opsi `1` memanggil `free(serviceShuttle)`
- Tapi pointer global `serviceShuttle` **tidak di-null** (dangling pointer)
- Opsi `2` melakukan `malloc(0x40)` lagi untuk `maintenanceBlob` lalu `read(0, ..., 0x40)`

Karena tcache LIFO dan size sama, chunk hasil free `serviceShuttle` direuse oleh `maintenanceBlob`. Artinya input opsi `2` bisa menimpa data object `serviceShuttle` lama.

### Step 6 — Pointer Hijack to Flag Buffer

Opsi `3` menjalankan:

```c
puts(serviceShuttle->relay)
```

Strateginya: overwrite `serviceShuttle->relay` (offset `0x20`) supaya menunjuk ke `vaultChunk`.

Dari leak:
- `shuttle_handle = serviceShuttle`
- `vaultChunk` ada 3 chunk sebelumnya
- `vaultChunk = shuttle_handle - 3*0x50 = shuttle_handle - 0xF0`

Sesuai hint “Little endian matters”, pointer ditulis dengan `p64(vaultChunk)`.

Payload 64 byte:
- `0x00..0x1f`: padding
- `0x20..0x27`: pointer `vaultChunk` (little-endian)
- sisanya padding

### Step 7 — Execute Attack

Urutan menu eksploit:

1. `1` (free `serviceShuttle`)  
2. `2` (alokasi ulang chunk dan kirim payload overwrite)  
3. `3` (print distress relay yang sekarang menunjuk ke `vaultChunk`)

Hasil remote:

```text
[ DISTRESS RELAY ]
jctf{r09U3_cART_hE4p_H!j4Ck}
```

---

## Flag

```
jctf{r09U3_cART_hE4p_H!j4Ck}
```

---

## Vulnerability Summary

| # | Vulnerability | Detail |
|---|---|---|
| 1 | **Use-After-Free (UAF)** | `serviceShuttle` di-free tapi pointer global tetap dipakai |
| 2 | **Type/State Confusion via Reallocation** | `maintenanceBlob` reuse chunk freed `serviceShuttle` (size sama, tcache) |
| 3 | **Trusted Pointer Dereference** | `puts(serviceShuttle->relay)` memakai pointer yang bisa dioverwrite attacker |
| 4 | **Info Leak** | Program leak alamat `serviceShuttle` via `%p`, mempermudah hitung `vaultChunk` |

---

## Remediation

1. Setelah `free(serviceShuttle)`, set pointer ke `NULL` dan validasi sebelum dipakai lagi
2. Pisahkan lifecycle object menu agar object freed tidak bisa diakses branch lain
3. Gunakan struct integrity check (magic/version/state) sebelum dereference field pointer
4. Hindari leak alamat internal (`%p`) di build produksi
5. Tambahkan hardening logic: jika objek utama sudah di-jettison, disable opsi relay/broadcast

---

## Tools Used

- `checksec`, `file`, `strings`, `nm`, `objdump`
- `pwntools` untuk exploit automation (`exploit.py`)
- `nc` / remote socket via pwntools

---

## Attack Flow

```text
Start binary / connect remote
        │
        ▼
Read leak: [ SHUTTLE HANDLE: <serviceShuttle> ]
        │
        ▼
Compute vaultChunk = serviceShuttle - 0xF0
        │
        ▼
Menu 1: free(serviceShuttle)
        │
        ▼
Menu 2: malloc(0x40) -> reuses freed serviceShuttle chunk
        │
        ▼
Overwrite at offset 0x20 with p64(vaultChunk)
        │
        ▼
Menu 3: puts(serviceShuttle->relay)
        │
        ▼
Relay pointer now points to vaultChunk -> flag printed
```
