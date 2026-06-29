# Herd Mentality — Reverse Engineering Writeup

## Informasi challenge

- CTF: V1T CTF 2026
- Kategori: Reverse
- File: `Herd.exe`, `Orchestrator.exe`
- Deskripsi: `if you know what i know, hide your ho, big cups, i’m sippin' flamingo`
- Flag: `v1t{1m_th3_r34l_k1ng_0f_th3_duck_p0nd}`

## Triage

```bash
unzip -l HerdMentality.zip
unzip HerdMentality.zip
file HerdMentality/Herd.exe HerdMentality/Orchestrator.exe
strings -a HerdMentality/Orchestrator.exe | less
strings -a HerdMentality/Herd.exe | less
```

Arsip berisi dua PE x64. `Orchestrator.exe` membuat shared memory bernama `Global\HerdPond_v2`, lalu menjalankan banyak instance `Herd.exe`. Child process tidak mencetak potongan flag secara langsung. Semuanya berkomunikasi melalui satu area shared memory berukuran `0x2000` byte.

Layout yang relevan:

| Offset | Isi |
|---|---|
| `0x04` | seed pond |
| `0x08` | state utama |
| `0x0c` | state sekunder |
| `0x14` | nomor event terakhir |
| `0x18` | baseline event crown aktif |
| `0x1c` | crown aktif |
| `0x20` | crown yang siap dipromosikan |
| `0x24` | bitmask shard yang terbuka |
| `0x36` | enam indeks kandidat crown |
| `0x40` | enam record plaintext shard |
| `0x238` | 100 slot proses, masing-masing 24 byte |
| `0xb98` | ring buffer 128 event, masing-masing 20 byte |

## Pembagian role

Fungsi `Herd.exe+0x1390` mengubah indeks slot menjadi role. Satu slot menjadi kandidat crown aktif. Slot lainnya dibagi melalui tiga set relasi pseudo-random:

```text
role 1 = kandidat crown aktif
role 5 = relation depth 0 / keeper
role 2 = relation depth 1 / message-bearer
role 3 = relation depth 2 / reflection
role 4 = anggota herd biasa
role 0 = slot mati atau tidak aktif
```

Set tersebut bukan random rahasia. Inputnya hanya seed, state, nomor crown, tabel step statis, dan daftar kandidat yang semuanya ada di shared memory. Ukuran ketiga set adalah 10, 15, dan 20 slot.

Mixer yang dipakai berulang kali:

```python
def mix(x):
    x &= 0xffffffff
    x ^= x >> 16
    x = x * 0x7feb352d & 0xffffffff
    x ^= x >> 15
    x = x * 0x846ca68b & 0xffffffff
    x ^= x >> 16
    return x & 0xffffffff
```

## Packet crown

`Herd.exe+0x1680` membangun packet validasi crown dari event setelah baseline. Tiap aturan disimpan sebagai triple:

```text
(event_type, role, jumlah)
```

Hasil decode enam crown:

| Crown | Event yang dibutuhkan |
|---|---|
| 0 | tidak ada |
| 1 | event 1, role 2, satu kali |
| 2 | event 2, role 3, dua kali |
| 3 | event 3, role 5, satu kali |
| 4 | event 2 role 4 satu kali, lalu event 1 role 3 satu kali |
| 5 | event 3 role 2 satu kali, lalu event 1 role 5 satu kali |

Makna event terlihat dari health monitor milik orchestrator:

- Event 1: proses terpantau atau mendeteksi debugger.
- Event 2: proses hilang atau berhenti.
- Event 3: proses masih ada tetapi tidak lagi memperbarui tick.

Satu record event berukuran 20 byte. Dua field integritasnya hanya memakai state publik:

```text
event.pid_hash   = mix(pid ^ seed ^ sequence)
event.token_hash = mix(token ^ state ^ event_type)
```

Tidak ada secret yang hanya dimiliki orchestrator. Record valid bisa dibuat offline selama role dan token slot dihitung dengan fungsi yang sama.

## Membuka shard

Fungsi `Herd.exe+0x22f0` menerima nomor crown, role, dan packet. Satu pemanggilan hanya memperoleh salah satu dari dua half-record. Selector half bergantung pada slot, role, state, dan digest packet. Solver memanggil fungsi yang sama untuk beberapa slot sampai kedua half terkumpul.

Saat kedua half tersedia, fungsi tersebut mendekripsi blob statis dan menulis plaintext ke record crown di offset `0x40 + 40 * crown`. Crown selain yang pertama juga mengisi field `next crown`, sehingga `Orchestrator.exe+0x2530` dapat mempromosikan state.

Promosi tidak menghapus shard yang sudah selesai. Fungsi itu:

1. memindahkan crown aktif;
2. menjadikan event sequence saat ini sebagai baseline baru;
3. memperbarui state memakai mixer yang sama;
4. membersihkan record crown setelah posisi aktif.

## Solver

`solve.py` tidak membutuhkan Wine dan tidak menjalankan seratus proses. Kedua PE dibaca langsung dari ZIP dan fungsi internalnya dijalankan dengan Unicorn.

Alurnya:

1. Buat shared memory deterministik dan isi 100 slot proses palsu.
2. Jalankan fungsi pemilih kandidat asli dari `Orchestrator.exe`.
3. Hitung role seluruh slot dari seed dan state.
4. Buat event ring yang memenuhi aturan crown aktif.
5. Jalankan packet builder asli dari `Herd.exe`.
6. Panggil fungsi shard untuk beberapa slot sampai dua half didapat.
7. Jalankan fungsi promosi asli, lalu ulangi sampai crown keenam.

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
pip install pefile unicorn
python3 solve.py HerdMentality.zip --show-shards
```

Output:

```text
stage 0: v1t{
stage 1: 1m_th3_
stage 2: r34l_
stage 3: k1ng_0
stage 4: f_th3_
stage 5: duck_p0nd}
v1t{1m_th3_r34l_k1ng_0f_th3_duck_p0nd}
```

## Flag

```text
v1t{1m_th3_r34l_k1ng_0f_th3_duck_p0nd}
```
