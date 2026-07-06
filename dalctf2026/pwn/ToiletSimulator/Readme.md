# Toilet Simulator

Challenge ini bukan soal memory corruption biasa. Binary `victim` membaca `/flag.txt`, lalu membocorkan tiap bit flag lewat akses cache ke shared memory. Petunjuk di deskripsi, "you have to flush and reload", memang literal: solusinya adalah serangan cache side-channel `Flush+Reload`.

## Ringkasan Inti

Service menjalankan proses `victim` sebagai root. Dari source yang tersedia di host:

```c
volatile uint8_t *probe[2] = { base + PROBE0_OFF, base + PROBE1_OFF };

for (;;) {
    sem_wait(&ctl->req);
    int i = ctl->index;
    if (i >= 0 && i < ctl->nbits) {
        int bit = (flag[i / 8] >> (7 - (i % 8))) & 1;
        (void)*probe[bit];
    }
    sem_post(&ctl->done);
}
```

Artinya:

1. Kita bisa membuka shared memory `/simulator` karena dibuat dengan mode `0666`.
2. Ada dua page probe:
   - `probe0` untuk bit `0`
   - `probe1` untuk bit `1`
3. Kita bisa memilih bit mana yang ingin dibocorkan dengan menulis `ctl->index`.
4. Sinkronisasi dilakukan lewat semaphore `req` dan `done`, jadi tidak perlu balapan liar. Tinggal:
   - flush kedua probe dari cache
   - set index bit
   - `sem_post(req)`
   - tunggu `sem_wait(done)`
   - ukur probe mana yang sekarang lebih cepat diakses

Probe yang lebih cepat berarti probe itu baru saja disentuh oleh `victim`, sehingga bit bisa diketahui.

## Recon

Login ke host:

```bash
ssh player@instancer.dalctf2026.com -p 59991
# password: dalctf
```

Cek proses dan shared memory:

```bash
ps auxww
ls -l /dev/shm/simulator
```

Yang penting terlihat:

- proses `/usr/local/bin/victim` berjalan
- `/dev/shm/simulator` world-readable dan world-writable

Source `victim.c` juga tersedia di home directory, jadi jalur eksfiltrasinya bisa dibaca langsung.

## Strategi Eksploitasi

Saya pakai helper C karena butuh instruksi `clflush` dan timing cycle yang presisi (`rdtscp`).

Alur helper:

1. `shm_open("/simulator", O_RDWR, 0)`
2. `mmap` shared memory
3. Ambil pointer ke:
   - `ctl`
   - `probe0`
   - `probe1`
4. Untuk tiap bit:
   - flush `probe0` dan `probe1`
   - tulis `ctl->index = i`
   - `sem_post(&ctl->req)`
   - `sem_wait(&ctl->done)`
   - ukur akses ke `probe0` dan `probe1`
5. Karena timing kadang noisy, satu bit di-sample beberapa kali lalu dipilih dengan voting mayoritas.

Pendekatan ini jauh lebih stabil dibanding satu kali ukur per bit.

## Solver

File yang dipakai:

- `exploit.c`: helper `Flush+Reload`
- `solve.py`: login via SSH pakai pwntools, upload helper, compile di remote, jalankan beberapa kali, lalu ambil flag dengan regex

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

Fallback venv kalau perlu:

```bash
source /home/kali/tools/ctf/bin/activate
python3 solve.py
```

## Flag

```text
dalctf{p00p_em0j1}
```
