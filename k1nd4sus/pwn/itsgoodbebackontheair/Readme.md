# Writeup - It's Good to Be Back on the Air...

## Informasi Challenge
- Kategori: PWN
- Binary: `radio`
- Remote: `chall.k1nd4sus.it:30507`

## 1. Initial Recon
Pertama saya cek tipe binary dan proteksinya.

### Ringkasan hasil
- ELF 64-bit, dynamically linked, **not stripped**
- **No PIE** (base fix di `0x400000`)
- **No Canary**
- **NX enabled**
- Partial RELRO

Ini langsung kasih indikasi bahwa stack overflow via return address masih sangat mungkin, lalu targetnya adalah `ret2win` (jika ada fungsi win) atau ROP sederhana.

## 2. Static Analysis
Dari `nm`/`objdump`, ditemukan fungsi-fungsi penting:
- `choice_menu`
- `do_state_scan`
- `do_state_tune`
- `do_state_service`
- `radio_jazz`

### Vulnerability utama
Di `do_state_service` ada pemanggilan `gets()` ke buffer stack lokal:

- stack frame `sub rsp, 0x50`
- buffer di sekitar `[rbp-0x40]`
- `gets(buffer)` tanpa batas panjang input

Artinya kita bisa overflow sampai overwrite saved RIP.

### Fungsi target (win)
Fungsi `radio_jazz` ternyata membangun string flag dan `puts()` flag tersebut.
Di local dia mengeluarkan fake flag:
- `KSUS{fakeflag_runthisonline}`

Jadi strategi paling efisien: **redirect RIP ke `radio_jazz`**.

## 3. Dynamic Analysis & Flow
Challenge ini state-machine. Overflow hanya bisa dipicu saat masuk `SERVICE mode` (state 4), bukan langsung dari awal.

Di `choice_menu` ada kondisi khusus agar return state = 4:
1. `lfsr == 0xe69e`
2. station saat ini harus sama dengan head list (`Radio 666 News`)

### Menentukan urutan input agar masuk SERVICE
Saya brute-force update LFSR berdasarkan fungsi `lfsr_update` dan transisi state.
Urutan yang valid dari awal adalah:

1. `1` (Scan)
2. `2` (Tune)
3. isi frekuensi: `666`
4. `1` (Scan)
5. `1` (Scan) -> trigger SERVICE mode

Setelah ini program minta input station favorit, dan di titik ini `gets()` dipanggil.

## 4. Offset Overflow
Offset ke RIP dihitung dari layout frame `do_state_service`:
- buffer start: `rbp - 0x40`
- saved RIP: `rbp + 0x8`

Jarak = `0x40 + 0x8 = 0x48` = **72 byte**.

Payload final:
- `b'A' * 72 + p64(addr_radio_jazz)`

Karena binary non-PIE, alamat `radio_jazz` stabil (`0x40141f`).

## 5. Exploit Script
Solver disimpan di `solve.py`.

### Jalankan local
```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py LOCAL=1
```

### Jalankan remote
```bash
source /home/nata/ctf_env/bin/activate
python3 solve.py
```

## 6. Hasil
Exploit berhasil dan mengeluarkan flag remote:

`KSUS{th15_fac3_w4s_m4d3_f0r_r4d10!}`

## Kenapa exploit ini stabil
- Tidak bergantung leak address
- Tidak bergantung libc remote
- Non-PIE membuat alamat fungsi target konstan
- Jalur state service sudah deterministik

Jadi sekali sequence benar, tinggal kirim overflow 72 byte + alamat `radio_jazz`.
