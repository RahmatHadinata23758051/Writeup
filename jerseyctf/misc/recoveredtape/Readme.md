# CTF Writeup — Recovered Tape

**Event:** JerseyCTF  
**Category:** Misc  
**Difficulty:** Medium  
**Flag:** `jctf{buy_0ne_g3t_0ne_fr33}`

---

## Challenge Description

> A shopping mall in Kansas City finally retired their '80s PA system, originally designed to work alongside looped music tapes for sale announcements. They want to archive its contents but can't figure out the messages. A short clip was salvaged from one of them.

**File:** `clip.wav`

---

## Reconnaissance

### Step 1 — Cek file dasar

Pertama gue cek metadata file:

```bash
file clip.wav
soxi clip.wav
```

Hasilnya:
- WAV PCM 16-bit, stereo, 44.1 kHz
- Durasi sekitar 17.5 detik

Jadi ini bukan file aneh/arsip bertingkat, tapi audio biasa yang kemungkinan ada data tersembunyi di dalam sinyalnya.

### Step 2 — Spectrogram analysis

Gue generate spectrogram untuk full audio dan per-channel:

```bash
sox clip.wav -n spectrogram -o spectrogram_full.png
sox clip.wav -n remix 1 spectrogram -o spectrogram_left.png
sox clip.wav -n remix 2 spectrogram -o spectrogram_right.png
```

Temuan penting:
- Di **channel kanan** ada blok sinyal yang sangat mencurigakan sekitar detik **7.7 sampai 10.0**.
- Bentuknya bukan suara manusia; lebih mirip data tone digital (modem lama).

### Step 3 — Ambil segmen sinyal data

```bash
sox clip.wav right.wav remix 2
sox right.wav signal.wav trim 7.7 '=10.0'
```

Gue fokus ke potongan ini karena jelas paling "non-musikal" dan konsisten seperti payload.

### Step 4 — Identifikasi petunjuk frekuensi

Dari visual spectrogram, muncul pasangan tone sekitar **1200 Hz** dan **2400 Hz**.

Di deskripsi challenge ada kata kunci **Kansas City**, yang langsung ngarah ke **Kansas City Standard (KCS)** untuk penyimpanan data di tape (era komputer lama).

KCS umumnya pakai:
- 300 baud
- tone 1200/2400 Hz

---

## Exploitation

### Step 5 — Decode dengan minimodem (KCS-like params)

Jalankan decode serial tone dengan parameter KCS:

```bash
minimodem --rx -f signal.wav 300 -M 2400 -S 1200 --startbits 1 --stopbits 2 -8 -q | xxd -p
```

Output hex yang kebaca:

```text
6a6374667b6275795f306e655f6733745f306e655f667233337dff
```

Decode ASCII-nya jadi:

```text
jctf{buy_0ne_g3t_0ne_fr33}
```

Byte `ff` di ujung cuma noise/terminator tambahan, bukan bagian flag.

---

## Flag

```text
jctf{buy_0ne_g3t_0ne_fr33}
```

---

## Vulnerability / Technique Summary

| # | Technique | Detail |
|---|---|---|
| 1 | Audio signal analysis | Spectrogram dipakai buat nemuin area sinyal tersembunyi |
| 2 | Channel isolation | Payload ada di channel kanan, bukan stereo campur |
| 3 | Legacy modem decoding | Tone 1200/2400 + hint Kansas City = KCS-style decoding |

---

## Tools Used

- `sox` / `soxi` — ekstraksi channel, trim segmen, spectrogram
- `minimodem` — decode tone menjadi data serial
- `xxd` — validasi output raw/hex

---

## Attack Flow

```text
Inspect WAV metadata
        |
        v
Generate per-channel spectrogram
        |
        v
Find suspicious tone block in right channel (7.7s–10.0s)
        |
        v
Extract and trim signal segment
        |
        v
Map hint "Kansas City" -> Kansas City Standard (1200/2400, 300 baud)
        |
        v
Decode with minimodem
        |
        v
jctf{buy_0ne_g3t_0ne_fr33}
```
