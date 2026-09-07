# CADENCE

## Ringkasan

`cadence` adalah binary REV berbentuk aplikasi terminal mirip pemutar musik. Bagian penting ada di menu Encore. Remote memberi `SESSION` 16 byte dalam hex dan sample rate. User harus mengirim base64 WAV mono PCM 16-bit yang waveform-nya lolos fungsi `encore.resonates()`.

Flag tidak disimpan sebagai string plaintext di binary lokal. Binary lokal hanya melakukan validasi waveform. Flag keluar dari service remote setelah payload WAV yang valid disubmit.

Flag yang didapat dari remote:

```
TFCCTF{the_encore_resonates_over_gf2_7c4e91ab}
```

## File Challenge

```
cadence              ELF 64-bit, stripped, statically linked
solve.py             solver final single-file
solve_final.py       backup solver final
resonant.wav         WAV hasil generator solver
payload.txt          base64 dari resonant.wav untuk disubmit
```

## Analisis Awal

Cek awal:

```bash
file cadence
strings -a cadence | less
nm cadence | grep -i encore
objdump -d -M intel cadence > objdump_cadence.txt
```

Binary berisi banyak simbol/runtime, tapi nama fungsi terkait challenge masih kebaca dari simbol internal. String UI menunjukkan menu `Encore` dan instruksi submit base64 WAV.

Di remote, menu Encore menampilkan format seperti ini:

```
SESSION <32 hex>
resonant track: mono 16-bit PCM WAV at <rate> Hz, 16+ samples
ADD ENCORE TRACK paste base64 WAV, Enter to submit
```

`SESSION` remote dipakai langsung sebagai nonce solver. Sample rate juga harus sama dengan yang ditampilkan remote.

## Analisis Static

Fungsi validasi utama ada di `encore.resonates`. Alurnya:

1. Parse WAV base64 dari input user.
2. Pastikan format WAV valid:
   - mono,
   - PCM 16-bit,
   - sample rate sesuai sesi,
   - minimal 16 sample.
3. Inisialisasi state 8 word `u32` dari SHA-256 domain:

```
cadence/resonance/init/v2
```

4. Setiap sample PCM 16-bit memodifikasi state memakai PRNG SplitMix64, rotate 32-bit, XOR, dan perkalian GF(2^32).
5. Final state dikalikan konstanta GF dan dibandingkan dengan target hardcoded di `.rodata`.

Konstanta target final:

```python
TARGET = [
    0x452821E6,
    0x38D01377,
    0xBE5466CF,
    0x34E90C6C,
    0xC0AC29B7,
    0xC97C50DD,
    0x3F84D5B5,
    0xB5470917,
]
```

Domain PRF target:

```
cadence/resonance/target/v2
```

Polynomial GF yang dipakai:

```
0x04C11DB7
```

Konstanta final GF:

```
0x27D4EB2F
```

Bug analisis awal ada di opcode `3`. Slot jump-table ini bukan cuma menulis `dst`, tapi juga melakukan swap balik ke `src`:

```python
old_dst = state[dst]
state[dst] = sample ^ state[src] ^ key
state[src] = old_dst
```

Kalau efek `state[src] = old_dst` dilewatkan, WAV tetap terbentuk tapi remote memberi:

```
Dissonance. The waveform does not resolve.
```

## Analisis Dynamic

Validasi dynamic dilakukan dengan service remote:

```
ncat --ssl chall-cadence-encore-88913dcf790d0bbc.challs.ctf.thefewchosen.com 1337
```

Contoh parameter remote:

```
SESSION c24e2b373236bfeeb0dddb76cdc4f78a
resonant track: mono 16-bit PCM WAV at 16000 Hz, 16+ samples
```

Solver menghasilkan `payload.txt`, lalu isi file itu dipaste ke prompt `>` remote. Versi solver yang belum memodelkan swap opcode `3` menghasilkan `Dissonance`. Setelah opcode `3` dibenerin, remote menerima waveform dan mengeluarkan flag.

## Algoritma Validasi atau Encoding

State awal:

```python
state = SHA256(b"cadence/resonance/init/v2" + nonce + p32(rate))
```

Digest SHA-256 dibaca sebagai 8 word little-endian `u32`.

Untuk tiap sample:

```python
seed = splitmix64(seed)
dst = d & 7
src = (d >> 3) & 7
if src == dst:
    src = (src + 1) & 7
op = (d >> 6) & 3
sample_rot = ((d >> 9) % 31) + 1
key_rot = ((i + src) % 31) + 1
key = rol32(nonce_word[(i + d) & 3], key_rot)
```

Opcode:

```python
if op == 0:
    state[dst] = old_dst ^ key ^ rol32(sample, sample_rot) ^ gf_mul(state[src], 0x9E3779B1)
elif op == 1:
    state[dst] = state[src] ^ key ^ rol32(old_dst, sample_rot) ^ gf_mul(sample, 0x85EBCA77)
elif op == 2:
    state[dst] = old_dst ^ key ^ rol32(state[src], sample_rot) ^ gf_mul(sample, 0xC2B2AE3D)
else:
    state[dst] = sample ^ state[src] ^ key
    state[src] = old_dst
```

Final check memakai state yang sudah dikalikan `0x27D4EB2F` di GF(2^32), lalu word-nya diacak dan di-XOR dengan nonce serta PRF target.

Karena semua operasi terhadap bit sample linear di GF(2), input WAV bisa dicari dengan aljabar linear. Solver memakai 51 sample. Total variabel = `51 * 16 = 816` bit, cukup untuk memenuhi target 256 bit.

## Penyusunan Solve Script

`solve.py` dibuat single-file supaya aman dinamai `solve.py`. Versi lama sempat error:

```
AttributeError: module 'solve' has no attribute 'solve_samples'
```

Penyebabnya wrapper remote juga melakukan `import solve`, lalu Python mengimpor file itu sendiri. Versi final tidak punya `import solve`.

Alur solver:

1. Parse `--nonce` atau `--seed`.
2. Kalau input `--seed`, nonce dihitung dengan:

```python
SHA256(b"cadence/encore/session/v2" + seed)[:16]
```

3. Simulasikan checker dengan sample nol untuk baseline.
4. Hitung target state sebelum final GF multiply.
5. Buat kolom linear untuk setiap bit sample.
6. Gaussian elimination di GF(2) untuk mencari kombinasi bit sample.
7. Tulis `resonant.wav`.
8. Encode WAV ke base64 sebagai `payload.txt`.
9. Verifikasi internal dengan fungsi `final_check()` sebelum payload ditulis.

## Cara Menjalankan

Manual dari parameter remote:

```bash
cd /home/nata/ctf/TFCCTF2026/rev/CADENCE
python3 solve.py --nonce SESSION_DARI_REMOTE --rate RATE_DARI_REMOTE
cat payload.txt
```

Paste isi `payload.txt` ke prompt `>` di remote.

Contoh:

```bash
python3 solve.py --nonce c24e2b373236bfeeb0dddb76cdc4f78a --rate 16000
cat payload.txt
```

Auto connect ke remote:

```bash
python3 solve.py --remote
```

Default remote:

```
chall-cadence-encore-88913dcf790d0bbc.challs.ctf.thefewchosen.com:1337
```

Catatan: payload harus dibuat ulang setiap koneksi karena `SESSION` berubah.

## Flag

```
TFCCTF{the_encore_resonates_over_gf2_7c4e91ab}
```
