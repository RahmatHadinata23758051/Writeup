# Cat Simulator

- **CTF:** BroncoCTF
- **Category:** Reverse
- **Difficulty:** Medium
- **Flag:** `bronco{fluffy_baby}`

## Recon

Binary Linux berupa ELF 64-bit PIE yang sudah di-strip:

```bash
file cat-sim-linux
```

Output:

```text
cat-sim-linux: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

Pemeriksaan string langsung memperlihatkan beberapa ending dan satu kandidat flag mencurigakan:

```bash
strings -a -n 4 cat-sim-linux
```

Potongan penting:

```text
You were so purrfect this week!
You're a strange cat, but you're my cat.
Final score: %d
bonco{almost_the
```

`bonco{almost_there}` sengaja ditaruh sebagai decoy. Prefix-nya bahkan salah karena kehilangan huruf `r`.

## State Permainan

Program berjalan selama lima hari. State utama yang disimpan:

```text
score
mood
invalid_count
talk_count
total_talk_length
eat_count
scratch_count
```

Nilai awal:

```text
score = 0
mood = 10
semua counter = 0
```

Efek setiap pilihan:

| Pilihan | Score | Mood | Counter |
|---|---:|---:|---|
| Talk | `+25` | `+7` | `talk_count++` |
| Scratch | `-50` | `-12` | `scratch_count++` |
| Eat | `+20` | `+2` | `eat_count++` |
| Input lain | `0` | `0` | `invalid_count++` |

Saat memilih **Talk**, program juga membaca sebuah string dan menambahkan panjangnya ke `total_talk_length`.

## Kondisi Flag Asli

Setelah hari kelima, cabang flag asli memeriksa semua kondisi berikut:

```text
invalid_count == 0
talk_count == 3
scratch_count == 1
eat_count == 1
score == 45
mood > 0
total_talk_length == 32
```

Dengan tiga Talk, satu Scratch, dan satu Eat:

```text
score = 3(25) - 50 + 20
      = 45
```

Mood akhirnya:

```text
mood = 10 + 3(7) - 12 + 2
     = 21
```

Jadi susunan jenis pilihannya boleh berubah, tetapi jumlah setiap pilihan harus tepat. Syarat yang masih perlu diatur manual adalah total panjang tiga pesan, yaitu 32 karakter.

Payload yang dipakai solver:

```text
Day 1: Talk, kirim 10 karakter
Day 2: Talk, kirim 10 karakter
Day 3: Talk, kirim 12 karakter
Day 4: Scratch
Day 5: Eat
```

Total panjang:

```text
10 + 10 + 12 = 32
```

## Decoy

Ada cabang terpisah yang aktif jika:

```text
total_talk_length == 32
```

tetapi kombinasi counter lainnya salah. Cabang ini menampilkan:

```text
bonco{almost_there}
```

Karena itu hanya mengejar panjang input 32 tidak cukup.

## Flag Terenkripsi

Flag asli tidak tersimpan sebagai string plaintext. Byte terenkripsinya berada di `.rodata`, lalu didekripsi hanya setelah seluruh kondisi tersembunyi terpenuhi.

Seed dekripsi memakai nilai mood akhir. Pada jalur benar:

```text
mood = 21
```

Hasil dekripsinya dimasukkan ke pesan finale:

```text
Owner: awwww it said "bronco{fluffy_baby}"
```

## Menjalankan Manual

```bash
printf '\n1\naaaaaaaaaa\n1\nbbbbbbbbbb\n1\ncccccccccccc\n2\n3\n' | ./cat-sim-linux
```

Bagian akhir output:

```text
(End of day 5) Current score: 45

=== Day 5 Finale ===
Owner: awwww it said "bronco{fluffy_baby}"

Final score: 45
Have an ameowsing day!
```

## Solver

`solve.py` mengirim pilihan dan pesan yang memenuhi semua constraint, lalu mengambil flag dari output program.

```bash
python3 solve.py ./cat-sim-linux
```

Output:

```text
bronco{fluffy_baby}
```

## Flag

```text
bronco{fluffy_baby}
```
