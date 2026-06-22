# Planetary Destruction — Misc/OSINT Writeup

**Author challenge:** ForeverFlames  
**Category:** Misc / OSINT  
**Flag:** `boroCTF{Eye_of_Rah}`

## Deskripsi Challenge

```text
The stars collapse, the light bends low, Into the VOID where no ships go.
A silent trap, a massive weight, The VOID decides the cosmic fate.

We cast our signals to the deep, But in the VOID, the shadows creep.
The Doppler shift, the redshift glare, The VOID consumes what wanders there.

A secret hidden in the night, Beyond the VOID, beyond the light.
To break the lock and shift the code, Embrace the VOID to find the road.

So watch the center, dark and still, The VOID is waiting, cold and chill.
The event horizon calls to you, Only the VOID will let truth through.

I could've sworn planets exploded differently when two black holes come in contact with eachother...
What gif is shown in this moment?

e2STziuFWUS

flag format: boroCTF{name_of_gif}
```

## Intuisi Awal

Challenge memberikan satu string pendek:

```text
e2STziuFWUS
```

Panjang string ini **11 karakter**, mirip format ID video YouTube. Karena deskripsi challenge juga bertanya tentang “moment” dan “gif is shown”, asumsi awal yang masuk akal adalah:

1. String tersebut berhubungan dengan video.
2. Kita perlu menemukan momen tertentu di video.
3. Pada momen itu ada GIF yang muncul.
4. Nama GIF tersebut menjadi isi flag.

Namun ID `e2STziuFWUS` tidak langsung menjadi video YouTube yang relevan. Jadi string ini kemungkinan masih terenkripsi atau perlu diproses.

## Analisis Petunjuk

Ada beberapa kata yang sengaja diulang dalam poem:

```text
VOID
VOID
VOID
VOID
```

Selain itu ada kalimat penting:

```text
To break the lock and shift the code,
Embrace the VOID to find the road.
```

Kata “shift the code” mengarah ke cipher berbasis pergeseran huruf. Karena `VOID` muncul berkali-kali dan berbentuk kata kunci, cipher yang paling cocok adalah **Vigenere cipher** dengan key:

```text
VOID
```

Jadi bukan sekadar Caesar shift biasa, karena Caesar hanya memakai satu nilai shift. Di sini challenge memberi key eksplisit yaitu `VOID`.

## Rabbit Hole

Sebelum menemukan jalur yang benar, ada rabbit hole yang cukup menggoda:

- Clue tentang black hole.
- Two black holes touching/colliding.
- Planetary destruction.
- GIF tentang gravitational waves atau simulasi merger black hole dari NASA.

Dari sana sempat mengarah ke GIF bertema black hole seperti visualisasi gravitational waves atau binary black holes. Ini ternyata salah, karena challenge tidak meminta GIF umum tentang black hole, tetapi **GIF yang muncul di momen tertentu pada video tertentu**.

Kesalahan utamanya adalah terlalu cepat menebak dari tema “black hole”, padahal string `e2STziuFWUS` belum diproses.

## Decode String

Kita decrypt `e2STziuFWUS` menggunakan Vigenere dengan key `VOID`.

Contoh script sederhana:

```python
import string

ct = "e2STziuFWUS"
key = "VOID"
alpha = string.ascii_letters

# Untuk kasus ini, kita cukup shift huruf alfabet.
# Angka dibiarkan tetap karena ID YouTube bisa mengandung angka.
def vig_decrypt(text, key):
    out = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            k = ord(key[ki % len(key)].upper()) - ord('A')
            out.append(chr((ord(ch) - base - k) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return ''.join(out)

print(vig_decrypt(ct, key))
```

Output:

```text
j2ELwngXTZE
```

Hasil ini valid sebagai YouTube video ID:

```text
https://www.youtube.com/watch?v=j2ELwngXTZE
```

## Menemukan Video

Setelah membuka ID tersebut, ditemukan video YouTube berjudul kurang lebih:

```text
How do black holes work???
```

Video inilah yang dimaksud challenge. Sekarang targetnya bukan lagi mencari GIF black hole secara umum, tetapi mencari momen ketika video menampilkan dua black hole dan planet yang “hancur”.

## Ekstraksi Frame

Agar lebih mudah dianalisis, video bisa di-download dan diekstrak frame-nya.

```bash
yt-dlp "https://www.youtube.com/watch?v=j2ELwngXTZE" -o blackhole.mp4
mkdir -p frames
ffmpeg -i blackhole.mp4 -vf fps=2 frames/frame_%04d.png
```

Lalu cari frame dengan visual:

- dua black hole berdampingan,
- ada planet di bawahnya,
- atau teks seperti `Planet getting destroyed btw`.

Pada momen yang relevan, terlihat GIF kecil di bawah black hole. GIF tersebut bukan animasi ilmiah black hole, melainkan meme/visual seorang pria dengan efek cahaya/emas di wajah.

Contoh frame yang ditemukan:

```text
Dua black hole di bagian atas,
planet/GIF kecil di bawah,
dan pada frame lain ada teks: "Planet getting destroyed btw".
```

## Identifikasi GIF

Setelah bagian GIF dicrop dari frame video, visualnya mengarah ke meme/GIF bernama:

```text
Eye of Rah
```

Ciri visualnya:

- wajah seseorang,
- efek cahaya kuning/emas,
- berasosiasi dengan meme “Eye of Rah”.

Karena challenge meminta:

```text
What gif is shown in this moment?
```

dan flag format-nya:

```text
boroCTF{name_of_gif}
```

maka nama GIF yang dimasukkan adalah `Eye_of_Rah`.

## Flag

```text
boroCTF{Eye_of_Rah}
```

## Summary Flow

```text
Challenge poem
    ↓
Perhatikan kata VOID yang diulang
    ↓
"shift the code" + VOID → Vigenere key = VOID
    ↓
Decrypt e2STziuFWUS
    ↓
Dapat YouTube ID: j2ELwngXTZE
    ↓
Buka video YouTube
    ↓
Cari momen dua black hole + planet destroyed
    ↓
Crop GIF yang muncul di momen tersebut
    ↓
Identifikasi GIF sebagai Eye of Rah
    ↓
Flag: boroCTF{Eye_of_Rah}
```

## Catatan Penting

Challenge ini menjebak dengan tema black hole. Kalau langsung mencari GIF tentang black hole merger, gravitational waves, atau NASA simulation, arahnya akan salah. Kunci sebenarnya ada di poem:

```text
VOID
shift the code
```

Dua petunjuk itu mengarah ke proses decode terlebih dahulu. Setelah video ditemukan, barulah clue “two black holes come in contact” dipakai untuk mencari momen yang benar di dalam video.
