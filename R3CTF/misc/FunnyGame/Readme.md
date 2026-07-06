# FunnyGame — R3CTF 2026

- **Category:** Misc / Reverse Engineering
- **Difficulty:** Hard
- **Flag:** `r3ctf{0dd_74p5_7h3n_5113nc3_f0110w_7h3_0r817_70_un10ck_7h3_f1n41_n073}`

## Ringkasan

Archive terlihat seperti build Unity IL2CPP biasa. Struktur itu sengaja dipakai sebagai kamuflase: `GameAssembly.dll` berisi banyak checker, ciphertext, dan class dengan nama meyakinkan, tetapi hasilnya memakai prefix `r0ctf`, `r1ctf`, `r2ctf`, `r4ctf`, atau `r5ctf`.

Jalur asli ada satu tingkat lebih dalam:

1. `FunnyGame.exe` adalah executable packed.
2. Setelah payload-nya dibuka, executable tersebut ternyata **Godot 4.6.2 custom build**, bukan launcher Unity normal.
3. Project Godot disimpan sebagai PCK terenkripsi di `FunnyGame_Data/resources.assets.resS` mulai offset `0x100`.
4. Engine memakai AES-256-CFB untuk mengenkripsi direktori dan setiap entry PCK.
5. Bytecode GDScript memakai format custom: identifier, constant, dan token semuanya diobfuscate.
6. `FlagSeal.gdc` menyimpan dua bagian flag.
7. `audio_core.dll`, yang dimuat sebagai GDExtension Godot, menyimpan bagian terakhir.

Hasil akhirnya membentuk kalimat leetspeak:

```text
odd taps then silence follow the orbit to unlock the final note
```

---

## 1. Enumerasi awal

Ekstrak archive lalu cek file utamanya.

```bash
unzip funnygame.zip -d FunnyGame
cd FunnyGame
file FunnyGame.exe GameAssembly.dll FunnyGame_Data/Plugins/x86_64/audio_core.dll
```

Output penting:

```text
FunnyGame.exe: PE32+ executable, x86-64, 3 sections
GameAssembly.dll: PE32+ executable, x86-64
FunnyGame_Data/Plugins/x86_64/audio_core.dll: PE32+ executable, x86-64, 3 sections
```

Layout direktorinya memang menyerupai Unity IL2CPP:

```text
FunnyGame.exe
GameAssembly.dll
UnityPlayer.dll
FunnyGame_Data/
├── il2cpp_data/Metadata/global-metadata.dat
├── resources.assets
├── resources.assets.resS
└── Plugins/x86_64/audio_core.dll
```

Dua hal langsung mencurigakan:

- `FunnyGame.exe` hanya memiliki tiga section dan entry point-nya berupa unpacking stub.
- `audio_core.dll` tidak terlihat seperti library audio normal. Import utamanya hanya fungsi loader/memory seperti `LoadLibraryA`, `GetProcAddress`, dan `VirtualProtect`.

---

## 2. Layer Unity adalah decoy

Metadata IL2CPP tetap layak diperiksa karena author menaruh banyak logic palsu di sana. Beberapa class custom yang ditemukan:

```text
ApproachRingAudit
ChartFalseVault
ChartLaneMath
ChartLongHashGate
ChartRuntimeBootstrap
TimingWindowNode00 ... TimingWindowNode63
```

Class tersebut punya checker, hash gate, ciphertext, dan UI callback yang terlihat valid. Kalau diikuti, beberapa jalur menghasilkan kandidat seperti:

```text
r0ctf{...}
r1ctf{...}
r2ctf{...}
r4ctf{...}
r5ctf{...}
```

Salah satu decoy bahkan mendekripsi teks yang sangat meyakinkan:

```text
r0ctf{un1ty_d0es_n0t_h0ld_th3_r1ng}
```

Prefix challenge yang benar adalah `r3ctf`, dan mengganti prefix secara manual juga tidak valid. Ini bukan masalah typo; seluruh layer Unity memang dibuat untuk menghabiskan waktu.

Indikator yang membedakan decoy dan jalur asli:

- Tidak ada jalur Unity yang menghasilkan prefix `r3ctf` secara native.
- Beberapa vault memakai format flag event lain secara sengaja.
- `FunnyGame.exe` tidak berperilaku seperti bootstrap Unity standar setelah unpack.
- Plugin `audio_core.dll` mengandung simbol/path `native_seal`, bukan implementasi audio.

Jadi `GameAssembly.dll` tetap berguna untuk mengenali jebakan, tetapi bukan sumber flag final.

---

## 3. Membuka `audio_core.dll`

`audio_core.dll` juga packed. Stub awal menyalin/dekompresi payload ke memory, mengubah proteksi page, lalu meneruskan eksekusi ke PE yang baru dibuka.

Unpacking dilakukan dengan emulasi stub menggunakan Unicorn, lalu image memory direbuild menjadi PE normal. File hasilnya disimpan sebagai:

```text
audio_core_unpacked.dll
```

Setelah dibuka, string dan RTTI menunjukkan bahwa library ini adalah GDExtension Godot:

```text
D:\Workspace\chall\r3ctf2026\Reverse\game\gosu\native_seal\src\native_seal.h
godot::A9::get_property_list_bind
```

File `bin/native_seal.gdextension` di project nanti mengonfirmasi entry point-nya:

```ini
[configuration]
entry_symbol = "audio_core_library_init"
compatibility_minimum = "4.1"

[libraries]
windows.release.x86_64 = "res://FunnyGame_Data/Plugins/x86_64/audio_core.dll"
```

Class native `A9` mengekspos lima method:

```text
f0()                         reset state
f1(int, int, ..., int)       validasi tujuh integer
f2(int, int)                 validasi tahap lanjutan
f3(Vector2, float)           menerima posisi note dan timestamp
f4() -> String               membuka fragmen terakhir
```

### State machine note

`f3` tidak menerima sembarang titik. Posisi diubah menjadi sektor pada sebuah orbit, lalu sector harus muncul dalam urutan:

```text
0, 4, 7, 3, 6, 2, 5, 1
```

Constraint lain yang terlihat dari fungsi:

```text
radius sekitar 265 sampai 390
interval antar-note sekitar 0.09 sampai 0.72 detik
jumlah note valid: 8
```

Setelah state `f1`, `f2`, dan seluruh delapan note valid, `f4` mendekripsi string:

```text
10ck_7h3_f1n41_n073}
```

String ini **bukan flag lengkap**. Menambahkan `r3ctf{` langsung menghasilkan kandidat salah. Posisi `f4` di arsitektur challenge adalah bagian akhir dari flag, bukan keseluruhan flag.

---

## 4. `FunnyGame.exe` ternyata Godot custom

Stub pada `FunnyGame.exe` dibuka dengan cara yang sama: map PE ke Unicorn, jalankan sampai loop decompression selesai, dump image memory, lalu rebuild PE dari NT header dan section table yang sudah terbuka.

String pada executable hasil unpack menunjukkan identitas engine sebenarnya:

```text
Godot Engine v4.6.2.stable.custom_build
D:\Workspace\chall\r3ctf2026\Reverse\MyGodot\godot\modules\gdscript\gdscript.h
D:\Workspace\chall\r3ctf2026\Reverse\MyGodot\godot\core\io\resource_loader.h
```

Ini menjelaskan kenapa analisis Unity tidak pernah mencapai flag: executable yang dieksekusi adalah Godot custom, sedangkan file Unity dipakai sebagai container dan umpan reverse engineering.

---

## 5. Menemukan PCK di `resources.assets.resS`

Cek isi awal resource stream:

```bash
python3 - <<'PY'
from pathlib import Path

data = Path('FunnyGame_Data/resources.assets.resS').read_bytes()
print(data[:8])
print(hex(data.find(b'GDPC')))
PY
```

Output:

```text
b'UnityFS\x00'
0x100
```

Pada offset `0x100` terdapat magic PCK Godot:

```text
47 44 50 43 03 00 00 00 ...
G  D  P  C
```

PCK dapat dipisahkan langsung:

```python
from pathlib import Path

src = Path("FunnyGame_Data/resources.assets.resS").read_bytes()
Path("funnygame.pck").write_bytes(src[0x100:])
```

Header yang didapat:

```text
magic          = GDPC
format version = 3
Godot version  = 4.6.2
flags          = 3
base offset    = 0x70
```

Flag PCK menunjukkan direktori dan entry file memakai enkripsi.

---

## 6. Membongkar enkripsi PCK

Key 32 byte diambil dari fungsi custom yang membuka PCK pada executable Godot:

```text
3a00dbacb3316f082fdbb88c7fd4a6b1
c1333ef17203b5c70619813ca6efa650
```

Mode cipher sempat terlihat seperti CBC dari nama wrapper internal, tetapi implementasi yang dipakai pada data adalah **AES-256-CFB128**.

Struktur entry terenkripsi:

```text
+0x00  md5 plaintext       16 byte
+0x10  plaintext length    uint64 little-endian
+0x18  IV                   16 byte
+0x28  ciphertext           align(length, 16)
```

Kode dekripsinya:

```python
from Crypto.Cipher import AES
import hashlib
import struct

key = bytes.fromhex(
    "3a00dbacb3316f082fdbb88c7fd4a6b1"
    "c1333ef17203b5c70619813ca6efa650"
)

md5_expected = blob[:16]
length = struct.unpack_from("<Q", blob, 16)[0]
iv = blob[24:40]
ciphertext = blob[40:40 + ((length + 15) & ~15)]

plaintext = AES.new(
    key,
    AES.MODE_CFB,
    iv=iv,
    segment_size=128,
).decrypt(ciphertext)[:length]

assert hashlib.md5(plaintext).digest() == md5_expected
```

MD5 menjadi pembeda penting saat menguji mode AES. CBC menghasilkan data acak, sedangkan CFB128 menghasilkan MD5 yang sama persis dengan header.

Direktori yang berhasil dibuka berisi 42 file, antara lain:

```text
Main.tscn
Interface.tscn
Hitball.tscn
Scripts/Main.gdc
Scripts/FlagSeal.gdc
Scripts/Hitball.gdc
bin/native_seal.gdextension
project.binary
```

---

## 7. Format bytecode GDScript dimodifikasi

File `.gdc` tidak bisa langsung dibaca decompiler GDScript biasa. Header `FlagSeal.gdc`:

```text
magic   = ABAB
version = 0x43544612
```

Engine memodifikasi tiga bagian bytecode:

1. identifier disimpan sebagai codepoint UTF-32 yang dienkripsi per karakter;
2. constant Variant dibungkus marker custom dan dienkripsi per index;
3. token ID dipermutasi sebelum disimpan.

### 7.1 Deobfuscation identifier

Untuk setiap identifier dan posisi karakter, stream key dibentuk dari index identifier dan index karakter.

Bagian inti algoritmanya:

```python
MASK = 0xffffffff


def u32(x):
    return x & MASK


def mix_full(x):
    x = u32(x ^ (x >> 16))
    x = u32(x * 0x7FEB352D)
    x = u32(x ^ (x >> 15))
    x = u32(x * 0x846CA68B)
    return u32(x ^ (x >> 16))


def decrypt_identifier_word(enc, ident_idx, char_idx):
    seed = u32((ident_idx + 1) * 0x045D9F3B)
    seed ^= u32((char_idx + 1) * 0x27D4EB2D)

    value = u32(seed ^ 0x45A1F3C7)
    value = u32(seed ^ (value >> 16) ^ 0x45A1F3C7)

    value = u32(value * 0x7FEB352D)
    value = u32(value ^ (value >> 15))
    value = u32(value * 0x846CA68B)
    value = u32(value ^ (value >> 16))

    out = bytearray(4)
    for i, byte in enumerate(enc):
        base = u32(0x9E3779B9 - u32(i * 0x61C88647))
        key = mix_full(base ^ value)
        out[i] = byte ^ ((key >> ((i & 3) * 8)) & 0xff)

    return int.from_bytes(out, "little")
```

Identifier penting yang pulih dari `FlagSeal.gdc`:

```text
EXTREME_LEVEL
NORMAL_LEVEL
EXTREME_HIT_COUNT
EXTREME_TRACE
PART1_CIPHER
PART2_CIPHER
initial_trace
feed_hit
try_open_part1
try_open_part2
_decrypt
_next32
_mix32
```

Nama-nama ini langsung menunjukkan bahwa script mengelola dua ciphertext dan trace gameplay.

### 7.2 Dekripsi constant

Setiap constant diawali byte marker `0xc7`, diikuti panjang payload. Seed constant bergantung pada index constant:

```python
def constant_seed(index):
    seed = u32((index + 1) * 0x27D4EB2D)
    value = u32(seed ^ 0xA17F23D5) >> 16
    seed = u32(seed ^ value ^ 0xA17F23D5)

    seed = u32(seed * 0x7FEB352D)
    seed = u32(seed ^ (seed >> 15))
    seed = u32(seed * 0x846CA68B)
    return u32(seed ^ (seed >> 16))
```

Setelah didekripsi, payload dibaca sebagai Variant Godot. Constant penting:

```text
NORMAL_LEVEL      = 6
EXTREME_LEVEL     = 11
EXTREME_HIT_COUNT = 64
EXTREME_TRACE     = 2271314799
GRADE_CODE        = {"Good": 1, "Great": 2, "Perfect": 3}
```

Dua array byte juga pulih sebagai `PART1_CIPHER` dan `PART2_CIPHER`.

### 7.3 Token permutation

Low byte setiap token tidak disimpan sebagai enum token asli. Mapping inverse yang dipakai:

```python
def decode_token(raw):
    value = raw & 0x7f
    if value == 0:
        return 0
    if value >= 100:
        return 98
    return ((2 * ((value - 18) % 99)) % 99) + 1
```

Sesudah token, identifier, dan constant dipulihkan, struktur `FlagSeal.gdc` dapat dibaca. Bentuk logiknya kurang lebih:

```gdscript
extends RefCounted

const NORMAL_LEVEL = 6
const EXTREME_LEVEL = 11
const EXTREME_HIT_COUNT = 64
const EXTREME_TRACE = 2271314799

static func initial_trace(level: int) -> int:
    # membentuk trace awal
    pass

static func feed_hit(trace: int, spawn_id: int, grade: String) -> int:
    # update trace untuk setiap note
    pass

static func try_open_part1(level, score, target_score, miss_count, best_combo) -> String:
    # hanya terbuka pada state level normal yang valid
    pass

static func try_open_part2(
    level, score, target_score, miss_count,
    best_combo, hit_count, trace
) -> String:
    # level 11, no miss, 64 hit, combo 64, trace harus tepat
    pass
```

Tidak perlu memainkan seluruh chart. Setelah constant, cipher, dan routine dekripsi direkonstruksi secara statik, dua bagian logis yang didapat adalah:

```text
r3ctf{0dd_74p5_7h3n_5113n
c3_f0110w_7h3_0r817_70_un
```

Bagian kedua berhenti di `un`, sehingga suffix dari plugin native menyambung kalimat menjadi `unlock_the_final_note`.

---

## 8. Menggabungkan seluruh fragmen

Tiga fragmen yang sudah terbukti berasal dari layer asli:

```text
GDScript part 1:
r3ctf{0dd_74p5_7h3n_5113n

GDScript part 2:
c3_f0110w_7h3_0r817_70_un

Native GDExtension:
10ck_7h3_f1n41_n073}
```

Gabungkan tanpa separator tambahan:

```text
r3ctf{0dd_74p5_7h3n_5113nc3_f0110w_7h3_0r817_70_un10ck_7h3_f1n41_n073}
```

## Flag

```text
r3ctf{0dd_74p5_7h3n_5113nc3_f0110w_7h3_0r817_70_un10ck_7h3_f1n41_n073}
```

---

## 9. Menjalankan reproducer

`solve.py` di folder ini melakukan pengecekan artefak utama dan merakit fragmen yang sudah dipulihkan dari GDScript serta GDExtension.

```bash
python3 solve.py
```

Output:

```text
[+] Embedded Godot PCK found at resources.assets.resS+0x100
[+] FlagSeal.gdc MD5 verified
[+] Native seal artifact verified
[+] FLAG: r3ctf{0dd_74p5_7h3n_5113nc3_f0110w_7h3_0r817_70_un10ck_7h3_f1n41_n073}
```

## Catatan akhir

Kesalahan terbesar saat mengerjakan challenge ini adalah memperlakukan semua file Unity sebagai aplikasi utama. Author sengaja membuat decoy-nya cukup lengkap: ada metadata IL2CPP, class custom, checker, ciphertext, dan output flag palsu. Pivot yang benar muncul dari dua bukti kecil: `FunnyGame.exe` adalah packed executable yang bukan bootstrap Unity normal, dan `audio_core.dll` berisi GDExtension bernama `native_seal`.

Setelah itu alurnya konsisten: buka Godot custom, ambil PCK, pulihkan bytecode, lalu gabungkan dua fragmen script dengan tail dari native extension.
