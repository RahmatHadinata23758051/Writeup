# Philologist — Forensics

## Ringkasan

Arsip menyimpan sebuah repository Git lengkap dan banyak flag palsu di working tree. Petunjuk utama ada pada akrostik puisi: huruf pertama tiap baris membentuk `ГИТЛОГ`, yang dibaca sebagai **GIT LOG**.

Repository memiliki tujuh commit bernama `part 0` sampai `part 6`. Dua digit pertama dari setiap commit hash merupakan satu byte hexadecimal. Setelah dikonversi ke ASCII, hasilnya adalah `1o9f1a9`.

Flag:

```text
grodno{1o9f1a9}
```

## 1. Triage arsip

Cek isi ZIP tanpa langsung mempercayai file yang tampak di working tree.

```bash
unzip -l filolog.zip | head -40
```

Bagian penting dari output:

```text
task-3 2/flag_check_old.py
task-3 2/utils_wip.py
task-3 2/backup.dat
task-3 2/file1.png
task-3 2/story.txt
task-3 2/.git/
task-3 2/.git/objects/
task-3 2/.git/logs/
task-3 2/.git/refs/
```

Direktori `.git` ikut terarsip, jadi histori commit dapat diperiksa secara utuh.

Ekstrak arsip:

```bash
unzip -q filolog.zip -d filolog
cd 'filolog/task-3 2'
```

## 2. Flag palsu di working tree

Pencarian string menghasilkan banyak kandidat, tetapi semuanya memakai nama seperti `red_herring`, `clickbait`, `wrong_flag`, atau `not_real`.

```bash
grep -RInaE '[A-Za-z_]+\{[^}]+\}' . --exclude-dir=.git
```

Contoh hasil:

```text
./backup.dat:1:# wrong_flag_buddy{k4nouhs9ft}
./cache.tmp:1:keep_looking_flag{azsaxbgpv9u66rb}
./cache.tmp:2:# flag_but_not_really{di7dcfclrcgiy79l}
./misc.txt:3:NOTE: red_herring_flag{1sgw91mpc04y}
./scratch.py:1:flag_but_not_really{3kr7b0}
```

Tidak ada kandidat yang menggunakan format `grodno{}`. File-file tersebut hanya decoy.

## 3. Membaca petunjuk puisi

Huruf pertama tiap baris adalah:

```text
Г ероев...
И ведь...
Т огдашних...
Л аскаясь...
О днажды...
Г раницы...
```

Akrostiknya:

```text
ГИТЛОГ
```

Tulisan Cyrillic tersebut mengarah langsung ke perintah:

```text
GIT LOG
```

## 4. Memeriksa histori commit

Tampilkan histori dari commit paling lama ke paling baru:

```bash
git log --reverse --format='%H %s'
```

Output:

```text
31dbe94b830bf861c963f7de45372ddd9edd54d0 part 0
6fdfa43ba2f2b6d1c4c5e0c5ad92b3337518d50f part 1
395b79453ae2968d11ef9daca46717bec68b920b part 2
66bc2a337c09fb538cbf71f28e5c5e5ffb298b78 part 3
3192d4cb55c224aa4891aad52c34fb63e14f2921 part 4
610f42ddf7a75f33908a60da201663002ce5a3a8 part 5
39a0f972486a8ae191785177dafcc83e0f42d98f part 6
```

Ada tujuh commit berurutan, sama dengan panjang payload flag yang nantinya diperoleh.

## 5. Hash sebagai byte ASCII

`file1.png` menampilkan tabel ASCII yang memetakan nilai hexadecimal ke karakter. Itu memberi cara membaca hash commit: ambil **dua digit pertama**, lalu interpretasikan sebagai satu byte hex.

| Part | Prefix hash | Hex ke ASCII |
|---:|:---:|:---:|
| 0 | `31` | `1` |
| 1 | `6f` | `o` |
| 2 | `39` | `9` |
| 3 | `66` | `f` |
| 4 | `31` | `1` |
| 5 | `61` | `a` |
| 6 | `39` | `9` |

Konversi manual dengan Python:

```bash
python3 - <<'PY'
values = ['31', '6f', '39', '66', '31', '61', '39']
print(''.join(chr(int(value, 16)) for value in values))
PY
```

Output:

```text
1o9f1a9
```

Setelah dibungkus sesuai format challenge:

```text
grodno{1o9f1a9}
```

## 6. Solver otomatis

`solve.py` menerima path menuju `filolog.zip` atau direktori repository. Untuk input ZIP, solver mengekstraknya ke folder lokal sementara, mencari `.git`, mengambil commit secara kronologis, lalu mengubah prefix hash menjadi ASCII.

Jalankan:

```bash
python3 solve.py filolog.zip
```

Output:

```text
[+] Repository : /mnt/data/.philologist_extract/task-3 2
[+] Commit hash prefixes:
    part 0: 31 -> '1'
    part 1: 6f -> 'o'
    part 2: 39 -> '9'
    part 3: 66 -> 'f'
    part 4: 31 -> '1'
    part 5: 61 -> 'a'
    part 6: 39 -> '9'
[+] Decoded    : 1o9f1a9
[+] Flag       : grodno{1o9f1a9}
```

## Flag

```text
grodno{1o9f1a9}
```
