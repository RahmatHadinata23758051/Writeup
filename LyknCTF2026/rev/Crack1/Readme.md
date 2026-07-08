# Cr4ck 1 — Reverse Engineering Writeup

- **CTF:** LYKNCTF 2026
- **Category:** Reverse
- **Binary:** `KeygenMe.exe`
- **Architecture:** PE32+ x86-64
- **Difficulty:** Medium
- **Flag:** `LYKNCTF{k3yg3n_h3ll_s3lfh4sh_4ntidbg_h1dd3n_us3r_2026}`

## Ringkasan

Binary meminta username dan license key lewat GUI. Username yang valid tidak disimpan sebagai string biasa, license dihitung dari username dan status anti-debug, sedangkan flag dienkripsi memakai hash dari `.text`, kredensial valid, dan byte anti-debug.

Hasil akhirnya:

```text
Username : th3_LYKN_v3nd0r
License  : 7211-57C4-CD96-CC26-5B67
```

## Recon

Identifikasi awal:

```bash
file KeygenMe.exe
strings -a -n 4 KeygenMe.exe | grep -Ei 'license|username|flag|success|failed'
```

Output penting:

```text
KeygenMe.exe: PE32+ executable for MS Windows, x86-64
Username must be at least 4 characters.
Wrong license key for this account.
Your license is valid.
Flag: %s
License valid, but the vault stays locked.
```

Import yang relevan:

- `GetDlgItemTextA` untuk mengambil username dan license.
- `lstrcmpA` untuk membandingkan hasil keygen.
- `NtQueryInformationProcess` untuk pemeriksaan debugger.
- `MessageBoxA` untuk menampilkan hasil.

## Username tersembunyi

Fungsi di sekitar `0x1400014d0` menginisialisasi array `S[256]` lalu menjalankan RC4 Key Scheduling Algorithm dengan key:

```text
L0i_Y3u_Kh0_N0i
```

Fungsi di `0x140001f10` mengambil beberapa byte dari tabel RC4 tersebut dan meng-XOR-nya dengan konstanta di `.rdata`:

```text
ad d9 93 f2 4c a6 78 dc 1d 36 9f 61 e4 02 36
```

Delapan byte pertama dibentuk dari indeks:

```text
42, 3d, 38, 33, 2e, 29, 24, 1f
```

Tujuh byte berikutnya memakai indeks mulai `0x47` dengan kenaikan lima. Hasil transformasinya:

```text
th3_LYKN_v3nd0r
```

Binary membandingkan string ini dengan input username memakai `lstrcmpA`.

## Anti-debug mask

Binary membentuk satu byte mask dari empat pemeriksaan:

1. `PEB.BeingDebugged` memberi bit `0x01`.
2. `PEB.NtGlobalFlag & 0x70` memberi bit `0x02`.
3. `ProcessDebugPort` memberi bit `0x04`.
4. `ProcessDebugFlags == 0` memberi bit `0x08`.

Pada eksekusi normal tanpa debugger, mask bernilai `0`.

Mask ini tidak cuma memblokir debugging. Nilainya masuk ke algoritma license dan derivasi kunci flag, jadi patch jump sederhana bisa menghasilkan license valid tetapi dekripsi flag tetap gagal.

## Algoritma license

Fungsi `0x140001660` menerima username dan anti-debug mask. State awalnya:

```text
r8  = 0x4c594b4e ^ (mask * 0x01010101)
r9  = 0xae054fb9
r11 = 0x43544632
acc = 0xa5a5f00d
```

Username diproses tiga kali dengan offset `0`, `7`, dan `14`. Setiap byte mengambil nilai dari tabel RC4 lalu dicampur memakai penjumlahan 32-bit, XOR, dan rotasi `ROL 3/5/11/17`.

Setelah empat finalization rounds, state diubah menjadi lima nilai 16-bit dan diformat sebagai lima grup hexadecimal uppercase:

```text
7211-57C4-CD96-CC26-5B67
```

Input license terlebih dahulu diubah ke uppercase, jadi format lowercase juga akan dinormalisasi oleh binary.

## Self-hash dan dekripsi flag

Setelah username dan license lolos, binary tidak langsung menampilkan flag. Ia menghitung SHA-256 dari section `.text` berdasarkan `VirtualSize`, bukan seluruh file:

```text
SHA256(.text) = 540a6fe0dfa677f2a7b1603fd0db282a01d77ba385ab670729f7b5d95670af3d
```

Master key dibentuk dengan formula:

```text
master = SHA256(
    username
    || 0x1f
    || uppercase_license
    || 0x1f
    || SHA256(.text)
    || anti_debug_mask
)
```

Untuk kondisi normal:

```text
master = f2fac42b79cc86a90753633f4efee6794eb709ce3eace088d6e4cc1abf0ef1ce
```

Keystream sepanjang 96 byte dibuat dari tiga digest:

```text
block[i] = SHA256(master || uint32_le(i)), i = 0, 1, 2
```

Blob terenkripsi 96 byte di RVA `0x6280` di-XOR dengan gabungan tiga block tersebut. Plaintext yang keluar:

```text
LYKNCTF{k3yg3n_h3ll_s3lfh4sh_4ntidbg_h1dd3n_us3r_2026}
```

Binary memvalidasi plaintext sekali lagi menggunakan:

```text
SHA256("LYKN2026" || plaintext)[:8]
```

Nilai yang diharapkan adalah:

```text
7d b5 1c 69 a8 dd 79 26
```

Checksum hasil dekripsi cocok, jadi flag bukan hasil tebakan atau patch paksa.

## Solver

Solver hanya memakai Python standard library. Ia mem-parsing section table PE, membangun tabel RC4, memulihkan username, membuat license, menghitung self-hash, lalu mendekripsi flag.

```bash
python3 solve.py KeygenMe.exe
```

Output:

```text
[+] Username : th3_LYKN_v3nd0r
[+] License  : 7211-57C4-CD96-CC26-5B67
[+] Flag     : LYKNCTF{k3yg3n_h3ll_s3lfh4sh_4ntidbg_h1dd3n_us3r_2026}
```
