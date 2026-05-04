# Office

Kategori: Reverse Engineering

Flag:

```text
CBC{b3w4r3_h1dd3n_m4cr0s}
```

## TL;DR

File challenge berupa `Game.xlsm`, jadi ini bukan sekadar spreadsheet biasa. Di dalamnya ada macro VBA yang menjalankan PowerShell. PowerShell tersebut bertahap mendecode payload lain dari sheet Excel yang disembunyikan.

Alur besarnya:

```text
Game.xlsm
-> VBA Workbook_Open
-> PowerShell EncodedCommand
-> C# helper untuk hash + AES
-> gate hostname WORK-PC
-> gate username Fischer
-> decrypt .NET assembly
-> ambil prefix flag dari logic registry
-> decrypt PNG berisi suffix flag
```

## 1. Enumerasi Awal

Pertama cek tipe file:

```bash
file Game.xlsm Game.7z
```

Hasilnya:

```text
Game.xlsm: Microsoft Excel 2007+
Game.7z:   7-zip archive data
```

Karena `xlsm` sebenarnya adalah ZIP berisi XML dan macro, isi filenya bisa dilihat dengan:

```bash
unzip -l Game.xlsm
```

Beberapa file yang penting:

```text
xl/workbook.xml
xl/worksheets/sheet1.xml
xl/worksheets/sheet2.xml
xl/sharedStrings.xml
xl/vbaProject.bin
```

Di `xl/workbook.xml` ada petunjuk menarik:

```xml
<sheet name="Data" sheetId="2" state="veryHidden" r:id="rId2"/>
```

Artinya workbook punya sheet bernama `Data` yang sengaja disembunyikan dengan mode `veryHidden`. Sheet ini akhirnya memang jadi tempat penyimpanan payload.

## 2. Macro VBA

Macro bisa diekstrak memakai `olevba`:

```bash
olevba Game.xlsm
```

Bagian pentingnya ada di `Workbook_Open()`. Macro melakukan XOR kecil untuk membentuk beberapa string. Setelah dideobfuscate, string tersebut adalah:

```text
Data
powershell.exe
 -WindowStyle Hidden -EncodedCommand
```

Macro mengambil tiga cell dari sheet `Data`:

```text
XFD1048568
XFD1048569
XFD1048570
```

Ketiga cell itu digabung, lalu dijalankan sebagai PowerShell `EncodedCommand`.

Jadi dari sini jelas bahwa challenge tidak selesai di Excel formula. Macro hanya loader untuk payload PowerShell berikutnya.

## 3. Decode PowerShell Stage Pertama

Payload di cell tersebut adalah base64 UTF-16LE, format standar untuk PowerShell `-EncodedCommand`.

Setelah didecode, stage pertama isinya membuat array string `$Sd886`, menggabungkannya, decode base64 lagi, lalu mengeksekusi hasilnya:

```powershell
$IVVvPHr = [System.Text.Encoding]::Unicode.GetString(
    [Convert]::FromBase64String([string]::Join("", $Sd886))
)
iex $IVVvPHr
```

Payload berikutnya berisi C# helper class bernama:

```text
XJJfQh0HMY
```

Class ini punya tiga fungsi penting:

```text
LsXxaQ        -> hash custom untuk hostname
Pia2wRPUo4iX  -> hash custom lain untuk key berikutnya
HUzqMxVCPuxJ  -> AES-CBC decrypt, key = SHA256(password), IV = null bytes
```

## 4. Gate Hostname

Stage ini mengecek hostname komputer:

```powershell
$expectedHash = "A045A54E5737EF"
$hostname = $env:COMPUTERNAME

if (([XJJfQh0HMY]::LsXxaQ($hostname, 3735928559) -ne $expectedHash) -and
    ($hostname.Length -ne 7)) {
    exit
}
```

Angka `3735928559` adalah `0xDEADBEEF`.

Fungsi `LsXxaQ` hanya operasi byte sederhana: rotate, XOR dengan seed, lalu update seed. Karena tidak ada hashing kriptografis sungguhan, hasilnya bisa dibalik byte per byte.

Membalik:

```text
A045A54E5737EF
```

menghasilkan hostname:

```text
WORK-PC
```

Setelah hostname valid, fungsi berikutnya dipanggil:

```powershell
[XJJfQh0HMY]::Pia2wRPUo4iX($hostname, 3405691582)
```

`3405691582` adalah `0xCAFEBABE`. Dengan state internal yang masih berlanjut, hasilnya:

```text
FB11FE0C146FAC
```

Nilai ini cocok dengan cell:

```text
Data!XFD1048572
```

Lalu dipakai sebagai password AES untuk decrypt blob di:

```text
Data!XFD1048573
```

## 5. Gate Username

Payload hasil decrypt tadi melakukan hal yang sama, tapi kali ini terhadap username:

```powershell
$JjQnfD = $env:USERNAME
$QVudi = "FDDE36E35BFC28"

if (([XJJfQh0HMY]::Pia2wRPUo4iX($JjQnfD, 3405691582) -ne $QVudi) -and
    ($JjQnfD.Length -ne 7)) {
    exit
}
```

Yang perlu diperhatikan: class C# memakai static seed. Jadi state dari pengecekan hostname masih mempengaruhi hasil pengecekan username.

Dengan state yang benar, hash ini bisa dibalik menjadi:

```text
Fischer
```

Username `Fischer` lalu dipakai sebagai password AES untuk decrypt blob di:

```text
Data!XFD1048574
```

## 6. Decrypt Assembly .NET

Payload berikutnya kembali memakai hostname `WORK-PC`. Ia mengambil empat cell besar:

```text
Data!XFD1048560
Data!XFD1048561
Data!XFD1048562
Data!XFD1048563
```

Keempatnya digabung dan didecrypt dengan AES, password:

```text
WORK-PC
```

Hasil decrypt adalah file PE/.NET assembly:

```text
flag_shellcode
```

Kalau disimpan sementara dan dicek:

```bash
file stage4.dll
```

hasilnya:

```text
PE32 executable (DLL) Intel 80386 Mono/.Net assembly
```

Method yang dipanggil oleh PowerShell:

```text
nksCTGRr.emcbDe4wAa()
```

## 7. Logic di Assembly

Disassembly dengan `monodis` memperlihatkan assembly ini membaca registry:

```text
HKCU\SOFTWARE\CTFChallenge
Value: FlagPart1
```

Nama registry key dan value tidak terlihat langsung di source karena disimpan sebagai byte XOR `0x42`. Setelah didecode:

```text
SOFTWARE\CTFChallenge
FlagPart1
```

Assembly lalu membangun string:

```text
MachineName:UserName:CBC2026:<registry value>
```

Karena hostname dan username sudah diketahui, formatnya menjadi:

```text
WORK-PC:Fischer:CBC2026:<registry value>
```

String tersebut diproses oleh fungsi `REcPQ3X`, lalu dibandingkan dengan 36 byte static di assembly.

Fungsi `REcPQ3X` reversible. Ia bekerja per 4 byte:

```text
block ^= previous
block += key1
block = rol32(block, 11)
previous = block
```

Dengan membalik operasi itu terhadap target static, plaintext yang didapat:

```text
WORK-PC:Fischer:CBC2026:CBC{b3w4r3
```

Jadi isi registry `FlagPart1` yang diharapkan adalah prefix flag:

```text
CBC{b3w4r3
```

Tidak perlu benar-benar membuat registry Windows. Cukup balik transformnya secara offline.

## 8. Decode PNG Final

Setelah registry value dianggap valid, assembly menghitung seed dari:

```text
CBC{b3w4r3
```

Seed ini dipakai untuk XOR PRNG terhadap blob besar di section `.sdata`. Hasilnya adalah PNG valid:

```text
89 50 4E 47 0D 0A 1A 0A ...
```

PNG tersebut berisi teks:

```text
_h1dd3n_m4cr0s}
```

Gabungan prefix dari assembly dan suffix dari PNG:

```text
CBC{b3w4r3 + _h1dd3n_m4cr0s}
```

Flag final:

```text
CBC{b3w4r3_h1dd3n_m4cr0s}
```

## Solver

Solver sudah dibuat di `solve.py`. Script ini tidak menjalankan macro Excel. Semua tahap dilakukan offline:

1. parse `sharedStrings.xml` dan sheet `Data`,
2. decode PowerShell stages,
3. balik hash hostname dan username,
4. decrypt AES payload,
5. parse section `.sdata` dari assembly,
6. balik transform registry,
7. decrypt PNG final,
8. OCR suffix dari PNG.

Jalankan:

```bash
source /home/nata/ctf_env/bin/activate
python solve.py
```

Output:

```text
<FLAG>CBC{b3w4r3_h1dd3n_m4cr0s}</FLAG>
```
