# I HATE THIS APP

- **CTF:** LYKNCTF 2026
- **Category:** Reverse
- **File:** `fuoverflow_learning.exe`
- **Flag:** `LYKNCTF{setwindowdisplayaffinity}`

## Ringkasan

Binary ini adalah aplikasi Windows x64 berbasis Tauri. Proteksi screenshot-nya bukan trik rendering atau transparansi window. Aplikasi memanggil WinAPI `SetWindowDisplayAffinity` dengan affinity `0x11`, yaitu mode yang mengecualikan window dari hasil capture.

## Identifikasi file

```bash
file fuoverflow_learning.exe
```

```text
fuoverflow_learning.exe: PE32+ executable for MS Windows 6.00 (GUI), x86-64, 6 sections
```

String di binary menunjukkan komponen Tauri dan beberapa command terkait capture protection:

```bash
strings -a -n 5 fuoverflow_learning.exe | grep -iE 'capture_protection|content_protected'
```

Potongan yang relevan:

```text
enable_capture_protection
disable_capture_protection
set_content_protected
```

Nama tersebut masih berada di level command dan wrapper Tauri. Fungsi native Windows yang benar-benar mengatur proteksi capture bisa dilihat dari import table.

## Mencari fungsi anti-screenshot

```bash
objdump -x fuoverflow_learning.exe \
  | sed -n '/DLL Name: user32.dll/,/DLL Name:/p' \
  | grep -i display
```

```text
00b1aaa8  <none>  0000  SetWindowDisplayAffinity
```

`SetWindowDisplayAffinity` adalah fungsi dari `user32.dll` yang menentukan apakah konten sebuah window boleh muncul pada mekanisme screen capture.

## Verifikasi call-site

Xref ke entry IAT tersebut ditemukan lewat disassembly:

```bash
objdump -d -Mintel fuoverflow_learning.exe \
  | grep -i -B8 -A12 '140b1aaa8'
```

Potongan wrapper yang paling jelas:

```asm
14098c580:  sub    rsp,0x38
14098c584:  mov    rcx,QWORD PTR [rcx+0x8]
14098c588:  xor    eax,eax
14098c58a:  test   dl,dl
14098c58c:  mov    edx,0x11
14098c591:  cmove  edx,eax
14098c594:  call   QWORD PTR [rip+0x18e50e] # 0x140b1aaa8
```

Argumen WinAPI x64 dikirim melalui register:

- `rcx` berisi handle window (`HWND`).
- `edx` berisi nilai display affinity.
- Saat boolean aktif, `edx = 0x11`.
- Saat boolean nonaktif, `cmove` menggantinya menjadi `0`.

Nilai `0x11` adalah `WDA_EXCLUDEFROMCAPTURE`, sedangkan `0` adalah `WDA_NONE`. Jadi wrapper tersebut mengaktifkan atau mematikan proteksi screenshot melalui `SetWindowDisplayAffinity`.

## Solver

`solve.py` melakukan parsing PE secara langsung menggunakan standard library Python. Script membaca import directory, mencari fungsi anti-screenshot pada `user32.dll`, lalu membentuk flag dengan nama fungsi lowercase.

```bash
python3 solve.py fuoverflow_learning.exe
```

```text
[+] DLL      : user32.dll
[+] Function : SetWindowDisplayAffinity
[+] Flag     : LYKNCTF{setwindowdisplayaffinity}
```

## Flag

```text
LYKNCTF{setwindowdisplayaffinity}
```
