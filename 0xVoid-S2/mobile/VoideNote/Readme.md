# VoidNotes

## Ringkasan

Flag disimpan di `assets/secret_note.bin`. File tersebut bukan enkripsi yang kuat: aplikasi hanya melakukan XOR satu byte dengan konstanta `0x55`.

## File Challenge

- `VoidNotes.apk` — Android APK berisi DEX, manifest, resource, dan asset rahasia.

## Analisis Awal

`file` mengidentifikasi `VoidNotes.apk` sebagai Android package. Isi APK terdiri dari `AndroidManifest.xml`, `resources.arsc`, `classes.dex`, dan `assets/secret_note.bin` berukuran 34 byte.

Strings pada resource menyebut `NoteDecryptor.java` dan asset `assets/secret_note.bin`. Manifest menunjukkan activity utama `com.voidnotes.MainActivity`.

## Analisis Static

DEX dapat didekompilasi dengan JADX. `MainActivity` memasang handler tombol `Decrypt Secret Note` yang menjalankan:

```java
NoteDecryptor.decrypt(NoteDecryptor.readAsset(mainActivity, "secret_note.bin"))
```

Implementasi `NoteDecryptor.decrypt()` adalah:

```java
public static final int KEY = 85;

for (int i = 0; i < encrypted.length; i++) {
    decrypted[i] = (byte) (encrypted[i] ^ 85);
}
```

Konstanta 85 sama dengan `0x55`. Tidak ada validasi tambahan atau key derivation.

## Analisis Dynamic

Asset diekstrak dan di-XOR dengan `0x55`. Hasilnya berupa teks UTF-8:

```text
0xV0ID{h4rdc0d3d_4ss3ts_4r3_tr4sh}
```

Hasil ini juga direproduksi oleh `solve.py` yang membaca asset langsung dari APK.

## Algoritma Validasi atau Encoding

Untuk setiap byte ciphertext `c`, plaintext dihitung dengan:

```text
p = c XOR 0x55
```

XOR bersifat involutif, sehingga operasi yang sama juga dapat dipakai untuk membalikkan encoding.

## Penyusunan Solve Script

`solve.py` membuka `VoidNotes.apk` sebagai ZIP, membaca `assets/secret_note.bin`, menerapkan XOR `0x55` pada setiap byte, lalu mendecode hasilnya sebagai UTF-8.

## Cara Menjalankan

```bash
python3 solve.py
```

## Flag

`0xV0ID{h4rdc0d3d_4ss3ts_4r3_tr4sh}`

## Catatan

Klaim bahwa note terenkripsi aman terbantahkan karena key dan seluruh algoritma berada di `classes.dex`, sedangkan ciphertext berada sebagai asset yang dapat dibaca langsung dari APK.
