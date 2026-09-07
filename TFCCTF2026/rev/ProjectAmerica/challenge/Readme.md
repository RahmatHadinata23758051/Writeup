# PROJECT AMERICAS

## Ringkasan

File utama adalah PE Windows 64-bit berbasis Go. Flag tidak muncul sebagai string biasa. `challenge_data/flag.txt` adalah container terenkripsi. Kunci tidak disimpan utuh, tapi dibentuk dari tiga shard di DLL palsu dan program VM di `content/patch_06.dat`.

Hasil akhir:

```
TFCCTF{a_vm_dreams_in_galois_fields_6e91c2}
```

## File Challenge

```
Project_Americas_Setup.exe          PE32+ Windows Go executable
bin/rage_streaming_x64.dll          asset shard role 1
bin/rgsc_socialclub_x64.dll         asset shard role 2
bin/oo2core_9_win64.dll             asset shard role 3
content/patch_06.dat                packed VM program
challenge_data/flag.txt             encrypted outer container
```

## Analisis Awal

`Project_Americas_Setup.exe` adalah binary Windows 64-bit. Symbol Go masih tersedia, jadi fungsi challenge bisa dicari lewat symbol table. Fungsi yang relevan:

```
challenge.unpackProgram
challenge.streamXOR
challenge.extractShard
challenge.hashParts
challenge.runProgram
challenge.deriveMaterial
challenge.blockDecrypt
challenge.decryptFlag
challenge.sealContainer
```

`strings` memperlihatkan tema GTA/RAGE/asset, tapi flag asli tidak ada sebagai plaintext. File `flag.txt` punya header container custom:

```
RSC 07 f1 9a 44 c3
version 4
header size 0x30
ciphertext length 0xb0
```

## Analisis Static

### VM program

`content/patch_06.dat` diawali magic:

```
RPFVM01\n
```

Data setelah magic adalah ASCII85. Alur unpack dari `challenge.unpackProgram`:

```
ASCII85 decode
streamXOR dengan key SHA256 parts("Project-Americas/stage-1", challengeID)
reverse byte order
gzip decompress
parse MATHVM1\x00 instruction stream
```

`challengeID` yang benar:

```
AMERICAS-20dbcdd7061b4ccabfe947ef
```

Program VM berisi 137 instruksi. Tiap instruksi berukuran 8 byte:

```
op, a, b, c, imm32_le
```

### Shard kunci

Masing-masing DLL menyimpan marker `TFCSHARD/V1`. Ada tiga shard 32 byte:

```
bin/rage_streaming_x64.dll       role 1
bin/rgsc_socialclub_x64.dll      role 2
bin/oo2core_9_win64.dll          role 3
```

Shard tidak langsung di-XOR. Setiap shard dimask dulu:

```
mask = hashParts(
    "Microsoft CodeView RSDS",
    challengeID,
    full_asset_path,
    role || "GTA"
)
```

Bagian pentingnya adalah `full_asset_path`, misalnya `bin/rage_streaming_x64.dll`, bukan cuma basename. Setelah unmask, tiga shard di-XOR untuk membentuk root secret:

```
5a4159ffaf885e3485f183692150f4985f859fac1e36639088740063349fccf5
```

### Key ladder

Material kunci dibentuk oleh `challenge.deriveMaterial`:

```
state = hashParts("TFCCTF/key-ladder/v4", rootSecret, challengeID, salt)
repeat:
    block = runProgram(vmProgram, state, counter ^ 0x564d0000)
    state = hashParts("register-fold", state, block)
    output += state
```

Untuk outer container, salt adalah:

```
"RSC7/runtime-seal/" || outer[0x0c:0x1c]
```

Untuk inner container, salt adalah:

```
inner[0x0c:0x1c]
```

### Block cipher

`challenge.blockDecrypt` adalah cipher custom 16 byte / 36 round. Round key dibuat dari 64 byte pertama material:

```
key[i] = rol32((i * 0x9e3779b9) ^ word[i & 15], 11 * i)
```

Mode enkripsi container mirip CBC, tapi tiap block juga di-whitening dengan mask per byte.

Outer decrypt:

```
plain[j] = blockDecrypt(cipher_block)[j]
           ^ previous_cipher_or_iv[j]
           ^ outerMask(block_index, j)
```

Mask outer:

```
outerMask = (((block_index * 0x2f + 31*j) ^ 0xa5) + rol8(13*j, block_index)) & 0xff
```

Inner decrypt:

```
plain[j] = blockDecrypt(cipher_block)[j]
           ^ previous_cipher_or_iv[j]
           ^ ((block_index * 0x1d + 17*j) & 0xff)
```

## Analisis Dynamic

Binary Windows tidak perlu dijalankan. Validasi dilakukan offline dengan solver Python:

1. Outer HMAC diverifikasi menggunakan `HMAC-SHA256(material[64:96], "RSC7-AUTH-V4" || outer_header_ciphertext)`.
2. Outer plaintext berhasil menghasilkan inner container `TFCENC3\x00`.
3. Inner HMAC diverifikasi menggunakan `HMAC-SHA256(material[64:96], inner[:-32])`.
4. Inner ciphertext didekripsi dan PKCS#7 unpad valid.
5. Plaintext berisi flag format `TFCCTF{...}`.

## Algoritma Validasi atau Encoding

Pipeline lengkap:

```
patch_06.dat -> unpack VM program
DLL shards -> unmask -> XOR -> root secret
root secret + VM + outer salt -> outer material
verify outer HMAC
custom block decrypt outer -> inner container
root secret + VM + inner salt -> inner material
verify inner HMAC
custom block decrypt inner -> final plaintext
extract TFCCTF{...}
```

## Penyusunan Solve Script

`solve.py` mengimplementasikan ulang fungsi-fungsi yang dibutuhkan dari disassembly:

```
hashParts
streamXOR
unpackProgram
extractShard/rootSecret
runProgram VM
key ladder deriveMaterial
blockDecrypt
outer container decrypt
inner container decrypt
```

Script tidak brute force dan tidak butuh koneksi remote. Semua data diambil dari file challenge lokal.

## Cara Menjalankan

Dari direktori challenge:

```bash
python3 solve.py
```

Output:

```
<FLAG>TFCCTF{a_vm_dreams_in_galois_fields_6e91c2}</FLAG>
```

## Flag

```
TFCCTF{a_vm_dreams_in_galois_fields_6e91c2}
```
