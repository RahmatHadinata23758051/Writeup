# Ducks Ping-Pong — Reverse Engineering Writeup

## Informasi challenge

- CTF: V1T CTF 2026
- Kategori: Reverse
- File: `Ducks_Ping-Pong.exe`, `DucksKD.sys`
- Deskripsi: `ever tried kernel reversing before?`

## Triage

```bash
file Ducks_Ping-Pong.exe DucksKD.sys
strings -a Ducks_Ping-Pong.exe
strings -a DucksKD.sys
```

Hasil awal menunjukkan executable Windows x64 dan driver kernel x64. Program user-mode membuka device berikut:

```text
\\.\DucksKD
```

Import yang paling relevan adalah `DeviceIoControl` pada executable, lalu `IoCreateDevice`, `IoCreateSymbolicLink`, `ZwOpenProcess`, dan `ZwReadFile` pada driver.

## Protokol IOCTL

Dispatcher driver berada di `DucksKD.sys` RVA `0x11d0`. Ada tiga IOCTL:

| IOCTL | Fungsi |
|---|---|
| `0x222004` | Membuka sesi dan menyimpan key proses |
| `0x222008` | Mengambil nomor stage yang sudah selesai |
| `0x222000` | Memproses satu stage ping-pong |

Handshake pertama memakai struktur 16 byte:

```c
struct SessionPacket {
    uint32_t magic;      // 0xE7DE0322
    uint32_t reserved;
    uint64_t session_key;
};
```

Driver juga membaca executable pemanggil dari disk dan menghitung FNV-1a section `.text`. Nilainya harus sama dengan:

```text
0x6598ae16e4af8e05
```

Pengecekan ini membuat patch executable secara langsung tidak praktis karena hash `.text` akan berubah.

## Tiga access violation

Executable memasang vectored exception handler di RVA `0x1230`. Tiga callback input sengaja menulis ke alamat invalid yang berbeda. Exception handler mengenali alamat fault, menghitung FNV-1a input, lalu mengirim paket 56 byte melalui IOCTL `0x222000`.

Layout paketnya:

```c
struct StagePacket {
    uint32_t index;
    uint32_t magic;       // 0xE7DE0322
    uint64_t session_key;
    uint64_t nonce;
    uint64_t input_hash;
    uint64_t response;
    uint8_t  extra[16];
};
```

Target FNV-1a untuk masing-masing stage di driver:

```text
stage 0: 0x41f59f05e7b2ab5d
stage 1: 0xf9ac95fed5fbf6a9
stage 2: 0xa4c25ee6cd04dc19
```

Jika hash benar, driver memilih key dari `.rdata` RVA `0x32b0`:

```text
K[0] = 0x4d3a1f7b9e52c806
K[1] = 0x71f4820d3cb96a15
K[2] = 0x0000000000000000
```

Response driver dihitung sebagai:

```text
response = nonce XOR K[index]
```

Executable langsung menghapus `nonce` lagi, lalu menyimpan:

```text
state[index] = input_hash XOR K[index]
```

Karena input yang diterima driver harus memiliki hash target, state sukses dapat direkonstruksi tanpa mencari preimage string:

```text
state[0] = 0x0ccf807e79e0635b
state[1] = 0x885817f3e9429cbc
state[2] = 0xa4c25ee6cd04dc19
```

Stage 1 juga mengembalikan blok 16 byte dari driver RVA `0x32a0`:

```text
effd350f14edd6913077a49a9a205409
```

## Dekripsi akhir

Fungsi final berada di executable RVA `0x1570`. Fungsi ini memastikan counter driver dan counter lokal sama-sama bernilai `3`, mengambil tiga state di atas, lalu memakai dua blok tambahan:

1. Blok 16 byte dari driver.
2. Blok executable RVA `0x34e0` yang didekripsi byte-per-byte dengan XOR `0x55`.

Key kedua menjadi:

```text
889a486e6ec9acfb5a1187ad99241e61
```

Sisa fungsi melakukan penyusunan ulang byte dan XOR, kemudian mencetak 32 byte lewat `putchar`. `solve.py` mengisi state sukses ke global executable dan mengemulasi fungsi final dengan Unicorn. Import Windows yang tidak memengaruhi transformasi diganti stub kecil.

## Menjalankan solver

```bash
source /home/nata/ctf_env/bin/activate
python3 -m pip install pefile unicorn
python3 solve.py
```

Output:

```text
v1t{kn0w_h0w_to_p1ngp0ng_ducks!}
```

## Flag

```text
v1t{kn0w_h0w_to_p1ngp0ng_ducks!}
```
