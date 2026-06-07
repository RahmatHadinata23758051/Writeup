# Bit Miner Writeup

Target: `tcp://instancer.dalctf2026.com:23270`

## Inti Masalah

Bug utamanya ada di `buy()`:

```c
if (price > bits) {
    printf("You don't have enough money for this item\n");
    return;
}

...

Account account = storage_get_account(username);
...
account.bits -= price;
storage_save_account(username, account);
```

Saldo dicek dulu memakai nilai `bits` yang diterima dari `shop()`, lalu akun di-load ulang dari storage sebelum dikurangi.

Artinya ada race / TOCTOU:

1. Session A membuka shop saat saldo cukup.
2. Session A berhenti di prompt konfirmasi.
3. Session B menghabiskan saldo yang sama sampai di bawah harga item.
4. Session A tetap lolos cek karena masih pakai snapshot saldo lama.
5. Saat `account.bits -= price` dijalankan, nilai aktual sudah lebih kecil dari `price`.
6. Karena `bits` bertipe `unsigned long`, subtraction underflow dan berubah jadi nilai sangat besar.

Begitu saldo meledak, flag bisa dibeli langsung.

## Kenapa Bisa Jalan

Harga termurah di shop adalah 10 bits. Jadi cukup bawa saldo ke kisaran 10 sampai 19 bits dulu. Dari state itu:

- Session A buka shop dan pilih item murah.
- Session B beli item murah yang sama.
- Session A konfirmasi.

Jika saldo aktual sudah turun di bawah 10 saat Session A mengeksekusi pembelian, hasil subtraction wrap ke angka maksimum `unsigned long`.

## Langkah Exploit

1. Buat akun baru.
2. Mine sampai saldo minimal 10 bits.
3. Buka shop di session A, pilih upgrade termurah, lalu tahan di prompt konfirmasi.
4. Buka session B dengan akun yang sama.
5. Beli upgrade termurah sekali supaya saldo turun di bawah 10.
6. Kembali ke session A dan konfirmasi.
7. Saldo wrap jadi besar.
8. Beli flag di shop.

## Hasil

Flag yang didapat:

`dalctf{b1t_w4rp1ng_5ucc3s5ful}`

## File

- `solve.py`: exploit otomatis end-to-end
- `README.md`: writeup ini
