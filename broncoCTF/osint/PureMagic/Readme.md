# Pure Magic

**Category:** OSINT  
**Flag:** `bronco{prefire_junkshadow_soldieroffortune88}`

## Overview

Challenge ini menggunakan jejak publik dari komunitas Magic: The Gathering. Tiga komponen flag yang harus ditemukan adalah:

```text
format_deckarchetype_player
```

Hasil akhirnya:

```text
prefire_junkshadow_soldieroffortune88
```

## 1. Mengidentifikasi format

Petunjuk challenge mengarah ke periode Modern sebelum perubahan desain kartu yang dikenal dengan istilah `FIRE` dan sebelum masuknya produk Modern Horizons.

Query yang digunakan:

```text
MTG format before FIRE design Modern
retro Modern format pre FIRE
"PreFIRE" Magic the Gathering
```

Nama format yang ditemukan adalah:

```text
PreFIRE
```

Untuk flag, penulisannya dinormalisasi menjadi lowercase:

```text
prefire
```

## 2. Menemukan archetype deck

Setelah format diketahui, pencarian dipersempit ke deck dan hasil pertandingan yang berkaitan dengan PreFIRE.

Query yang berguna:

```text
"PreFIRE" "Junk Shadow"
"Junk Shadow" MTG deck
site:mtggoldfish.com "Junk Shadow"
```

Nama archetype yang cocok adalah:

```text
Junk Shadow
```

Spasi dihilangkan agar sesuai dengan format flag:

```text
junkshadow
```

`Junk Shadow` merujuk pada shell deck berwarna Abzan/Junk yang menggunakan paket ancaman berbasis pengurangan life seperti strategi Death's Shadow.

## 3. Pivot ke nama pemain

Nama deck kemudian dipakai sebagai pivot untuk mencari pemain yang menggunakannya pada hasil atau halaman deck publik.

Query:

```text
"Junk Shadow" "SoldierofFortune88"
site:mtggoldfish.com/player/SoldierofFortune88
"SoldierofFortune88" MTG
```

Handle pemain yang ditemukan:

```text
SoldierofFortune88
```

Normalisasi untuk flag:

```text
soldieroffortune88
```

## 4. Menggabungkan komponen

Ketiga bagian digabung menggunakan underscore:

```text
prefire
junkshadow
soldieroffortune88
```

Menjadi:

```text
prefire_junkshadow_soldieroffortune88
```

## Flag

```text
bronco{prefire_junkshadow_soldieroffortune88}
```
