# Writeup Challenge Crypto: casino

Jadi di challenge ini, kita dikasih akses ke sebuah casino online lewat `nc`. Kita dikasih modal awal 1000 credits, tapi harga flag-nya mahal banget, yaitu 50.000 credits. 

### Analisis Awal
Pas pertama kali baca source code `chall.py`, ada satu hal yang langsung bikin "ngeh":
```python
rng = random.Random(secrets.randbits(256))
```
Challenge ini pake library `random` bawaan Python. Masalahnya, library `random` di Python itu pake algoritma **Mersenne Twister**. Walaupun seed-nya pake `secrets.randbits(256)` (yang sebenernya aman), algoritma Mersenne Twister itu sendiri **bukan** *cryptographically secure PRNG*.

Artinya apa? Kalau kita bisa ngumpulin cukup banyak output dari generatornya, kita bisa "cloning" atau nebak state internal-nya, terus kita bisa prediksi angka apa yang bakal keluar selanjutnya.

### Strategi "Nge-cheat"
Mersenne Twister (MT19937) itu punya state berukuran 624 integer (masing-masing 32-bit). Di kodenya, setiap kali kita main roulette atau slots, sistem bakal manggil `rng.getrandbits(32)` buat bikin "ticket id".

Rencananya gini:
1. Main roulette sebanyak 624 kali.
2. Setiap ronde, kita pasang bet kecil aja (1 credit) biar modal nggak abis.
3. Kita catat setiap `ticket id` yang keluar.
4. Masukin 624 ticket id tadi ke library `randcrack`.
5. Setelah dapet state-nya, kita prediksi `ticket id` ronde berikutnya.
6. Hitung angka menangnya (`ticket % 37`).
7. All-in modal kita ke angka itu.
8. Profit! Terus beli flag-nya.

### Scripting
Daripada manual ngetik 624 kali (bisa gempor tangan), mending kita automasi pake `pwntools` dan `randcrack`.

Inti dari script solve-nya:
```python
# Ngumpulin data
for i in range(624):
    r.sendlineafter(b'> ', b'1') # Main roulette
    r.sendlineafter(b'stake: ', b'1')
    r.sendlineafter(b'number (0-36): ', b'0')
    r.recvuntil(b'ticket id: ')
    ticket = int(r.recvline().strip(), 16)
    rc.submit(ticket) # Kasih datanya ke randcrack

# Prediksi & All-in
predicted_ticket = rc.predict_getrandbits(32)
winning_number = predicted_ticket % 37
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'stake: ', str(balance).encode()) # Pasang semua modal
r.sendlineafter(b'number (0-36): ', str(winning_number).encode())
```

### Eksekusi
Pas script-nya jalan, dia bakal grinding ngumpulin data dulu. Setelah dapet 624 ticket, boom! Tebakannya tepat sasaran. Modal yang tadinya cuma sisa dikit langsung naik drastis jadi 31.680 credits. Main sekali lagi biar dapet 1 juta lebih credits (biar sombong dikit), terus langsung ke menu nomor 3 buat beli flag.

**Flag:**
`CBC{st0p_gambling_st4rt_predicting!!_f8cad9}`

Pelajaran hari ini: Jangan pernah pake `random` buat urusan keamanan atau duit kalau nggak mau di-crack sama orang!
