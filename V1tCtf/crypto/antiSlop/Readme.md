# Slop Anti or Anti SLop

## Informasi Challenge

- **Kategori:** Crypto
- **Deskripsi:** `Wishing you a delicious cup of milky coffee while waiting for the AI to complete the challenge`
- **Flag:** `v1t{1_w0nd3r1ng_w1th0ut_41_c4n_y0u_st1ll_s0lv3_1t_4nyw4y_h0p3_y0u_h4v3_fun_w1th_th4t}`

## Ringkasan

Ciphertext memakai AES-256-GCM. Key diturunkan dari tiga nilai bernama `coffee`, `cream`, dan `sugar`:

```python
K = SHA256(
    b"coffee" + SHA256(csv(coffee)) +
    b"cream"  + SHA256(str(cream)) +
    b"sugar"  + SHA256(str(sugar))
)
```

Tiga nilai tersebut dipulihkan dengan teknik berbeda:

1. `coffee`: integer relation menggunakan PSLQ dari satu evaluasi polinomial berpresisi tinggi.
2. `cream`: interpolasi Lagrange modulo `m` pada `x = 0`.
3. `sugar`: 70 juta repeated modular squaring sesuai fungsi `R`.

Field seperti `h`, `otp`, `coffee = arabica`, `sugar = cube`, dan `cmd` tidak masuk ke jalur pembentukan key. String RSA pada `a` hanya berfungsi sebagai AAD AES-GCM.

## 1. Struktur Enkripsi

Fungsi `E` menunjukkan format field `c`:

```python
y = SHA256(
    b"drip" + SHA256(csv(coffee)) +
    b"cream" + SHA256(str(cream))
)[:12]

c = base64(y + AESGCM(K).encrypt(y, flag, A))
```

Setelah base64 didekode:

```text
12-byte nonce || ciphertext || 16-byte GCM tag
```

Nonce tidak bergantung pada `sugar`. Nilai ini dapat dipakai sebagai oracle untuk memastikan hasil recovery `coffee` dan `cream` sudah benar sebelum menjalankan tahap 70 juta iterasi.

## 2. Recover `coffee` dengan PSLQ

`P(x, coffee)` adalah polinomial berderajat 8 dengan sembilan koefisien integer:

```text
y = c0 + c1*x + c2*x^2 + ... + c8*x^8
```

Output menyediakan lima pasangan `(x, y)` dengan ratusan digit presisi. Satu pasangan sudah cukup karena koefisiennya integer dan relatif kecil dibanding presisi angka yang dicetak.

Untuk satu observasi, susun vektor:

```text
[1, x, x^2, ..., x^8, y]
```

PSLQ mencari relasi integer:

```text
c0 + c1*x + ... + c8*x^8 - y = 0
```

Koefisien yang ditemukan:

```python
coffee = [
    -794776879491038202558712248,
     231978547017104987636113337,
    -1236111155741405863929313341,
    -703614985251603931111397881,
    -914058253825396366167362727,
     1012081845277004387528301932,
     28127542803535647396748015,
     338456460421344523263806475,
    -1220995114101159313257217147,
]
```

Empat observasi lain hanya memberi redundansi.

## 3. Recover `cream`

Fungsi `M` membentuk tiga titik modular dari beberapa elemen `coffee`:

```python
a = v[10]
xs = v[4:7]
ids = v[7:10]
bs = v[11:14]

points = [
    (x, (a * coffee[index] + bias) % m)
    for x, index, bias in zip(xs, ids, bs)
]
```

Dua titik pertama sudah tersimpan langsung pada awal vektor `v`:

```python
(v[0], v[1])
(v[2], v[3])
```

Kelima titik dimasukkan ke fungsi `I`. Implementasinya adalah interpolasi Lagrange modulo `m` yang dievaluasi pada `x = 0`:

```text
cream = f(0) mod m
```

Hasilnya:

```text
cream = 384647880619861103603355431
```

Nonce hasil derivasi menjadi:

```text
d23f0a4a41c9d1e0e580a464
```

Nilai tersebut sama dengan 12 byte pertama field `c`, sehingga recovery PSLQ dan interpolasi sudah valid.

## 4. Recover `sugar`

Fungsi `R` menjalankan operasi berikut sebanyak `z = 70000000` kali:

```python
sugar = r
for _ in range(z):
    sugar = sugar * sugar % n
```

Secara matematis hasilnya adalah:

```text
r^(2^z) mod n
```

Modulus `n` komposit dan orde grupnya tidak diberikan. Tanpa faktorisasi `n`, eksponen tidak dapat direduksi menggunakan fungsi Carmichael. Delay repeated-squaring ini memang bagian anti-automation challenge.

Loop Python murni terlalu lambat. Solver mengompilasi helper C kecil dengan GMP dan membagi pekerjaan menjadi chunk 5 juta iterasi. Setelah setiap chunk, state disimpan pada:

```text
.slop-vdf-checkpoint.json
```

Proses dapat dihentikan lalu dijalankan kembali tanpa mengulang dari awal.

Hasil akhirnya:

```text
653668884593803966785968068300194757722649873920080311581755266227887887682617593977899793804124264628654976234612635937761156905523412862794131482867769041652806187404731784564681924434747047778198781246015257981810337219310559717389426637172878896988973496105005827228108022967536563360699015337109289512127198436284982048363500780707334015012742630761899604859511794865917287983518595747161682921861994698930104887432642695806191828656590408705457558442726143536313118055840864102579591593791567416584309418949995302177139960363538783462744376934011963447795636990247305738506804507114441318207050919640926460208
```

## 5. Dekripsi AES-GCM

Setelah ketiga komponen tersedia:

```python
key = K(coffee, cream, sugar)
nonce = cup[:12]
ciphertext_and_tag = cup[12:]
flag = AESGCM(key).decrypt(nonce, ciphertext_and_tag, A)
```

AAD yang dipakai:

```text
v1t::RSA_NoHashInHere_PoW_OTP::r1muru
```

Authentication tag berhasil diverifikasi dan plaintext berisi flag.

## Solver

Dependency Python:

```bash
source /home/nata/ctf_env/bin/activate
pip install mpmath cryptography
```

Helper VDF membutuhkan GCC dan GMP development headers:

```bash
sudo apt install build-essential libgmp-dev
```

Jalankan:

```bash
python3 solve.py output.txt
```

Jika terhenti, jalankan perintah yang sama. Solver membaca checkpoint terakhir secara otomatis.

Output akhir:

```text
[+] coffee = [-794776879491038202558712248, ..., -1220995114101159313257217147]
[+] cream  = 384647880619861103603355431
[+] nonce  = d23f0a4a41c9d1e0e580a464 (valid)
[+] VDF progress: 70000000/70000000
[+] sugar  = 6536688845938039667859680683001947577...
[+] flag   = v1t{1_w0nd3r1ng_w1th0ut_41_c4n_y0u_st1ll_s0lv3_1t_4nyw4y_h0p3_y0u_h4v3_fun_w1th_th4t}
```

## Flag

```text
v1t{1_w0nd3r1ng_w1th0ut_41_c4n_y0u_st1ll_s0lv3_1t_4nyw4y_h0p3_y0u_h4v3_fun_w1th_th4t}
```
