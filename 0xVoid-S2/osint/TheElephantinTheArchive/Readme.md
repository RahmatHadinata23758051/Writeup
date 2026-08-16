# The Elephant in the Archive — OSINT Writeup

## Challenge

**Category:** OSINT
**Challenge:** The Elephant in the Archive

Diberikan sebuah gambar `evidence.png` yang menampilkan bangunan berbentuk gajah beserta beberapa petunjuk:

* `CASE FILE 1896`
* `NOT A STATUE. PEOPLE ENTERED IT.`
* `31 / 63 / 25`
* `One sibling survives. Two vanished.`
* `A contemporary count conflicts with a descendant's retelling.`
* `SEARCH THE OPEN WEB. TRUST PRIMARY PAGES. EVENT DATE != REPORT DATE.`

Kita diminta mendapatkan lima nilai:

1. Nomor paten enam digit.
2. Nama satu ruangan persis seperti yang tercetak dalam tourist guide tahun 1887.
3. Jumlah **full working days** menurut guide 1887.
4. Nomor public school yang saat ini berada dekat lokasi historis.
5. Tanggal kebakaran sebenarnya, bukan tanggal koran memberitakannya.

Format flag:

`0xV01D{patent_room_days_school_yyyymmdd}`

---

# 1. Mengidentifikasi Bangunan

Petunjuk pertama yang paling kuat adalah gambar bangunan berbentuk **gajah raksasa**.

Tulisan:

> `NOT A STATUE. PEOPLE ENTERED IT.`

menunjukkan bahwa objek tersebut bukan patung, tetapi bangunan yang dapat dimasuki.

Pencarian awal dapat menggunakan query:

`1896 elephant shaped building Coney Island`

atau:

`elephant hotel burned 1896`

Hasil pencarian mengarah ke **Elephantine Colossus**, yang juga dikenal sebagai **Elephant Hotel**, sebuah bangunan berbentuk gajah di Coney Island, New York.

Petunjuk:

`One sibling survives. Two vanished.`

juga cocok dengan sejarah struktur karya **James V. Lafferty**. Situs resmi Lucy the Elephant menjelaskan bahwa terdapat tiga struktur gajah yang berkaitan dengan desain Lafferty dan **Lucy the Elephant adalah satu-satunya yang masih utuh**. Dua struktur lainnya adalah Light of Asia dan Elephantine Colossus.

Dengan demikian target challenge dapat diidentifikasi sebagai:

**Elephantine Colossus / Elephant Hotel — Coney Island**

---

# 2. Mencari Nomor Paten

Challenge meminta:

> The six-digit US patent number for the animal-shaped building idea.

Query yang digunakan:

`James V Lafferty elephant building patent`

Sumber yang sangat kuat ditemukan di **U.S. National Archives**.

National Archives menjelaskan bahwa James V. Lafferty memperoleh paten untuk bangunan berbentuk hewan tersebut pada 5 Desember 1882 dengan nomor:

**Patent No. 268,503**.

Karena format challenge meminta enam digit tanpa tanda baca:

**Token #1**

`268503`

---

# 3. Menemukan Tourist Guide Tahun 1887

Challenge secara spesifik meminta informasi dari:

> the 1887 tourist guide

Pencarian terhadap sumber tersebut menghasilkan buku:

**J. Perkins Tracy — The Tourists Companion and Guide to Coney Island, Fort Hamilton, Bath Beach, Sheepshead Bay, Rockaway Beach and Far Rockaway**

Buku tersebut diterbitkan oleh Austin Publishing Company pada **1887**. Salinan digital Google Books berasal dari koleksi Princeton University.

HathiTrust juga mencatat edisi yang sama sebagai terbitan tahun 1887 dengan akses full-view yang berasal dari Library of Congress.

Bagian inilah yang menjadi kunci utama challenge karena kita harus mempercayai **sumber sezaman**, bukan retelling modern.

---

# 4. Room Name — Jebakan `through` vs `trough`

Pada bagian deskripsi ruangan Elephantine Colossus terdapat daftar berbagai kamar.

Di antara daftar tersebut tercetak:

`1 through room from which the Elephant is feeding`

Ejaan yang secara intuitif terasa benar adalah **trough**, karena *trough* berarti tempat makan hewan.

Tetapi challenge mengatakan:

> Preserve the printed spelling.

Artinya kita tidak diperbolehkan memperbaiki typo atau ejaan aneh dari sumber asli.

Transkripsi lain dari daftar kamar yang sama juga mempertahankan bentuk:

`1 through room from which the Elephant is feeding.`

Jadi nilai yang harus digunakan adalah:

**Token #2**

`through`

Bukan:

`trough`

Ini merupakan salah satu jebakan utama challenge.

---

# 5. Full Working Days — Jebakan `129` vs `120`

Ini merupakan bagian tersulit dari challenge.

Pada awalnya, sumber modern yang sangat meyakinkan memberikan angka:

**129 full working days**

Situs resmi Lucy the Elephant menyebut bahwa Elephantine Colossus membutuhkan **263 pekerja dan 129 full working days** untuk diselesaikan. Situs tersebut juga menyebut 31 ruangan, 65 jendela, dan 25 lampu listrik.

Namun challenge memberikan clue:

> `A contemporary count conflicts with a descendant's retelling.`

Kata **contemporary** menunjukkan kita harus menggunakan sumber yang berasal dari periode ketika Elephantine Colossus masih berdiri.

Karena itu sumber modern tidak boleh langsung dipercaya.

Saat scan guide tahun **1887** diperiksa langsung, terdapat kalimat:

> `It took 263 men 120 full working days to build it`

Dengan demikian angka di sumber sezaman adalah:

**120**

bukan:

**129**

Scan halaman yang digunakan saat investigasi dapat dilihat di sini:

[Scan guide 1887](sandbox:/mnt/data/guide_render/page33.png)

Hal ini menjelaskan maksud clue tentang konflik antara **contemporary count** dan **descendant's retelling**.

Sumber modern Lucy memberikan `129`, sedangkan guide sezaman tahun 1887 memberikan `120`.

Maka:

**Token #3**

`120`

---

# 6. Memahami Clue `31 / 63 / 25`

Evidence image juga menampilkan:

`31 / 63 / 25`

Angka-angka tersebut ternyata bukan angka acak.

Guide sezaman menggambarkan Elephantine Colossus dengan:

* **31 rooms**
* **63 windows**
* **25 electric lights**

Sementara retelling modern Lucy masih menyebut 31 rooms dan 25 electric lights, tetapi memberikan angka **65 windows**, bukan 63.

Artinya clue `31 / 63 / 25` sekaligus memberikan indikasi bahwa pembuat challenge mengharapkan kita kembali ke **sumber historis asli**, bukan hanya mengambil angka dari halaman sejarah modern.

Ini juga memperkuat bahwa angka `120` dari guide 1887 adalah nilai yang harus digunakan.

---

# 7. Menentukan Public School

Berikutnya challenge meminta:

> The public school number currently near the historical site, normalized as `psNN`.

Kita perlu mencari posisi historis Elephantine Colossus dan membandingkannya dengan lokasi modern.

Pencarian:

`Elephant Hotel Coney Island PS 90`

menghasilkan halaman dari **Coney Island History Project**.

Mereka menjelaskan bahwa hotel berbentuk gajah tersebut dahulu berada **di seberang lokasi sekolah yang sekarang menjadi P.S. 90** di West 12th Street.

Selanjutnya informasi sekolah diverifikasi menggunakan sumber resmi **New York City Public Schools**.

Sekolah tersebut adalah:

**P.S. 90 Edna Cohen School**

dengan:

* School Number: `K090`
* Address: `2840 West 12 Street, Brooklyn, NY 11224`

Challenge meminta normalisasi sebagai:

`psNN`

Jadi `P.S. 90` menjadi:

**Token #4**

`ps90`

---

# 8. Menentukan Tanggal Kebakaran

Bagian terakhir meminta:

> The fire date itself as YYYYMMDD, not the next day's newspaper date.

Evidence bahkan memberikan warning:

> `EVENT DATE != REPORT DATE.`

Ini menunjukkan bahwa mengambil tanggal pada header surat kabar secara langsung akan menghasilkan jawaban salah.

Pencarian arsip koran melalui Library of Congress menghasilkan berita mengenai kebakaran Elephantine Colossus.

Berita tersebut memiliki dateline:

**September 28**

tetapi teks laporan mengatakan Elephant Coney Island telah hancur oleh kebakaran **late last night**.

Artinya:

* Report date = 28 September 1896
* Fire/event date = malam sebelumnya
* Event date = **27 September 1896**

Hal tersebut dapat diverifikasi secara independen melalui situs resmi Lucy the Elephant, yang menyatakan bahwa Elephantine Colossus terbakar pada **Sunday evening, September 27, 1896**.

Format yang diminta:

`YYYYMMDD`

menjadi:

**Token #5**

`18960927`

---

# 9. Penyusunan Flag

Semua token yang berhasil dikumpulkan:

| Field             | Value      |
| ----------------- | ---------- |
| Patent            | `268503`   |
| Room              | `through`  |
| Full working days | `120`      |
| School            | `ps90`     |
| Fire date         | `18960927` |

Gabungkan mengikuti format challenge:

`0xV01D{patent_room_days_school_yyyymmdd}`

Sehingga didapat:

**FLAG**

`0xV01D{268503_through_120_ps90_18960927}`

---

# OSINT Tracker

| No. | Target                    | Query / Pivot                                  | Source                       | Temuan                                                                                                                      | Token                  |
| --- | ------------------------- | ---------------------------------------------- | ---------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| 1   | Identify building         | `1896 elephant shaped building Coney Island`   | Lucy the Elephant            | Target adalah Elephantine Colossus, salah satu dari tiga struktur gajah Lafferty.                                           | `Elephantine Colossus` |
| 2   | Patent                    | `James V Lafferty elephant building patent`    | U.S. National Archives       | Patent No. 268,503 diberikan kepada Lafferty pada 1882.                                                                     | `268503`               |
| 3   | Identify historical guide | `"Tourists Companion" Coney Island 1887 Tracy` | Google Books / HathiTrust    | Guide J. Perkins Tracy diterbitkan pada 1887.                                                                               | —                      |
| 4   | Room label                | Inspect 1887 guide                             | 1887 guide scan              | Tercetak `through room`, bukan `trough room`.                                                                               | `through`              |
| 5   | Construction days         | Inspect 1887 guide                             | 1887 guide scan              | Guide sezaman mencatat `120 full working days`. Modern Lucy retelling menggunakan `129`.                                    | `120`                  |
| 6   | Numbers clue              | Compare `31 / 63 / 25`                         | 1887 guide + Lucy history    | 31 rooms / 63 windows / 25 electric lights membantu menunjukkan perbedaan dengan retelling modern yang menyebut 65 windows. | —                      |
| 7   | Historical location       | `Elephant Hotel Coney Island PS 90`            | Coney Island History Project | Elephant Hotel dahulu berada di seberang lokasi P.S. 90.                                                                    | `ps90`                 |
| 8   | Verify school             | `P.S. 90 West 12 Street Brooklyn`              | NYC Public Schools           | P.S. 90 Edna Cohen School / K090 berada di 2840 West 12 Street.                                                             | `ps90`                 |
| 9   | Fire report               | `Coney Elephant burned September 1896`         | Library of Congress          | Laporan bertanggal Sept. 28 menyatakan kebakaran terjadi `late last night`.                                                 | `18960927`             |
| 10  | Verify event date         | Search official surviving sibling history      | Lucy the Elephant            | Situs resmi menyebut Sunday evening, Sept. 27, 1896.                                                                        | `18960927`             |

---

# Key Takeaways

Challenge ini memiliki beberapa jebakan OSINT yang cukup bagus.

### 1. Exact transcription matters

Kata yang terlihat seperti typo tidak boleh langsung diperbaiki.

`through` ≠ `trough`

Karena challenge secara eksplisit meminta **printed spelling**, nilai yang benar tetap:

`through`

### 2. Primary source beats modern retelling

Sumber modern memberikan:

`129 full working days`

tetapi guide sezaman tahun 1887 memberikan:

`120 full working days`

Clue:

`A contemporary count conflicts with a descendant's retelling.`

secara langsung mengarahkan investigator untuk memilih angka dari sumber historis.

### 3. Historical location requires a modern pivot

Bangunan sudah tidak ada sejak 1896, sehingga lokasi tidak dapat diverifikasi hanya dengan mencari bangunannya pada peta modern.

Pivot yang digunakan:

`historic Elephant Hotel location → West 12th Street → P.S. 90 → NYC Schools`

menghasilkan:

`ps90`

### 4. Report date is not always event date

Berita koran memiliki tanggal:

`1896-09-28`

tetapi isi berita mengatakan kejadian terjadi pada malam sebelumnya.

Karena challenge meminta **fire date itself**, nilai yang benar adalah:

`1896-09-27`

atau:

`18960927`

---

# Final Flag

**`0xV01D{268503_through_120_ps90_18960927}`**
