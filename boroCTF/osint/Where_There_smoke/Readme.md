# Where there's smoke, there's fire

**CTF:** boroCTF  
**Category:** OSINT  
**Author:** Franklin  
**Challenge:** Where there's smoke, there's fire  
**Flag:** `boroCTF{Eagle_Point_Dr}`

## Challenge

```txt
My dad told me a story about how around the time of Halo 3's release, when he was driving home, he saw a massive plume of smoke in the distance while he was coming off of Butterfly Court onto Turtle Creek. What's even crazier is that that a Google Maps car was right behind him. I wonder if it ever got onto the maps? To this day, he's wondered if it was captured on camera. Do you know the former name of the street where the fire occured?

Flag Format: boroCTF{Street_Suffix}
```

## Quick read

Clue utamanya bukan cuma `smoke` dan `fire`, tapi kombinasi:

```txt
around the time of Halo 3's release
Butterfly Court -> Turtle Creek
Google Maps car was right behind him
```

Halo 3 rilis September 2007. Jadi yang dicari adalah kejadian lama dari era awal Google Street View, bukan Street View terbaru.

## Recon awal

Query awal yang masuk akal:

```txt
"Butterfly Court" "Turtle Creek" "Google Maps" fire
"Butterfly Court" "Turtle Creek" "smoke"
"Google Street View" "house fire" "smoke"
"Google Maps caught a house fire"
"Google Maps car" "house fire" "September 2007"
```

Hasil yang relevan bukan langsung dari Google Maps, tapi dari artikel/forum lama yang membahas momen Google Street View menangkap rumah terbakar.

## Rabbit hole

Ada beberapa jebakan yang bikin gampang salah submit:

1. **Mencari di Street View sekarang**  
   Street View terbaru sudah berubah. Kalau cuma pakai imagery saat ini, smoke/fire lama tidak akan muncul.

2. **Terlalu fokus ke `Turtle Creek`**  
   Banyak lokasi bernama Turtle Creek. Clue ini perlu digabung dengan `Butterfly Court` dan cerita Google Maps car.

3. **Menganggap harga `$980,148`-style clue seperti challenge spreadsheet sebelumnya**  
   Ini OSINT murni. Tidak ada file metadata atau hidden payload.

4. **Submit full suffix `Drive`**  
   Lokasi memang sering ditulis sebagai `Eagle Point Drive`, tapi flag meminta format `Street_Suffix`. Label lama/pendek di map ditulis `Eagle Point Dr`, jadi suffix yang dipakai adalah `Dr`.

## Titik terang

Pencarian soal Google Street View dan rumah kebakaran mengarah ke arsip lama tentang momen Google Maps menangkap rumah terbakar di area Arkansas.

Salah satu jejak lama menyebut kejadian Google Maps/Street View menangkap smoke/fire sekitar September 2007. Ini cocok dengan clue `around the time of Halo 3's release`.

Lokasinya mengerucut ke area sekitar:

```txt
Butterfly Court
Turtle Creek
Eagle Point Dr
```

Dari screenshot/arsip lama, jalan yang terkait dengan fire tersebut berlabel:

```txt
Eagle Point Dr
```

## Validasi lokasi

Rute pada prompt:

```txt
coming off of Butterfly Court onto Turtle Creek
```

cocok dengan area perumahan yang punya jalan-jalan tersebut. Lalu arsip kejadian fire/Street View mengarahkan ke `Eagle Point Dr`.

Jadi street yang dicari bukan `Butterfly Court` dan bukan `Turtle Creek`, melainkan jalan tempat fire tersebut terjadi:

```txt
Eagle Point Dr
```

## Kenapa bukan `Eagle_Point_Drive`

Submit awal dengan suffix lengkap:

```txt
boroCTF{Eagle_Point_Drive}
```

ditolak.

Flag format memberi hint:

```txt
boroCTF{Street_Suffix}
```

Street suffix pada label map adalah `Dr`, bukan `Drive`.

Submit yang benar:

```txt
boroCTF{Eagle_Point_Dr}
```

## Reference trail

Jejak yang dipakai saat recon:

```txt
https://forums.thefirepanel.com/t/that-one-time-google-maps-caught-a-house-fire/8576
https://sfist.com/2008/08/11/google_street_view_captures_image_o/
```

Gunakan source lama/arsip seperti ini karena kejadian Street View tahun 2007 sering hilang dari tampilan Google Maps modern.

## Flag

```txt
boroCTF{Eagle_Point_Dr}
```
