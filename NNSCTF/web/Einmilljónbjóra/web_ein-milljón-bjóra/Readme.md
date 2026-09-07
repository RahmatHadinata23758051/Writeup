# Ein milljón bjóra

## Ringkasan

Bug ada di serialisasi kolom `Point` saat backend menerima lokasi dari EXIF `UserComment`. `JsonElement` bukan `ITuple` atau `IList`, sehingga `ClickHouse.Driver` menulis 0 byte untuk kolom `location`. Byte kolom berikutnya lalu bergeser.

## Target dan File

- Target: `https://ein-milljon-bjora-f89a6e88273f.chall.nnsc.tf`
- Backend: `backend/Program.cs` dan `backend/Exif.cs`
- Driver: `ClickHouse.Driver 1.3.0`
- Payload source: `beer-payload-source.png`

## Analisis Awal

Request GPS EXIF biasa menghasilkan satu row dengan `amount=1`. Token bucket membatasi approval, sehingga pengiriman biasa tidak praktis. Header `x-llm-id` bukan bagian dari alur aplikasi dan diabaikan.

## Vulnerability

`Exif.ReadLocation()` mengembalikan `JsonElement` untuk `UserComment`:

```json
{"location":{"x":0,"y":0}}
```

`PointType.Write()` meneruskan nilai ke `TupleType.Write()`. Implementasi driver hanya menulis nilai jika object adalah `ITuple` atau `IList`; `JsonElement` melewati kedua cabang tersebut dan menghasilkan 0 byte.

Row yang seharusnya ditulis:

```text
Point | UInt32 amount=1 | String classification | Bool approved
```

menjadi byte stream tanpa 16 byte `Point`. Parser ClickHouse kemudian membaca byte classification sebagai `amount`.

## Eksploitasi

Payload bitmap dibuat agar classifier mengembalikan tepat 48 byte:

```text
The image shows a beer, but the type is unclear.
```

Offset penting:

- byte 11 sampai 14: `hows`, dibaca sebagai little-endian `UInt32` `1937207144`
- byte 15: spasi (`32`), dibaca sebagai panjang string berikutnya
- 32 byte berikutnya membentuk classification
- byte `approved` asli tetap terbaca sebagai `true`

Dengan satu row, `counted` melewati `1_000_000`.

## Solve Script

`solve.py` membuat EXIF `UserComment`, mengirim payload ke `/api/beers`, lalu mengambil flag dari `/api/stats`.

## Cara Menjalankan

```bash
python3 -m pip install requests pillow piexif
python3 solve.py
```

Target dapat diganti:

```bash
python3 solve.py --target https://challenge.example
```

## Flag

`NNS{5ka1_31N_M11lJoN_BJoRa_og_317t_7oMt_7UPle}`

## Catatan Stabilitas

Payload bergantung pada output classifier yang tepat 48 byte. Flag tervalidasi dari response `/api/stats`, dengan `counted=1937207188` dan `flag` non-null.
